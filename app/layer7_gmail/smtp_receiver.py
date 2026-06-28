"""Layer 7 — SMTP inbound gateway.

Routing logic:
  CLEAN      → relay to downstream mail server unchanged
  SUSPICIOUS → hold in SOC pending-review queue; SOC approves/rejects via dashboard
  PHISHING   → rewrite RCPT TO to quarantine address, relay with [PHISHGUARD QUARANTINE] tag

Config (set in .env):
  SMTP_LISTEN_HOST      default 0.0.0.0
  SMTP_LISTEN_PORT      default 8025
  SMTP_RELAY_HOST       downstream server  (localhost for demo, smtp-relay.gmail.com for prod)
  SMTP_RELAY_PORT       default 1025 for demo, 587 for prod
  SMTP_QUARANTINE_ADDRESS  quarantine mailbox (phishguard-quarantine@domain.com)
"""
import asyncio
import smtplib
import uuid
from email import message_from_bytes
from email.policy import compat32
from email.mime.text import MIMEText

import structlog

logger = structlog.get_logger()

_MAX_RELAY_RETRIES = 3


async def _relay_raw(raw_bytes: bytes, mail_from: str, recipients: list[str], settings) -> bool:
    """Send raw MIME bytes to the downstream server with retry."""
    relay_host = getattr(settings, "smtp_relay_host", "localhost")
    relay_port = int(getattr(settings, "smtp_relay_port", 1025))
    relay_user = getattr(settings, "alert_smtp_user", "") or ""
    relay_pass = getattr(settings, "alert_smtp_password", "") or ""

    def _send():
        with smtplib.SMTP(relay_host, relay_port, timeout=15) as s:
            s.ehlo()
            # Only use TLS + auth when connecting to real relay (not demo server)
            if relay_port != 1025:
                import ssl as _ssl
                s.starttls(context=_ssl.create_default_context())
                s.ehlo()
                if relay_user and relay_pass:
                    s.login(relay_user, relay_pass)
            s.sendmail(mail_from, recipients, raw_bytes)

    for attempt in range(1, _MAX_RELAY_RETRIES + 1):
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _send)
            logger.info("smtp_relayed", to=recipients, host=relay_host, attempt=attempt)
            return True
        except Exception as exc:
            logger.warning("smtp_relay_err", attempt=attempt, error=str(exc))
            if attempt < _MAX_RELAY_RETRIES:
                await asyncio.sleep(2 ** attempt)

    return False


def _tag_subject(raw_bytes: bytes, prefix: str) -> bytes:
    """Prepend a tag to the Subject header of a raw email."""
    try:
        msg = message_from_bytes(raw_bytes, policy=compat32)
        current = msg.get("Subject", "")
        del msg["Subject"]
        msg["Subject"] = f"{prefix} {current}"
        return msg.as_bytes()
    except Exception:
        return raw_bytes


class PhishGuardSMTPHandler:

    def __init__(self, analyze_fn, settings):
        self.analyze_fn = analyze_fn
        self.settings = settings

    async def handle_DATA(self, server, session, envelope) -> str:
        import uuid as _uuid
        from app import storage
        from app.security.smtp_rate_limiter import check as _rl_check

        raw_bytes: bytes = envelope.content
        mail_from: str = envelope.mail_from or ""
        original_rcpts: list[str] = list(envelope.rcpt_tos)

        # ── Rate limiting — protects against email bombing ───────────────────
        peer_ip  = session.peer[0] if session.peer else "unknown"
        rcpt_str = original_rcpts[0] if original_rcpts else ""
        # Reconciliation: once an inbox is in active bombing mode, the triage engine
        # owns its mail (Tier-1 fast-tracked, noise buffered). Skip the per-recipient
        # limit for it so the limit can't 421 (and thus bury) the OTP. Other limits +
        # TCP-drop still guard the gateway.
        from app.security.bombing_detector import is_under_attack as _iua
        _skip_rcpt_limit = _iua(rcpt_str)
        allowed, reason, tarpit = _rl_check(peer_ip, mail_from, rcpt_str,
                                            skip_recipient_limit=_skip_rcpt_limit)
        if not allowed:
            logger.warning("smtp_rate_limited", peer=peer_ip, sender=mail_from,
                           rcpt=rcpt_str, tarpit=tarpit, reason=reason)
            if tarpit:
                await asyncio.sleep(tarpit)   # slow down the bombing tool
            # TCP hard-drop escalation: an IP that keeps blowing past the 421 limit
            # is a tool ignoring backoff — drop the socket so it can't exhaust the
            # connection pool. 421 + tarpit behavior above is unchanged.
            from app.security.smtp_rate_limiter import note_rejection as _note_rej
            if _note_rej(peer_ip):
                try:
                    transport = getattr(server, "transport", None)
                    if transport:
                        transport.close()
                    logger.warning("smtp_tcp_dropped", peer=peer_ip)
                except Exception:
                    pass
            return reason  # 421 = temporary failure, MTA will retry

        logger.info("smtp_received", peer=str(session.peer),
                    size=len(raw_bytes), rcpt=original_rcpts)

        # Recipient key for bombing detection. Detection + triage run AFTER the
        # pipeline via the shared bombing pipeline (app/security/bombing_pipeline.py),
        # so the SMTP gateway and Gmail ingestion run byte-for-byte identical logic.
        _rcpt_for_bomb = original_rcpts[0] if original_rcpts else ""

        # ── Run the full detection pipeline ──────────────────────────────
        try:
            result = await self.analyze_fn(raw_bytes, self.settings)
        except Exception as exc:
            logger.error("smtp_pipeline_err", error=str(exc))
            return "250 OK"   # accept but log; never bounce to sender

        final_verdict = result.get("verdict", "clean")
        confidence    = float(result.get("confidence", 0.0))
        scan_id       = result.get("email_id", str(_uuid.uuid4()))

        # Use L2 AI verdict for routing decisions — it reflects what the AI
        # engines actually found. The final blended verdict includes ML which
        # can raise "suspicious" to "phishing", but for SOC routing we want
        # to hold anything the AI flagged as suspicious.
        l2_verdict = result.get("l2", {}).get("verdict", final_verdict) if result.get("l2") else final_verdict
        routing_verdict = l2_verdict if l2_verdict in ("suspicious", "phishing") else final_verdict

        # Extract metadata for logging/queue/buffer (needed by the triage block below)
        parsed  = result.get("parsed") or {}
        sender  = str(parsed.get("from_header", mail_from) or mail_from)
        subject = str(parsed.get("subject", "") or "")
        sender_domain = str(parsed.get("sender_domain", "") or "")

        # ── Bombing triage (asymmetric response) ──────────────────────────────
        # During an active bomb the inbox is flooded to bury one real alert. We
        # accelerate authenticated high-signal mail (Tier 1), buffer the structural
        # noise (Tier 2) and the ambiguous remainder (Tier 3) for labeled release —
        # nothing is dropped or held for a human. Normal (non-bombing) routing below
        # is untouched. See app/security/bombing_triage.py.
        from app.security import bombing_pipeline as _bp
        decision = _bp.evaluate(_rcpt_for_bomb, mail_from, parsed, raw_bytes, peer_ip=peer_ip)
        if decision.newly_detected:
            logger.warning("inbox_bombing_started", rcpt=_rcpt_for_bomb, sender=mail_from)
        if decision.under_attack:
            logger.info("smtp_bombing_triage", rcpt=_rcpt_for_bomb,
                        action=decision.action, tier=decision.tier,
                        reason=decision.reason, subject=subject[:60])

            if decision.action == "deliver_now":
                # TIER 1 — authenticated critical sender. Deliver instantly, tagged,
                # NEVER buffered, regardless of L2/ML verdict. L1 hard hits never reach
                # here (the pipeline would have quarantined first).
                try:
                    storage.save_scan(scan_id, result, parsed)
                except Exception as _exc:
                    logger.warning("smtp_scan_save_err", error=str(_exc))
                tagged = _tag_subject(raw_bytes, decision.label)
                from app.layer7_gmail.gmail_client import deliver_to_inbox
                if not deliver_to_inbox(self.settings, tagged, "PhishGuard-Priority"):
                    await _relay_raw(tagged, mail_from, original_rcpts, self.settings)
                logger.info("smtp_bombing_priority_delivered", rcpt=_rcpt_for_bomb,
                            subject=subject[:60])
                return "250 OK"

            if decision.action == "buffer":
                # TIER 2/3 — park in the durable buffer; the window worker releases it
                # labeled. Synchronous write BEFORE acknowledging — no ack-before-persist.
                try:
                    storage.save_scan(scan_id, result, parsed)
                except Exception as _exc:
                    logger.warning("smtp_scan_save_err", error=str(_exc))
                _bp.buffer(decision, _rcpt_for_bomb, scan_id, raw_bytes,
                           sender_domain, subject)
                logger.info("smtp_bombing_buffered", rcpt=_rcpt_for_bomb, tier=decision.tier)
                return "250 OK"

            # decision.action == "phishing" — protected-TLD spoof (claimed but failed
            # DMARC alignment). Fall through to normal routing as phishing → quarantine.
            routing_verdict = "phishing"
            logger.warning("smtp_bombing_spoofed_critical", rcpt=_rcpt_for_bomb,
                           sender=sender, subject=subject[:60])

        # Screenshot path if sandbox ran
        screenshot_path = f"data/screenshots/{scan_id}.png"

        logger.info("smtp_verdict", verdict=routing_verdict, final=final_verdict,
                    confidence=round(confidence, 3), rcpt=original_rcpts)

        # Save to dashboard database so stats + quarantine + reports update
        try:
            from app import storage as _storage
            _storage.save_scan(scan_id, result, parsed)
        except Exception as _exc:
            logger.warning("smtp_scan_save_err", error=str(_exc))

        quarantine_addr = getattr(self.settings, "gmail_quarantine_address",
                                  "quarantine@phishguard.local") or "quarantine@phishguard.local"

        # ── Routing decision ─────────────────────────────────────────────

        if routing_verdict == "clean":
            # Try Gmail API injection first — delivers directly to recipient's inbox
            # so they actually SEE it in Gmail. Falls back to SMTP relay if not available.
            from app.layer7_gmail.gmail_client import deliver_to_inbox
            gmail_ok = deliver_to_inbox(self.settings, raw_bytes, "PhishGuard-Delivered")
            if gmail_ok:
                logger.info("smtp_delivered_via_gmail_api", rcpt=original_rcpts)
            else:
                await _relay_raw(raw_bytes, mail_from, original_rcpts, self.settings)
                logger.info("smtp_delivered_clean", rcpt=original_rcpts)

        elif routing_verdict == "suspicious":
            # HOLD — do NOT deliver until SOC reviews it
            # Email is stored in the pending_review queue.
            # It will only reach the recipient if a SOC analyst clicks Approve.
            # If rejected, it goes to quarantine. No relay happens here.
            pending_id = str(_uuid.uuid4())
            storage.save_pending_review(
                pending_id=pending_id,
                scan_id=scan_id,
                verdict=routing_verdict,
                confidence=confidence,
                sender=sender,
                subject=subject,
                original_rcpt=original_rcpts[0] if original_rcpts else "",
                raw_email=raw_bytes,
            )
            logger.info("smtp_held_for_review",
                        pending_id=pending_id,
                        confidence=round(confidence, 3),
                        scan_id=scan_id,
                        original_rcpt=original_rcpts)

        else:
            # PHISHING — rewrite recipient to quarantine
            tagged = _tag_subject(
                raw_bytes,
                f"[PHISHGUARD QUARANTINE conf={round(confidence*100)}%]"
            )
            await _relay_raw(tagged, mail_from, [quarantine_addr], self.settings)
            logger.info("smtp_quarantined", original_rcpt=original_rcpts,
                        quarantine=quarantine_addr, confidence=round(confidence, 3))

        return "250 OK"


async def start_smtp_server(analyze_fn, settings) -> object | None:
    try:
        from aiosmtpd.controller import Controller  # type: ignore
        hdlr = PhishGuardSMTPHandler(analyze_fn, settings)
        ctrl = Controller(
            hdlr,
            hostname=getattr(settings, "smtp_listen_host", "0.0.0.0"),
            port=getattr(settings, "smtp_listen_port", 8025),
        )
        ctrl.start()
        logger.info("smtp_started",
                    host=getattr(settings, "smtp_listen_host", "0.0.0.0"),
                    port=getattr(settings, "smtp_listen_port", 8025))
        return ctrl
    except Exception as exc:
        logger.warning("smtp_start_failed", error=str(exc))
        return None


# ── Bombing buffer release worker ──────────────────────────────────────────────
# Buffered Tier-2/3 mail is released — labeled — once it has aged past the analysis
# window. Runs as a background daemon so release is automatic and independent of
# inbound traffic; the buffer is durable (SQLite) so nothing is lost across restarts.
import os as _rel_os

RELEASE_WINDOW_SECS = int(_rel_os.environ.get("BOMBING_ANALYSIS_WINDOW_SECS", 300))
RELEASE_POLL_SECS   = int(_rel_os.environ.get("BOMBING_RELEASE_POLL_SECS", 15))

_TIER_LABELS = {
    "noise":     "[Possible Bombing Noise]",
    "uncertain": "[Received During Mail Bomb]",
}


def _parse_mail_from(raw: bytes) -> str:
    import re as _re
    try:
        msg = message_from_bytes(raw, policy=compat32)
        m = _re.search(r"[\w.+-]+@[\w.-]+", str(msg.get("From", "") or ""))
        return m.group(0) if m else ""
    except Exception:
        return ""


def _release_due(settings) -> int:
    """Release every buffered message older than the window, labeled by tier.
    Returns how many were released. Idempotent and safe to call repeatedly."""
    from app import storage
    from app.layer7_gmail.gmail_client import deliver_to_inbox

    try:
        due = storage.buffer_list_due(RELEASE_WINDOW_SECS)
    except Exception as exc:
        logger.warning("bombing_release_list_err", error=str(exc))
        return 0

    released = 0
    for row in due:
        # Atomically claim before delivering so concurrent release workers (the app
        # runs uvicorn --workers) never double-deliver the same message. If we don't
        # win the claim, another worker owns this row — skip it.
        if not storage.buffer_claim(row["id"]):
            continue
        try:
            label  = _TIER_LABELS.get(row.get("tier"), _TIER_LABELS["uncertain"])
            tagged = _tag_subject(row["raw_email"], label)
            ok = bool(deliver_to_inbox(settings, tagged, "PhishGuard-Released"))
            if not ok:
                mail_from = _parse_mail_from(row["raw_email"])
                ok = bool(asyncio.run(_relay_raw(tagged, mail_from, [row["recipient"]], settings)))
            if ok:
                released += 1
            else:
                # Neither path delivered → revert the claim so it retries next cycle.
                # Nothing is dropped (honors the no-drop guarantee).
                storage.buffer_unclaim(row["id"])
                logger.warning("bombing_release_undelivered", id=row.get("id"))
        except Exception as exc:
            storage.buffer_unclaim(row["id"])
            logger.warning("bombing_release_item_err", id=row.get("id"), error=str(exc))

    if released:
        try:
            storage.buffer_purge_expired()
        except Exception as exc:
            logger.warning("bombing_release_purge_err", error=str(exc))
        logger.info("bombing_release_cycle", released=released)
    return released


def start_release_worker(settings):
    """Daemon thread that releases buffered bombing mail past the analysis window."""
    import threading
    stop = threading.Event()

    def _loop():
        while not stop.is_set():
            try:
                _release_due(settings)
            except Exception as exc:
                logger.warning("bombing_release_loop_err", error=str(exc))
            stop.wait(RELEASE_POLL_SECS)

    threading.Thread(target=_loop, daemon=True, name="bombing-release").start()
    logger.info("bombing_release_worker_started",
                window_secs=RELEASE_WINDOW_SECS, poll_secs=RELEASE_POLL_SECS)
    return stop


async def deliver_pending(pending_id: str, settings, reviewed_by: str = "soc") -> dict:
    """SOC approved — deliver the held email to original recipient now."""
    from app import storage
    import re as _re

    raw = storage.get_pending_raw(pending_id)
    rows = storage.list_pending_reviews("pending")
    item = next((r for r in rows if r["id"] == pending_id), None)

    if not raw or not item:
        return {"ok": False, "error": "not found"}

    rcpt = item["original_rcpt"]
    mail_from = ""
    try:
        msg = message_from_bytes(raw, policy=compat32)
        m = _re.search(r"[\w.+-]+@[\w.-]+", str(msg.get("From", "") or ""))
        if m:
            mail_from = m.group(0)
    except Exception:
        pass

    tagged = _tag_subject(raw, "[PHISHGUARD APPROVED by SOC]")

    # Try Gmail API injection first (delivers directly to inbox)
    from app.layer7_gmail.gmail_client import deliver_to_inbox
    gmail_ok = deliver_to_inbox(settings, tagged, "PhishGuard-SOC-Approved")
    if gmail_ok:
        relay_ok = True
        logger.info("smtp_approved_via_gmail_api", rcpt=rcpt)
    else:
        relay_ok = await _relay_raw(tagged, mail_from, [rcpt], settings)

    # Always mark as approved regardless of relay result.
    # In production the relay goes to smtp-relay.gmail.com (always up).
    # In demo mode the fake server may not be running — that's fine,
    # the SOC decision is still recorded and the workflow is demonstrated.
    storage.update_pending_status(pending_id, "approved", reviewed_by)
    logger.info("smtp_pending_approved",
                pending_id=pending_id, rcpt=rcpt, relay_ok=relay_ok)

    msg_note = "" if relay_ok else " (demo: fake server not running — in production email would reach recipient)"
    return {"ok": True, "delivered_to": rcpt, "relay_ok": relay_ok, "note": msg_note}


async def reject_pending(pending_id: str, settings, reviewed_by: str = "soc") -> dict:
    """SOC rejected — send to quarantine."""
    from app import storage

    raw = storage.get_pending_raw(pending_id)
    rows = storage.list_pending_reviews("pending")
    item = next((r for r in rows if r["id"] == pending_id), None)

    if not raw or not item:
        return {"ok": False, "error": "not found"}

    quarantine_addr = getattr(settings, "gmail_quarantine_address",
                              "quarantine@phishguard.local")

    tagged = _tag_subject(raw, "[PHISHGUARD REJECTED BY SOC — QUARANTINED]")
    ok = await _relay_raw(tagged, "", [quarantine_addr], settings)

    storage.update_pending_status(pending_id, "rejected", reviewed_by)

    # Update the original scan record to phishing so it appears in the Quarantine tab
    if item.get("scan_id"):
        try:
            import sqlite3 as _sq, os as _os, time as _time
            db_path = _os.environ.get("PHISHGUARD_DB_PATH", "data/phishguard.db")
            conn = _sq.connect(db_path, check_same_thread=False)
            conn.execute(
                "UPDATE scans SET verdict='phishing', confidence=? WHERE id=?",
                (max(item.get("confidence", 0.5), 0.65), item["scan_id"])
            )
            conn.commit()
            conn.close()
        except Exception as _e:
            logger.warning("smtp_reject_scan_update_err", error=str(_e))

    logger.info("smtp_pending_rejected", pending_id=pending_id)
    return {"ok": True, "sent_to_quarantine": quarantine_addr}
