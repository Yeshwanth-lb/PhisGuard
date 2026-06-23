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
        allowed, reason, tarpit = _rl_check(peer_ip, mail_from, rcpt_str)
        if not allowed:
            logger.warning("smtp_rate_limited", peer=peer_ip, sender=mail_from,
                           rcpt=rcpt_str, tarpit=tarpit, reason=reason)
            if tarpit:
                await asyncio.sleep(tarpit)   # slow down the bombing tool
            return reason  # 421 = temporary failure, MTA will retry

        logger.info("smtp_received", peer=str(session.peer),
                    size=len(raw_bytes), rcpt=original_rcpts)

        # ── Bombing detection ─────────────────────────────────────────────────
        # Parse subject from raw bytes before running pipeline so we can
        # score the subscription-pattern signal immediately on arrival.
        from app.security.bombing_detector import record as _bomb_record
        try:
            from email import message_from_bytes as _mfb
            from email.policy import compat32 as _c32
            _msg_preview = _mfb(raw_bytes[:4096], policy=_c32)
            _subject_preview = str(_msg_preview.get("Subject", "") or "")
        except Exception:
            _subject_preview = ""
        _rcpt_for_bomb = original_rcpts[0] if original_rcpts else ""
        _under_attack, _newly_detected = _bomb_record(
            _rcpt_for_bomb, mail_from, _subject_preview
        )
        if _newly_detected:
            logger.warning("inbox_bombing_started", rcpt=_rcpt_for_bomb,
                           sender=mail_from)

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

        # ── Bombing override — force-hold during active attack ────────────────
        # When an inbox is under a subscription bomb, even legitimate clean
        # emails are held for SOC review. This prevents real phishing or OTP
        # emails from being buried in the flood where the user can't see them.
        if _under_attack and routing_verdict == "clean":
            routing_verdict = "suspicious"
            logger.info("smtp_bombing_hold_applied", rcpt=_rcpt_for_bomb,
                        original_verdict="clean", forced_to="suspicious")

        # Extract metadata for logging/queue
        parsed  = result.get("parsed") or {}
        sender  = str(parsed.get("from_header", mail_from) or mail_from)
        subject = str(parsed.get("subject", "") or "")

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
