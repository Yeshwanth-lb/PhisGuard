"""Shared bombing detection + triage pipeline (Phase 2).

THE single source of truth that BOTH the SMTP gateway and the Gmail ingestion path
call. Neither source owns the bombing logic — they are thin adapters that hand a
parsed message to evaluate() and act on the returned decision. This guarantees both
entry points run identical detection (cascading windows), identical tiering, identical
labels, and the same Slack alert (fired inside the detector) + dashboard banner
(/api/bombing/active reads detector + buffer state).

Flow (identical for SMTP and Gmail):
    decision = evaluate(recipient, mail_from, parsed, raw_bytes)
    if decision.under_attack:
        deliver_now | route-as-phishing | buffer(decision, ...)
    else:
        normal routing (caller-specific)
"""
import os
import re
import uuid
from collections import namedtuple
from email import message_from_bytes
from email.policy import compat32

import structlog

from app.security import bombing_detector as bd
from app.security import bombing_triage as triage

logger = structlog.get_logger()


# under_attack    — recipient is in active bombing mode (caller adjusts routing)
# newly_detected  — detection fired on THIS email (caller logs; Slack alert already sent)
# action          — None (not under attack) | 'deliver_now' | 'phishing' | 'buffer'
# tier/label/sig  — from the triage classifier (only meaningful when under_attack)
BombingDecision = namedtuple(
    "BombingDecision",
    "under_attack newly_detected action tier label signal reason",
)


def evaluate(recipient: str, mail_from: str, parsed: dict,
             raw_bytes: bytes, peer_ip: str | None = None) -> BombingDecision:
    """Record the arrival, run cascading-window detection, and — if the recipient is
    under attack — triage this email into a tier. Call this for EVERY ingested email
    (detection needs to see all arrivals, not just ones during an active bomb).

    peer_ip is the connecting SMTP client IP — enables real SPF alignment in Tier-1
    classification. Omitted by the Gmail path (no live peer IP); DKIM still applies."""
    parsed = parsed or {}
    subject = str(parsed.get("subject", "") or "")

    # first-contact must be read BEFORE record() adds this domain to history.
    first_contact = bd.is_first_contact(recipient, mail_from)
    under_attack, newly = bd.record(recipient, mail_from, subject)

    if not under_attack:
        return BombingDecision(False, newly, None, None, None, None, "not_under_attack")

    tri = triage.classify(parsed, raw_bytes, first_contact,
                          peer_ip=peer_ip, envelope_from=mail_from)
    return BombingDecision(True, newly, tri.action, tri.tier, tri.label,
                           tri.signal, tri.reason)


# Per-recipient buffer ceiling. Once an inbox is under attack the SMTP per-recipient
# rate limit is bypassed, so the buffer needs its own bound. On overflow the caller
# delivers immediately-labeled instead of buffering — bounds storage, never drops.
MAX_BUFFER_PER_RCPT = int(os.environ.get("BOMBING_MAX_BUFFER_PER_RCPT", 500))


def buffer_is_full(recipient: str) -> bool:
    from app import storage
    return storage.buffer_count_for_recipient(recipient) >= MAX_BUFFER_PER_RCPT


def buffer(decision: BombingDecision, recipient: str, scan_id: str,
           raw_bytes: bytes, sender_domain: str = "", subject: str = "") -> bool:
    """Park a Tier-2/3 message in the durable buffer (released labeled by the worker).
    Synchronous write — no ack-before-persist."""
    from app import storage
    return storage.buffer_add(
        buffer_id=str(uuid.uuid4()), recipient=recipient, scan_id=scan_id,
        tier=decision.tier, raw_email=raw_bytes,
        sender_domain=sender_domain, subject=subject,
    )


# ── Gmail ingestion adapter ────────────────────────────────────────────────────

def _gmail_recipient(parsed: dict, raw_bytes: bytes, settings) -> str:
    """Resolve the ACTUAL mailbox this message was delivered to, so detection and
    buffering are keyed per real inbox — not collapsed onto one shared bucket (which
    would false-fire detection and release buffered mail to the wrong mailbox).

    Prefer the delivered-to headers (Delivered-To / X-Original-To / To); fall back to
    the impersonated account only if none are present."""
    try:
        msg = message_from_bytes(raw_bytes or b"", policy=compat32)
        for hdr in ("Delivered-To", "X-Original-To", "To"):
            m = re.search(r"[\w.+-]+@[\w.-]+", str(msg.get(hdr, "") or ""))
            if m:
                return m.group(0).strip().lower()
    except Exception as exc:
        logger.info("gmail_recipient_parse_err", error=str(exc))
    rcpt = getattr(settings, "google_admin_impersonate_email", "") or ""
    return (rcpt or "gmail-inbox").strip().lower()


def ingest_gmail_message(parsed: dict, raw_bytes: bytes, settings,
                         scan_id: str = "") -> dict | None:
    """Feed a Gmail-ingested message through the shared bombing pipeline.

    Returns the decision as a dict, or None when ingestion is disabled (the flag-off
    dormant path: no work done). Tier-2/3 mail is buffered exactly as on the SMTP
    side; the already-running release worker delivers it labeled.
    """
    if not getattr(settings, "inbox_ingestion_enabled", False):
        return None

    parsed = parsed or {}
    recipient = _gmail_recipient(parsed, raw_bytes, settings)
    mail_from = parsed.get("sender_email") or parsed.get("from_header", "") or ""

    decision = evaluate(recipient, mail_from, parsed, raw_bytes)
    if decision.newly_detected:
        logger.warning("gmail_bombing_started", rcpt=recipient, sender=mail_from)
    if decision.under_attack:
        logger.info("gmail_bombing_triage", rcpt=recipient, action=decision.action,
                    tier=decision.tier, reason=decision.reason)
        if decision.action == "buffer":
            if buffer_is_full(recipient):
                # Overflow valve: deliver immediately-labeled instead of buffering.
                try:
                    from app.layer7_gmail.gmail_client import deliver_to_inbox
                    from app.layer7_gmail.smtp_receiver import _TIER_LABELS, _tag_subject
                    deliver_to_inbox(settings, _tag_subject(
                        raw_bytes, _TIER_LABELS.get(decision.tier, _TIER_LABELS["uncertain"])),
                        "PhishGuard-Released")
                    logger.warning("gmail_bombing_buffer_overflow_delivered", rcpt=recipient)
                except Exception as exc:
                    logger.warning("gmail_overflow_deliver_err", error=str(exc))
            else:
                buffer(decision, recipient, scan_id, raw_bytes,
                       str(parsed.get("sender_domain", "") or ""),
                       str(parsed.get("subject", "") or ""))
    return decision._asdict()
