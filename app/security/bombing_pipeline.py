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
import uuid
from collections import namedtuple

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
             raw_bytes: bytes) -> BombingDecision:
    """Record the arrival, run cascading-window detection, and — if the recipient is
    under attack — triage this email into a tier. Call this for EVERY ingested email
    (detection needs to see all arrivals, not just ones during an active bomb)."""
    parsed = parsed or {}
    subject = str(parsed.get("subject", "") or "")

    # first-contact must be read BEFORE record() adds this domain to history.
    first_contact = bd.is_first_contact(recipient, mail_from)
    under_attack, newly = bd.record(recipient, mail_from, subject)

    if not under_attack:
        return BombingDecision(False, newly, None, None, None, None, "not_under_attack")

    tri = triage.classify(parsed, raw_bytes, first_contact)
    return BombingDecision(True, newly, tri.action, tri.tier, tri.label,
                           tri.signal, tri.reason)


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

def _gmail_recipient(parsed: dict, settings) -> str:
    """Resolve the mailbox the message landed in. Prefer the impersonated user
    (the inbox we ingest on behalf of); fall back to the To header."""
    rcpt = getattr(settings, "google_admin_impersonate_email", "") or ""
    if rcpt:
        return rcpt
    to = ""
    try:
        to = (parsed.get("headers", {}) or {}).get("To", "") or parsed.get("to", "")
    except Exception:
        to = ""
    return (to or "gmail-inbox").strip().lower()


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
    recipient = _gmail_recipient(parsed, settings)
    mail_from = parsed.get("sender_email") or parsed.get("from_header", "") or ""

    decision = evaluate(recipient, mail_from, parsed, raw_bytes)
    if decision.newly_detected:
        logger.warning("gmail_bombing_started", rcpt=recipient, sender=mail_from)
    if decision.under_attack:
        logger.info("gmail_bombing_triage", rcpt=recipient, action=decision.action,
                    tier=decision.tier, reason=decision.reason)
        if decision.action == "buffer":
            buffer(decision, recipient, scan_id, raw_bytes,
                   str(parsed.get("sender_domain", "") or ""),
                   str(parsed.get("subject", "") or ""))
    return decision._asdict()
