"""Three-tier bombing triage classifier (Phase 1B).

Evaluated for each email that arrives while a recipient is in ACTIVE bombing mode.
The whole point of a mail bomb is to bury one real alert (an OTP / bank notice), so
the response is asymmetric: accelerate authenticated high-signal mail, quietly buffer
the structural noise, and let everything else through soft-labeled. NOTHING is dropped
or held for a human.

  TIER 1 — IMPORTANT  → deliver instantly, never buffered
      ONLY an authenticated critical sender (critical_sender.is_critical_sender),
      i.e. a protected/trusted domain that is cryptographically DMARC-aligned.
      Subject words alone do NOT qualify (closes the throwaway-domain fake-OTP
      bypass). A protected-TLD claim that FAILS alignment → 'spoofed_critical',
      routed to the phishing path, never trusted.

  TIER 2 — NOISE      → buffer, deliver labeled after the window
      Language-independent STRUCTURAL signals (subject + headers only, never body):
        1. List-Unsubscribe present
        2. Precedence: bulk OR List-Id present
        3. first-contact-ever sender domain (from the detector's history)
        4. ESP relay fingerprint in Received (mailchimp/sendgrid/mailgun/…)
        5. very-new sender domain (WHOIS age — only if enabled & available)

  TIER 3 — UNCERTAIN  → buffer, deliver labeled (the safety valve, DEFAULT)
      Matches neither: non-English, business mail, empty subject, AND a subject-only
      OTP/bank match from an UNAUTHENTICATED sender. Still delivered + soft-labeled —
      we never bury a possible alert — but not fast-tracked or trusted.

PRIVACY: classification reads subject + structural headers only. The message body is
never inspected or logged (consistent with the standing no-bodies rule).
"""
import os
import re
from collections import namedtuple
from email import message_from_bytes
from email.policy import compat32

import structlog

from app.security import critical_sender
from app.security.bombing_detector import is_high_signal

logger = structlog.get_logger()


# action: 'deliver_now' (Tier 1) | 'phishing' (spoofed_critical) | 'buffer' (Tier 2/3)
# tier  : 'important' | 'noise' | 'uncertain' | None  (matches bombing_buffer CHECK)
# label : subject-prefix applied on delivery/release
TriageResult = namedtuple("TriageResult", "action tier label signal reason")

_LABEL_NOISE     = "[Possible Bombing Noise]"
_LABEL_UNCERTAIN = "[Received During Mail Bomb]"
_LABEL_PRIORITY  = "[PhishGuard-Priority]"


def _csv_set(key: str, default: str) -> set[str]:
    return {x.strip().lower() for x in os.environ.get(key, default).split(",") if x.strip()}


# ESP relay fingerprints — substrings searched in Received headers (host/helo/by).
ESP_FINGERPRINTS = _csv_set(
    "BOMBING_ESP_FINGERPRINTS",
    "mailchimp,mandrillapp,sendgrid,mailgun,amazonses,sparkpost,sendinblue,"
    "constantcontact,mailjet,postmarkapp",
)

# WHOIS new-domain check is off by default — it does a network lookup we don't want
# in the SMTP hot path. The other four Tier-2 signals are sufficient; this is additive.
WHOIS_ENABLED   = os.environ.get("BOMBING_TIER2_WHOIS", "false").lower() in ("1", "true", "yes")
NEW_DOMAIN_DAYS = int(os.environ.get("BOMBING_NEW_DOMAIN_DAYS", "30"))


# ── Individual, testable Tier-2 structural signals ─────────────────────────────

def _has_list_unsubscribe(msg) -> bool:
    return msg.get("List-Unsubscribe") is not None


def _is_bulk(msg) -> bool:
    prec = (msg.get("Precedence", "") or "").strip().lower()
    return prec == "bulk" or msg.get("List-Id") is not None


def _esp_fingerprint(msg) -> bool:
    received = " ".join(str(h) for h in msg.get_all("Received", [])).lower()
    return any(esp in received for esp in ESP_FINGERPRINTS)


def _is_new_domain(domain: str) -> bool:
    """Very-new registration. Gated behind WHOIS_ENABLED; fail-soft to False so a
    lookup error never misclassifies (defaults toward delivery, never toward noise)."""
    if not WHOIS_ENABLED or not domain:
        return False
    try:
        from app.layer1.verdicts import domain_age_days  # reuse L1 WHOIS if present
        age = domain_age_days(domain)
        return age is not None and age < NEW_DOMAIN_DAYS
    except Exception as exc:
        logger.info("bombing_triage_whois_skip", domain=domain, error=str(exc))
        return False


def _tier2_signals(msg, sender_domain: str, first_contact: bool) -> list[str]:
    hits = []
    if _has_list_unsubscribe(msg):       hits.append("list_unsubscribe")
    if _is_bulk(msg):                    hits.append("bulk_or_list_id")
    if first_contact:                    hits.append("first_contact")
    if _esp_fingerprint(msg):            hits.append("esp_fingerprint")
    if _is_new_domain(sender_domain):    hits.append("new_domain")
    return hits


def classify(parsed: dict, raw_bytes: bytes, first_contact: bool,
             trusted_domains: set[str] | None = None,
             peer_ip: str | None = None, envelope_from: str | None = None) -> TriageResult:
    """Triage one email arriving during active bombing mode. See module docstring.

    peer_ip/envelope_from feed real SPF alignment in the Tier-1 authentication check
    (SMTP path); without them, DKIM alignment alone decides."""
    parsed = parsed or {}
    subject = str(parsed.get("subject", "") or "")
    sender_domain = (parsed.get("sender_domain") or "").lower()

    # ── Tier 1 / spoofed_critical — authentication decides, not the subject ─────
    crit = critical_sender.is_critical_sender(parsed, raw_bytes, trusted_domains,
                                              peer_ip=peer_ip, envelope_from=envelope_from)
    if crit.signal == "spoofed_critical":
        # Claimed a protected/trusted identity but failed cryptographic alignment.
        return TriageResult("phishing", None, "", "spoofed_critical",
                            f"spoofed protected sender {crit.from_domain}")
    if crit.is_critical:
        return TriageResult("deliver_now", "important", _LABEL_PRIORITY, "critical",
                            f"authenticated critical sender {crit.from_domain}")

    # ── Tier 2 — structural bombing noise (headers only, language-independent) ──
    try:
        msg = message_from_bytes(raw_bytes or b"", policy=compat32)
    except Exception:
        msg = message_from_bytes(b"", policy=compat32)
    signals = _tier2_signals(msg, sender_domain, first_contact)
    if signals:
        return TriageResult("buffer", "noise", _LABEL_NOISE, None,
                            "noise:" + ",".join(signals))

    # ── Tier 3 — uncertain safety valve (DEFAULT: favor delivery) ──────────────
    # A subject-only OTP/bank match from an unauthenticated sender lands HERE — it is
    # delivered and soft-labeled (we never bury a possible alert) but NOT fast-tracked.
    reason = "uncertain:subject_high_signal_unauthenticated" if is_high_signal(subject) \
        else "uncertain:no_signal"
    return TriageResult("buffer", "uncertain", _LABEL_UNCERTAIN, None, reason)
