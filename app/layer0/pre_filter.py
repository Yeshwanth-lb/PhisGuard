"""Layer 0 — Trivial-clean pre-filter.

Fast-path for short, URL-free emails where SPF and DKIM both explicitly pass.
Skips L1 OSINT API calls and L2 AI analysis entirely.

All of the following must be true to fast-exit as clean:
  • SPF  = "pass"
  • DKIM = "pass"
  • 0 extracted URLs
  • 0 attachment hashes
  • Body length ≤ 600 characters
  • No urgency / action keywords in subject or body

If any criterion is not met → returns None and the pipeline continues to L1.
"""
import re

_URGENCY_RE = re.compile(
    r'\b('
    r'urgent|verify\s+your|account\s+(?:suspended|limited|blocked|compromised)|'
    r'click\s+here|confirm\s+(?:your\s+)?password|wire\s+transfer|'
    r'unusual\s+sign.{0,3}in|reset\s+your\s+password|your\s+account\s+has\s+been|'
    r'immediately|act\s+now|expires?\s+in\s+\d|last\s+chance|final\s+notice|'
    r'action\s+required|failure\s+to\s+(?:act|respond)|account\s+will\s+be'
    r')\b',
    re.IGNORECASE,
)

MAX_BODY_LEN = 600


def run_layer0(
    parsed: dict,
    urls: list,
    spf_result: str,
    dkim_result: str,
) -> dict | None:
    """Return a clean verdict dict if trivially safe, else None (continue to L1)."""
    if spf_result != "pass" or dkim_result != "pass":
        return None

    if urls:
        return None

    if parsed.get("attachment_hashes"):
        return None

    body = (parsed.get("body_text") or "").strip()
    if len(body) > MAX_BODY_LEN:
        return None

    subject = parsed.get("subject", "") or ""
    if _URGENCY_RE.search(body) or _URGENCY_RE.search(subject):
        return None

    return {
        "verdict": "clean",
        "confidence": 0.02,
        "blocked_at": None,
        "fast_path": "layer0_trivial_clean",
        "l0": {
            "passed": True,
            "spf": spf_result,
            "dkim": dkim_result,
            "url_count": 0,
            "attachment_count": 0,
            "body_len": len(body),
            "reason": "SPF+DKIM pass, no URLs, no attachments, short body, no urgency keywords",
        },
    }
