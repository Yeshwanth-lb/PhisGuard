"""DMARC-aligned critical-sender recognizer (Phase 1A of the bombing triage rework).

The From header is forgeable, so a .bank/.gov claim means nothing on its own.
A sender is "critical" — Tier 1, instant unbuffered delivery even mid-bomb — ONLY
when BOTH hold:

  1. the From domain is a PROTECTED critical type
     (TLD in BOMBING_PROTECTED_TLDS, or the org-domain is in the trusted_domains
     table), AND
  2. the message is DMARC-ALIGNED — a real From-vs-authenticated-domain check:
     DKIM-aligned pass = the DKIM-Signature is cryptographically verified AND the
     signing `d=` domain organizationally aligns with the From domain.

A message that CLAIMS a protected TLD but FAILS alignment returns the distinct
`spoofed_critical` signal — a PHISHING indicator, never trusted (the caller routes
it to the phishing path).

WHY WE COMPUTE ALIGNMENT OURSELVES (not parsed['dmarc_result']):
  app/parser/email_parser.py only REGEX-SCRAPES the Authentication-Results header.
  On our SMTP gateway we ARE the receiving MTA, so that header is usually absent
  (→ "unknown") and, when present, is attacker-forgeable. dkimpy verifies the
  DKIM-Signature that travels WITH the message, so it works even when no upstream
  MTA stamped Authentication-Results, and a forged header cannot fake a valid
  cryptographic signature.

SPF ALIGNMENT — DELIBERATELY NOT TRUST-GRANTING (yet):
  A raw spf=pass does NOT catch a forged From, and on our gateway the scraped
  Received-SPF/Authentication-Results is itself forgeable. A correct SPF check
  needs the live connecting peer IP, which is not plumbed to this layer in 1A.
  So SPF is reported for transparency but never grants Tier 1 on its own. Live
  peer-IP SPF is a documented follow-up (Phase 3). This is fail-closed: a bank
  that only passes SPF (no DKIM) lands in Tier 3 — delivered + soft-labeled,
  still visible — never falsely fast-tracked.

CHECKDMARC (optional corroborator):
  If the `checkdmarc` library is installed, we annotate whether the From org-domain
  PUBLISHES an enforcing DMARC policy. This is informational only — it never grants
  or revokes trust on its own (the trust decision is the cryptographic DKIM check).
  Absent library / DNS error is ignored (graceful).

FAIL-CLOSED EVERYWHERE: any missing data, parse error, or unavailable dependency
means NOT aligned → the sender is treated as non-critical and the message routes to
Tier 3 (delivered + soft-labeled), never fast-tracked.
"""
import os
import re
from collections import namedtuple
from email import message_from_bytes
from email.policy import compat32

import structlog

logger = structlog.get_logger()


# ── Tunable sets — os.environ in-module style, matching bombing_detector.py ─────
def _set(key: str, default: str) -> set[str]:
    return {x.strip().lower() for x in os.environ.get(key, default).split(",") if x.strip()}


PROTECTED_TLDS = _set("BOMBING_PROTECTED_TLDS", ".bank,.bank.in,.gov,.gov.in,.nic.in,.insurance")

# Known multi-part public suffixes we must treat as a unit when deriving the
# organizational (registrable) domain. This is NOT the full Public Suffix List —
# it covers the protected set plus common cases. DOCUMENTED LIMITATION: a domain
# under a multi-part suffix not listed here falls back to the last-two-labels rule,
# which can mis-derive the org domain and therefore mis-judge alignment. Extend
# this tuple (or swap in a real PSL/tldextract) if new suffixes matter.
_MULTI_SUFFIXES = (
    "bank.in", "gov.in", "nic.in", "co.in", "org.in", "net.in", "ac.in",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "co.jp", "co.kr",
)


# is_critical → True only for an authenticated protected sender.
# signal      → 'critical' | 'spoofed_critical' | None
#               'spoofed_critical' = claimed a protected TLD but failed alignment
#                (phishing indicator); None = not a protected sender at all.
CriticalResult = namedtuple(
    "CriticalResult", "is_critical signal from_domain aligned detail"
)


def organizational_domain(domain: str) -> str:
    """Best-effort registrable domain (eTLD+1). See _MULTI_SUFFIXES caveat."""
    d = (domain or "").strip().lower().rstrip(".")
    if not d or "." not in d:
        return d
    for suf in _MULTI_SUFFIXES:
        if d == suf or d.endswith("." + suf):
            extra = d[: -(len(suf) + 1)]
            if not extra:
                return d
            first = extra.rsplit(".", 1)[-1]
            return f"{first}.{suf}"
    return ".".join(d.split(".")[-2:])


def _load_trusted() -> set[str]:
    try:
        from app import storage
        return {(r.get("domain") or "").lower() for r in storage.list_trusted_domains()}
    except Exception as exc:
        logger.warning("critical_sender_trusted_load_err", error=str(exc))
        return set()


def _is_protected_domain(domain: str, trusted: set[str]) -> bool:
    if not domain:
        return False
    for tld in PROTECTED_TLDS:
        suf = tld if tld.startswith(".") else "." + tld
        if domain == suf.lstrip(".") or domain.endswith(suf):
            return True
    return domain in trusted or organizational_domain(domain) in trusted


def _dkim_signing_domains(raw_bytes: bytes) -> list[str]:
    """Extract every `d=` signing domain from the message's DKIM-Signature header(s)."""
    out: list[str] = []
    try:
        msg = message_from_bytes(raw_bytes, policy=compat32)
        for sig in msg.get_all("DKIM-Signature", []):
            m = re.search(r"\bd=([^;\s]+)", str(sig), re.IGNORECASE)
            if m:
                out.append(m.group(1).strip().lower().rstrip("."))
    except Exception as exc:
        logger.info("critical_sender_dkim_header_parse_err", error=str(exc))
    return out


def _dkim_aligned(raw_bytes: bytes | None, from_org: str) -> bool:
    """True only if the DKIM signature verifies cryptographically AND its signing
    domain organizationally aligns with the From domain. Fail-closed."""
    if not raw_bytes or not from_org:
        return False
    try:
        import dkim  # dkimpy — verifies the signature, fetching the public key via DNS
    except Exception:
        logger.warning("critical_sender_dkim_unavailable")
        return False
    try:
        verified = bool(dkim.verify(raw_bytes))
    except Exception as exc:
        logger.info("critical_sender_dkim_verify_err", error=str(exc))
        return False
    if not verified:
        return False
    for d in _dkim_signing_domains(raw_bytes):
        if organizational_domain(d) == from_org:
            return True
    return False


def _spf_info(parsed: dict, from_org: str) -> dict:
    """Report SPF result + envelope alignment for transparency. NOT trust-granting
    (see module docstring)."""
    spf = (parsed.get("spf_result") or "unknown").lower()
    rp = parsed.get("return_path") or ""
    m = re.search(r"@([\w.-]+)", rp)
    env_org = organizational_domain(m.group(1)) if m else ""
    return {
        "spf_result": spf,
        "envelope_aligned": bool(env_org) and env_org == from_org,
    }


def _published_dmarc(from_org: str) -> str | None:
    """Optional corroboration via checkdmarc — does the org-domain publish an
    enforcing DMARC policy? Informational only; never flips the trust decision."""
    if not from_org:
        return None
    try:
        import checkdmarc  # optional — not a hard dependency
    except Exception:
        return None
    try:
        rec = checkdmarc.get_dmarc_record(from_org)
        return (rec.get("parsed", {}).get("tags", {}).get("p", {}).get("value")
                if isinstance(rec, dict) else None)
    except Exception:
        return None


def is_critical_sender(parsed: dict | None,
                       raw_bytes: bytes | None = None,
                       trusted_domains: set[str] | None = None) -> CriticalResult:
    """Decide whether an email is from an authenticated critical sender.

    Returns a CriticalResult. Use ``.is_critical`` for the Tier-1 gate and
    ``.signal == 'spoofed_critical'`` to route a protected-TLD spoof to phishing.
    """
    parsed = parsed or {}
    from_domain = (parsed.get("sender_domain") or "").strip().lower()
    if not from_domain:
        m = re.search(r"@([\w.-]+)", parsed.get("from_header") or "")
        from_domain = m.group(1).lower() if m else ""

    from_org = organizational_domain(from_domain)
    trusted = trusted_domains if trusted_domains is not None else _load_trusted()

    if not _is_protected_domain(from_domain, trusted):
        return CriticalResult(False, None, from_domain, False, "not_protected")

    aligned = _dkim_aligned(raw_bytes, from_org)
    spf = _spf_info(parsed, from_org)
    detail = {"dkim_aligned": aligned, **spf, "published_dmarc": _published_dmarc(from_org)}

    if aligned:
        return CriticalResult(True, "critical", from_domain, True, detail)

    # Claimed a protected TLD / trusted domain but no cryptographically aligned
    # authentication → treat as a spoof. PHISHING indicator, never trusted.
    logger.warning("critical_sender_spoofed", from_domain=from_domain, detail=detail)
    return CriticalResult(False, "spoofed_critical", from_domain, False, detail)
