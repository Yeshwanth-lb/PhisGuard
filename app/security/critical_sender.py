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

SPF ALIGNMENT — real DMARC SPF-alignment (not a bare spf=pass):
  We perform a live SPF check against the connecting peer IP (passed in from the SMTP
  session) for the envelope MAIL FROM, AND require that envelope domain to align
  organizationally with the From domain. A bare spf=pass on a non-aligned domain does
  NOT count (that's how forged-From mail can pass SPF). The peer IP is only available
  on the SMTP path; Gmail-ingested mail has none, so SPF contributes nothing there and
  DKIM alignment carries the decision. Trust = DKIM-aligned OR SPF-aligned. Fail-closed.

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


def _sig_covers_from(dkim_obj) -> bool:
    """True if the DKIM signature's h= tag actually includes the From header — an
    alignment claim is meaningless if the signature doesn't even sign From."""
    try:
        h = dkim_obj.signature_fields.get(b"h", b"")
        h = h.decode() if isinstance(h, (bytes, bytearray)) else str(h)
        return "from" in [x.strip().lower() for x in h.split(":")]
    except Exception:
        return False


def _dkim_aligned(raw_bytes: bytes | None, from_org: str) -> bool:
    """True only if a DKIM signature CRYPTOGRAPHICALLY VERIFIES *and* that same verified
    signature's d= organizationally aligns with the From domain *and* it signs From.

    Critically, we verify EACH signature individually and only trust the d= of one that
    actually passed. dkim.verify() validates only the topmost signature, so trusting a
    d= scraped from any header let an attacker attach a valid throwaway signature plus a
    bogus d=<victim> header and forge alignment. Fail-closed."""
    if not raw_bytes or not from_org:
        return False
    try:
        import dkim  # dkimpy
    except Exception:
        logger.warning("critical_sender_dkim_unavailable")
        return False
    try:
        n_sigs = len(message_from_bytes(raw_bytes, policy=compat32).get_all("DKIM-Signature", []))
    except Exception:
        n_sigs = 0
    for i in range(n_sigs):
        try:
            d = dkim.DKIM(raw_bytes)
            if not d.verify(idx=i):          # cryptographically verify THIS signature
                continue
            signing = d.domain.decode() if isinstance(d.domain, (bytes, bytearray)) else str(d.domain or "")
            if signing and organizational_domain(signing) == from_org and _sig_covers_from(d):
                return True
        except Exception as exc:
            logger.info("critical_sender_dkim_verify_err", idx=i, error=str(exc))
            continue
    return False


def _envelope_domain(envelope_from: str) -> str:
    addr = (envelope_from or "").strip().strip("<>").lower()
    m = re.search(r"@([\w.-]+)", addr)
    if m:
        return m.group(1)
    return addr if "." in addr else ""


def _spf_aligned(peer_ip: str | None, envelope_from: str | None, from_org: str) -> bool:
    """True only if SPF PASSES for the connecting IP AND the SPF-authenticated domain
    (the envelope MAIL FROM) organizationally aligns with the From domain — i.e. real
    DMARC SPF-alignment, not a bare spf=pass.

    Requires the live connecting peer IP, so it only contributes on the SMTP path
    (Gmail-ingested mail has no peer IP → returns False, DKIM still applies). Fail-closed
    on any missing data, missing pyspf, or DNS error."""
    if not peer_ip or not envelope_from or not from_org:
        return False
    env_domain = _envelope_domain(envelope_from)
    if not env_domain or organizational_domain(env_domain) != from_org:
        return False   # SPF would authenticate a non-aligned domain → not DMARC-aligned
    try:
        import spf  # pyspf — performs the SPF DNS lookup
    except Exception:
        logger.warning("critical_sender_spf_unavailable")
        return False
    try:
        result, _ = spf.check2(i=peer_ip, s=envelope_from.strip().strip("<>"), h=env_domain)
    except Exception as exc:
        logger.info("critical_sender_spf_err", error=str(exc))
        return False
    return result == "pass"


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


def is_dmarc_aligned(parsed: dict | None, raw_bytes: bytes | None = None,
                     peer_ip: str | None = None, envelope_from: str | None = None) -> bool:
    """General DMARC alignment for ANY From domain (not just protected TLDs): True if the
    message is DKIM-aligned OR SPF-aligned to its From domain. Used by the pipeline to
    fast-pass *authenticated* senders.

    IMPORTANT: alignment only proves the From domain isn't spoofed — it does NOT imply the
    domain is reputable (a phisher can DKIM-sign their own throwaway domain). Callers must
    pair this with a reputation check (domain age / OSINT / allowlist)."""
    parsed = parsed or {}
    from_domain = (parsed.get("sender_domain") or "").strip().lower()
    if not from_domain:
        m = re.search(r"@([\w.-]+)", parsed.get("from_header") or "")
        from_domain = m.group(1).lower() if m else ""
    from_org = organizational_domain(from_domain)
    if not from_org:
        return False
    return _dkim_aligned(raw_bytes, from_org) or _spf_aligned(peer_ip, envelope_from, from_org)


def is_critical_sender(parsed: dict | None,
                       raw_bytes: bytes | None = None,
                       trusted_domains: set[str] | None = None,
                       peer_ip: str | None = None,
                       envelope_from: str | None = None) -> CriticalResult:
    """Decide whether an email is from an authenticated critical sender.

    Trust = real DMARC alignment: DKIM-aligned (signature verified + signing domain
    aligns) OR SPF-aligned (SPF passes for the peer IP + envelope domain aligns).
    peer_ip/envelope_from enable the SPF path (SMTP only); without them DKIM still
    applies. Returns a CriticalResult — use ``.is_critical`` for the Tier-1 gate and
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

    dkim_ok = _dkim_aligned(raw_bytes, from_org)
    spf_ok  = _spf_aligned(peer_ip, envelope_from, from_org)
    aligned = dkim_ok or spf_ok
    detail = {"dkim_aligned": dkim_ok, "spf_aligned": spf_ok,
              "published_dmarc": _published_dmarc(from_org)}

    if aligned:
        return CriticalResult(True, "critical", from_domain, True, detail)

    # Claimed a protected TLD / trusted domain but neither DKIM nor SPF aligns →
    # treat as a spoof. PHISHING indicator, never trusted.
    logger.warning("critical_sender_spoofed", from_domain=from_domain, detail=detail)
    return CriticalResult(False, "spoofed_critical", from_domain, False, detail)
