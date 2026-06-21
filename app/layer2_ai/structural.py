"""Engine 4 — Structural Forensic Analyst.

Checks:
- Brand impersonation (homoglyphs + display-name mismatch)
- Typosquatting (Levenshtein distance ≤ 2 against high-value brands)
- Unicode homoglyph domains
- Domain age via WHOIS (< 7 days → critical, < 30 days → high)
- Reply-To domain mismatch
- DMARC / SPF / DKIM alignment against From domain
- Tracking pixels and JS redirects
- Attachment risk: double extensions, macro-capable file types
"""
import asyncio
import re
from datetime import datetime, timezone

import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HOMOGLYPHS: dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "і": "i", "ν": "v", "μ": "u", "ο": "o", "α": "a",
    "ĺ": "l", "ı": "i", "ḷ": "l", "0": "o", "1": "l",
}

HIGH_VALUE_BRANDS: set[str] = {
    "paypal", "amazon", "microsoft", "apple", "google", "netflix",
    "bank", "wellsfargo", "chase", "citibank", "fedex", "dhl",
    "irs", "usps", "linkedin", "facebook", "instagram", "twitter",
    "dropbox", "docusign", "zoom", "onedrive", "sharepoint",
    "office365", "outlook", "icloud",
}

MACRO_EXTENSIONS: set[str] = {
    ".doc", ".xls", ".ppt",         # old binary — can contain VBA
    ".docm", ".xlsm", ".pptm",      # macro-enabled Office XML
    ".xlsb",                         # binary workbook
    ".js", ".vbs", ".wsh",           # script files
    ".hta",                          # HTML application
    ".exe", ".bat", ".cmd", ".ps1",  # executables / scripts
    ".scr",                          # screensaver (PE)
}

DOUBLE_EXT_RE = re.compile(r"\.(pdf|doc|xls|png|jpg|txt)\.(exe|bat|cmd|vbs|js|ps1)$", re.IGNORECASE)

_WHOIS_CACHE: dict[str, int | None] = {}   # domain → age_days (None = unknown)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize(domain: str) -> str:
    return "".join(HOMOGLYPHS.get(c, c) for c in domain.lower())


def _has_homoglyph(domain: str) -> bool:
    return any(c in HOMOGLYPHS for c in domain.lower())


def _brand_impersonation(domain: str) -> tuple[float, str | None]:
    """Return (score, brand_name) if domain impersonates a brand."""
    norm = _normalize(domain)
    base = norm.split(".")[0] if "." in norm else norm
    if _has_homoglyph(domain):
        for brand in HIGH_VALUE_BRANDS:
            if brand in norm and norm.split(".")[0] != brand:
                return 0.90, brand
        return 0.85, None
    for brand in HIGH_VALUE_BRANDS:
        if brand in base and base != brand:
            return 0.90, brand
    return 0.0, None


def _levenshtein(a: str, b: str) -> int:
    """Pure-Python Levenshtein distance — no external dependency."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def _typosquatting_score(domain: str) -> tuple[float, str | None, int]:
    """Check Levenshtein distance from domain base to each high-value brand."""
    try:
        from Levenshtein import distance as _lev_dist
    except ImportError:
        _lev_dist = _levenshtein  # type: ignore

    base = _normalize(domain).split(".")[0] if "." in domain else _normalize(domain)
    best_dist = 999
    best_brand = None
    for brand in HIGH_VALUE_BRANDS:
        if abs(len(base) - len(brand)) > 3:
            continue
        d = _lev_dist(base, brand)
        if d < best_dist:
            best_dist = d
            best_brand = brand

    if best_dist == 0:
        return 0.0, None, 0   # exact match = not typosquatting
    if best_dist == 1:
        return 0.95, best_brand, best_dist
    if best_dist == 2:
        return 0.70, best_brand, best_dist
    return 0.0, None, best_dist


def _display_name_mismatch(from_hdr: str, sender_domain: str) -> float:
    m = re.match(r'^"?([^"<]+)"?\s*<', from_hdr or "")
    if not m:
        return 0.0
    name = m.group(1).lower().strip()
    for brand in HIGH_VALUE_BRANDS:
        if brand in name and brand not in (sender_domain or "").lower():
            return 0.85
    return 0.0


def _reply_to_mismatch(reply_to: str, sender_domain: str) -> tuple[float, str | None]:
    if not reply_to:
        return 0.0, None
    m = re.search(r"@([\w.-]+)", reply_to)
    if not m:
        return 0.0, None
    rt_domain = m.group(1).lower()
    if rt_domain and rt_domain != (sender_domain or "").lower():
        return 0.70, rt_domain
    return 0.0, None


def _count_pixels(html: str) -> int:
    low = html.lower()
    count = 0
    pos = 0
    while True:
        idx = low.find("<img", pos)
        if idx == -1:
            break
        end = low.find(">", idx)
        tag = low[idx:end] if end != -1 else low[idx: idx + 300]
        if ("width=1" in tag or "width=\"1\"" in tag) and ("height=1" in tag or "height=\"1\"" in tag):
            count += 1
        pos = idx + 1
    return count


def _count_redirects(html: str) -> int:
    low = html.lower()
    return low.count("http-equiv") + low.count("window.location")


def _attachment_risk(attachments: list[dict]) -> tuple[str, list[str]]:
    """Return (risk_level, [flag_strings])."""
    flags = []
    worst = "none"
    levels = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    for att in attachments:
        fname = (att.get("filename") or "").lower()
        ct = (att.get("content_type") or "").lower()
        _, ext = (fname.rsplit(".", 1) if "." in fname else ("", ""))
        full_ext = "." + ext if ext else ""

        if DOUBLE_EXT_RE.search(fname):
            flags.append(f"double_extension:{fname}")
            worst = max(worst, "medium", key=lambda x: levels[x])

        if full_ext in MACRO_EXTENSIONS:
            if full_ext in {".docm", ".xlsm", ".pptm", ".xlsb", ".hta"}:
                flags.append(f"macro_capable:{fname}")
                worst = max(worst, "critical", key=lambda x: levels[x])
            elif full_ext in {".doc", ".xls", ".ppt"}:
                flags.append(f"legacy_office:{fname}")
                worst = max(worst, "high", key=lambda x: levels[x])
            elif full_ext in {".exe", ".bat", ".cmd", ".scr", ".ps1"}:
                flags.append(f"executable:{fname}")
                worst = max(worst, "critical", key=lambda x: levels[x])
            elif full_ext in {".js", ".vbs", ".wsh"}:
                flags.append(f"script:{fname}")
                worst = max(worst, "critical", key=lambda x: levels[x])

        if "password" in fname and ("zip" in fname or "rar" in fname or "7z" in fname):
            flags.append(f"password_protected_archive:{fname}")
            worst = max(worst, "medium", key=lambda x: levels[x])

    return worst, flags


def _dmarc_alignment(parsed: dict) -> tuple[float, str]:
    """Check DMARC/SPF/DKIM alignment against From domain."""
    sender_domain = (parsed.get("sender_domain") or "").lower()
    spf = (parsed.get("spf_result") or "unknown").lower()
    dkim = (parsed.get("dkim_result") or "unknown").lower()
    dmarc = (parsed.get("dmarc_result") or "unknown").lower()

    if dmarc == "pass":
        return 0.0, "aligned"
    if dmarc == "fail":
        return 0.75, "misaligned"
    fail_count = sum(1 for r in (spf, dkim) if r == "fail")
    if fail_count == 2:
        return 0.65, "misaligned"
    if fail_count == 1:
        return 0.35, "partial"
    return 0.0, "aligned"


async def _domain_age_days(domain: str) -> int | None:
    """Query WHOIS for domain creation date and return age in days. Cached 24h."""
    if domain in _WHOIS_CACHE:
        return _WHOIS_CACHE[domain]

    def _sync_whois() -> int | None:
        try:
            import whois  # type: ignore
            w = whois.whois(domain)
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if created is None:
                return None
            if hasattr(created, "tzinfo") and created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - created).days
            return max(age, 0)
        except Exception:
            return None

    try:
        age = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, _sync_whois),
            timeout=5.0,
        )
    except Exception:
        age = None

    _WHOIS_CACHE[domain] = age
    return age


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

async def run_structural(parsed: dict) -> dict:
    """Engine 4: Structural Forensic Analyst."""
    findings: list[str] = []
    scores: list[float] = []

    sd = parsed.get("sender_domain", "") or ""
    fh = parsed.get("from_header", "") or ""
    rt = parsed.get("reply_to", "") or ""
    bh = parsed.get("body_html", "") or ""
    attachments = parsed.get("attachments", []) or []

    # --- Brand impersonation ---
    if sd:
        bi_score, bi_brand = _brand_impersonation(sd)
        if bi_score > 0:
            findings.append(f"brand_impersonation:{bi_brand or sd}")
            scores.append(bi_score)

    # --- Typosquatting ---
    if sd:
        ts_score, ts_brand, ts_dist = _typosquatting_score(sd)
        if ts_score > 0:
            findings.append(f"typosquatting:dist={ts_dist}:vs={ts_brand}")
            scores.append(ts_score)

    # --- Display name mismatch ---
    dnm = _display_name_mismatch(fh, sd)
    if dnm > 0:
        findings.append("display_name_mismatch")
        scores.append(dnm)

    # --- Reply-To mismatch ---
    rtm_score, rt_domain = _reply_to_mismatch(rt, sd)
    if rtm_score > 0:
        findings.append(f"reply_to_mismatch:{rt_domain}")
        scores.append(rtm_score)

    # --- Domain age (async WHOIS) ---
    if sd:
        age = await _domain_age_days(sd)
        if age is not None:
            if age < 7:
                findings.append(f"domain_age_critical:{age}d")
                scores.append(0.95)
            elif age < 30:
                findings.append(f"domain_age_high:{age}d")
                scores.append(0.75)
            elif age < 90:
                findings.append(f"domain_age_medium:{age}d")
                scores.append(0.40)
    else:
        age = None

    # --- DMARC/auth alignment ---
    align_score, alignment = _dmarc_alignment(parsed)
    if align_score > 0:
        findings.append(f"auth_alignment:{alignment}")
        scores.append(align_score)

    # --- Raw auth failures ---
    af = sum(
        1 for k in ("spf_result", "dkim_result", "dmarc_result")
        if parsed.get(k, "unknown") == "fail"
    )
    if af > 0:
        findings.append(f"auth_failures:{af}")
        scores.append(min(0.40 + af * 0.20, 0.90))

    # --- Tracking pixels ---
    if bh:
        px = _count_pixels(bh)
        if px > 0:
            findings.append(f"tracking_pixels:{px}")
            scores.append(min(0.40 + px * 0.10, 0.70))

        rd = _count_redirects(bh)
        if rd > 0:
            findings.append(f"js_redirects:{rd}")
            scores.append(min(0.50 + rd * 0.15, 0.90))

    # --- Attachment risk ---
    att_risk, att_flags = _attachment_risk(attachments)
    for flag in att_flags:
        findings.append(flag)
    risk_map = {"none": 0.0, "low": 0.20, "medium": 0.50, "high": 0.75, "critical": 0.95}
    if att_risk != "none":
        scores.append(risk_map[att_risk])

    final = max(scores) if scores else 0.0
    logger.info(
        "structural_done",
        score=round(final, 3),
        findings=findings,
        domain_age=age,
        alignment=alignment if align_score > 0 else "aligned",
        att_risk=att_risk,
    )
    return {
        "engine": "structural",
        "score": round(final, 3),
        "findings": findings,
        "domain_age_days": age,
        "auth_alignment": alignment if align_score > 0 else "aligned",
        "attachment_risk": att_risk,
        "red_flags": [
            {"flag": f, "severity": _flag_severity(f)} for f in findings
        ],
    }


def _flag_severity(flag: str) -> str:
    if any(k in flag for k in ("critical", "typosquatting", "homoglyph", "macro_capable", "executable", "script")):
        return "critical"
    if any(k in flag for k in ("brand_impersonation", "display_name_mismatch", "reply_to_mismatch",
                                "domain_age_high", "auth_alignment:misaligned", "legacy_office")):
        return "high"
    if any(k in flag for k in ("domain_age_medium", "auth_failures", "js_redirects",
                                "double_extension", "password_protected_archive")):
        return "medium"
    return "low"
