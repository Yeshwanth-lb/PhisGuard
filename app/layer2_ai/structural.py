"""Engine 4 - Structural Forensic Analyst."""
import re
import structlog
from typing import List

logger = structlog.get_logger()

HOMOGLYPHS: dict = {
    "а": "a", "е": "e",
    "о": "o", "р": "p",
    "с": "c", "у": "y",
    "і": "i", "ν": "v",
    "μ": "u", "ο": "o",
    "α": "a",
}

HIGH_VALUE_BRANDS: set = {
    "paypal", "amazon", "microsoft", "apple",
    "google", "netflix", "bank", "wellsfargo",
    "chase", "citibank", "fedex", "dhl",
    "irs", "usps", "linkedin", "facebook",
}

def _normalize(domain: str) -> str:
    return "".join(HOMOGLYPHS.get(c, c) for c in domain.lower())

def _has_homoglyph(domain: str) -> bool:
    return any(c in HOMOGLYPHS for c in domain.lower())

def _brand_score(domain: str) -> float:
    norm = _normalize(domain)
    base = norm.split(".")[0]
    for brand in HIGH_VALUE_BRANDS:
        if brand in base and base != brand:
            return 0.9
    if _has_homoglyph(domain): return 0.85
    return 0.0

def _display_mismatch(from_hdr: str, sender_domain: str) -> float:
    m = re.match(r'^"?([^"<]+)"?\\s*<', from_hdr or "")
    if not m: return 0.0
    name = m.group(1).lower()
    for brand in HIGH_VALUE_BRANDS:
        if brand in name and brand not in (sender_domain or "").lower():
            return 0.85
    return 0.0

def _count_pixels(html: str) -> int:
    low = html.lower(); count = 0; pos = 0
    while True:
        idx = low.find("<img", pos)
        if idx == -1: break
        end = low.find(">", idx)
        tag = low[idx:end] if end != -1 else low[idx:idx+300]
        if ("width=1" in tag) and ("height=1" in tag): count += 1
        pos = idx + 1
    return count

def _count_redirects(html: str) -> int:
    low = html.lower()
    return low.count("http-equiv") + low.count("window.location")

async def run_structural(parsed: dict) -> dict:
    """Engine 4: Structural Forensic Analyst."""
    findings: List[str] = []; scores: List[float] = []
    sd = parsed.get("sender_domain", "") or ""
    fh = parsed.get("from_header", "") or ""
    rt = parsed.get("reply_to", "") or ""
    bh = parsed.get("body_html", "") or ""
    bs = _brand_score(sd)
    if bs > 0: findings.append(f"brand_impersonation:{sd}"); scores.append(bs)
    ms = _display_mismatch(fh, sd)
    if ms > 0: findings.append("display_name_mismatch"); scores.append(ms)
    if rt:
        rtm = re.search("@([\\w.-]+)", rt)
        if rtm and rtm.group(1).lower() != sd:
            findings.append(f"reply_to_diff:{rtm.group(1)}"); scores.append(0.6)
    if bh:
        px = _count_pixels(bh)
        if px > 0: findings.append(f"pixels:{px}"); scores.append(min(0.4+px * 0.1, 0.7))
        rd = _count_redirects(bh)
        if rd > 0: findings.append(f"redirects:{rd}"); scores.append(min(0.5+rd * 0.15, 0.9))
    af = sum(1 for k in ("spf_result", "dkim_result", "dmarc_result") if parsed.get(k,"unknown") == "fail")
    if af > 0: findings.append(f"auth_failures:{af}"); scores.append(min(0.4+af * 0.2, 0.9))
    final = max(scores) if scores else 0.0
    logger.info("structural_done", score=round(final,3), findings=findings)
    return {"engine": "structural", "score": round(final,3), "findings": findings}
