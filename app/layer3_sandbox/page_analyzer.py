"""Layer 3 - Page Analyzer: DOM, redirect, credential field detection."""

import structlog

logger = structlog.get_logger()

CREDENTIAL_FIELDS = {
    "password", "passwd", "pwd",
    "ssn", "credit", "card", "cvv",
    "pin", "otp", "token", "account",
    "username", "login",
}

SUSPICIOUS_JS = [
    "document.cookie", "localStorage", "sessionStorage",
    "eval(", "atob(", "fromCharCode", "keydown",
]


def analyze_page(crawl_result: dict) -> dict:
    """Analyze Puppeteer crawl result dict."""
    score = 0.0; findings: list[str] = []
    dom = (crawl_result.get("dom_html", "") or "").lower()
    scripts = crawl_result.get("scripts", [])
    fdata = crawl_result.get("form_data", [])
    redirects = crawl_result.get("redirects", [])
    orig_url = crawl_result.get("url", "")
    final_url = crawl_result.get("final_url", orig_url)
    title = (crawl_result.get("title", "") or "").lower()
    cred_count = 0
    for fitem in fdata:
        for field in fitem.get("fields", []):
            fname = field.get("name", "").lower()
            ftype = field.get("type", "").lower()
            if any(kw in fname for kw in CREDENTIAL_FIELDS) or ftype == "password":
                cred_count += 1
    if cred_count > 0:
        findings.append(f"cred_fields:{cred_count}")
        score = max(score, 0.7 + min(cred_count, 3) * 0.05)
    n_redirects = len(redirects)
    if n_redirects > 2:
        findings.append(f"redirect_chain:{n_redirects}")
        score = max(score, min(0.3 + n_redirects * 0.1, 0.7))
    if orig_url and final_url and orig_url != final_url:
        findings.append(f"url_redirect:{final_url[:80]}")
        score = max(score, 0.4)
    for patt in SUSPICIOUS_JS:
        for script in scripts:
            if patt in (script or ""):
                findings.append(f"sus_js:{patt}")
                score = max(score, 0.5)
                break
    from app.layer2_ai.structural import HIGH_VALUE_BRANDS
    for brand in HIGH_VALUE_BRANDS:
        if brand in title:
            findings.append(f"title_brand:{brand}")
            score = max(score, 0.6)
            break
    final = round(min(score, 1.0), 3)
    logger.info("page_analysis", score=final, findings=findings)
    return {"score": final, "findings": findings, "cred_fields": cred_count, "redirects": n_redirects}
