"""Layer 5 - Feature extractor: converts verdict docs to ML feature vectors."""
import re
from typing import Any
from urllib.parse import urlparse

BRANDS = [
    "paypal", "amazon", "microsoft", "google", "apple", "netflix",
    "fedex", "dhl", "bank", "chase", "wellsfargo", "citi", "capitalone",
    "linkedin", "facebook", "instagram", "dropbox", "docusign",
]

URGENT_WORDS = [
    "urgent", "verify", "suspended", "immediately", "confirm", "unusual",
    "locked", "expire", "expired", "alert", "action required", "validate",
    "reactivate", "limited", "compromised",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "tiny.cc", "is.gd",
    "buff.ly", "adf.ly", "rb.gy", "cutt.ly", "shorturl.at",
}

_DOMAIN_LIKE_RE = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", re.IGNORECASE)


def _domain_of_url(u):
    try:
        netloc = urlparse(u).netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc
    except Exception:
        return ""


def _domain_of_email(addr):
    if not addr:
        return ""
    m = re.search(r"@([\w.-]+)", addr)
    return m.group(1).lower() if m else ""


def _anchor_href_mismatch_count(body_html):
    if not body_html:
        return 0
    try:
        from bs4 import BeautifulSoup
    except Exception:
        return 0
    try:
        soup = BeautifulSoup(body_html, "lxml")
    except Exception:
        try:
            soup = BeautifulSoup(body_html, "html.parser")
        except Exception:
            return 0
    n = 0
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if not href.startswith("http"):
            continue
        href_dom = _domain_of_url(href)
        text = (a.get_text() or "").strip().lower()
        if not href_dom or not text:
            continue
        text_doms = [d for d in _DOMAIN_LIKE_RE.findall(text) if "." in d]
        if not text_doms:
            continue
        if not any(td in href_dom or href_dom in td for td in text_doms):
            n += 1
    return n


def extract_features(verdict_doc: dict) -> dict[str, Any]:
    """Extract a flat numeric feature dict from a verdict document."""
    parsed = verdict_doc.get("parsed") or {}
    l1 = verdict_doc.get("l1") or {}
    l2 = verdict_doc.get("l2") or {}
    subject_raw = parsed.get("subject") or ""
    subject = subject_raw.lower()
    body_text = parsed.get("body_text") or ""
    body_html = parsed.get("body_html") or ""
    body_combined = (body_text + " " + body_html).lower()
    urls = parsed.get("urls") or []
    hdrs = parsed.get("headers") or {}
    eng_scores = l2.get("engine_scores") or {}

    from_addr = parsed.get("from_header") or hdrs.get("From") or ""
    reply_to = parsed.get("reply_to") or hdrs.get("Reply-To") or ""
    from_dom = _domain_of_email(from_addr)
    reply_dom = _domain_of_email(reply_to)
    reply_to_mismatch = int(bool(reply_dom) and bool(from_dom) and reply_dom != from_dom)

    _doms = list(filter(None, map(_domain_of_url, urls)))
    distinct_url_domains = len(set(_doms))
    shortener_url_count = sum(1 for d in _doms if d in URL_SHORTENERS)

    subject_alpha = list(filter(str.isalpha, subject_raw))
    subject_uppercase_ratio = (
        sum(map(str.isupper, subject_alpha)) / len(subject_alpha)
        if subject_alpha else 0.0
    )
    subject_exclamation_count = subject_raw.count("!")
    subject_non_ascii_count = sum(1 for c in subject_raw if ord(c) > 127)

    body_length = min(len(body_text) + len(body_html), 50000)
    html_only = int(bool(body_html) and len(body_text) < 32)
    body_brand_count = sum(1 for b in BRANDS if b in body_combined)

    urgent_scope = subject + " " + body_combined[:1024]
    urgent_word_count = sum(1 for w in URGENT_WORDS if w in urgent_scope)

    return {
        "url_count": len(urls),
        "has_http_url": int(any(u.startswith("http:") for u in urls)),
        "has_ip_url": int(any(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u) for u in urls)),
        "l1_hit_count": len(l1.get("hits", [])),
        "structural_score": float(eng_scores.get("structural", 0.0)),
        "nlp_score": float(eng_scores.get("nlp", 0.0)),
        "behavioral_score": float(eng_scores.get("behavioral", 0.0)),
        "l2_confidence": float(l2.get("confidence", 0.0)),
        "urgent_word_count": urgent_word_count,
        "brand_spoof_count": sum(1 for b in BRANDS if b in subject),
        "subject_len": len(subject_raw),
        "spf_fail": int("fail" in str(hdrs.get("received-spf", "")).lower()),
        "dkim_fail": int("fail" in str(hdrs.get("dkim-signature", "")).lower()),
        "attachment_count": len(parsed.get("attachment_hashes", [])),
        "body_length": body_length,
        "html_only": html_only,
        "distinct_url_domains": distinct_url_domains,
        "shortener_url_count": shortener_url_count,
        "body_brand_count": body_brand_count,
        "reply_to_mismatch": reply_to_mismatch,
        "subject_uppercase_ratio": round(subject_uppercase_ratio, 4),
        "subject_exclamation_count": subject_exclamation_count,
        "subject_non_ascii_count": subject_non_ascii_count,
        "anchor_text_href_mismatch": _anchor_href_mismatch_count(body_html),
    }


def label_from_verdict(verdict_doc: dict) -> int:
    """Return 1 for phishing, 0 otherwise."""
    v = verdict_doc.get("verdict", "")
    return 1 if v == "phishing" else 0

FEATURE_KEYS = [
    "url_count", "has_http_url", "has_ip_url",
    "l1_hit_count", "structural_score", "nlp_score",
    "behavioral_score", "l2_confidence", "urgent_word_count",
    "brand_spoof_count", "subject_len", "spf_fail",
    "dkim_fail", "attachment_count",
    "body_length", "html_only", "distinct_url_domains",
    "shortener_url_count", "body_brand_count", "reply_to_mismatch",
    "subject_uppercase_ratio", "subject_exclamation_count",
    "subject_non_ascii_count", "anchor_text_href_mismatch",
]
