"""Layer 5 - Feature extractor: converts verdict docs to ML feature vectors."""
import re
from typing import Dict, Any

BRANDS = ["paypal", "amazon", "microsoft", "google", "apple", "netflix", "fedex", "dhl"]


def extract_features(verdict_doc: dict) -> Dict[str, Any]:
    """Extract a flat numeric feature dict from a verdict document."""
    parsed = verdict_doc.get("parsed") or {}
    l1 = verdict_doc.get("l1") or {}
    l2 = verdict_doc.get("l2") or {}
    subject = parsed.get("subject", "").lower()
    urls = parsed.get("urls", [])
    hdrs = parsed.get("headers") or {}
    eng_scores = l2.get("engine_scores") or {}
    urgent_words = ["urgent", "verify", "suspended", "immediately", "confirm", "unusual", "locked"]
    return {
        "url_count": len(urls),
        "has_http_url": int(any(u.startswith("http:") for u in urls)),
        "has_ip_url": int(any(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u) for u in urls)),
        "l1_hit_count": len(l1.get("hits", [])),
        "structural_score": float(eng_scores.get("structural", 0.0)),
        "nlp_score": float(eng_scores.get("nlp", 0.0)),
        "behavioral_score": float(eng_scores.get("behavioral", 0.0)),
        "l2_confidence": float(l2.get("confidence", 0.0)),
        "urgent_word_count": sum(1 for w in urgent_words if w in subject),
        "brand_spoof_count": sum(1 for b in BRANDS if b in subject),
        "subject_len": len(subject),
        "spf_fail": int("fail" in hdrs.get("received-spf", "").lower()),
        "dkim_fail": int("fail" in hdrs.get("dkim-signature", "").lower()),
        "attachment_count": len(parsed.get("attachment_hashes", [])),
    }


def label_from_verdict(verdict_doc: dict) -> int:
    """Return 1 for phishing, 0 otherwise."""
    v = verdict_doc.get("verdict", "")
    return 1 if v == "phishing" else 0
