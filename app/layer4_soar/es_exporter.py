"""Layer 4 - Elasticsearch exporter: index every verdict document."""
from datetime import UTC, datetime

import structlog

logger = structlog.get_logger()


async def export_to_es(verdict_doc: dict, settings) -> bool:
    """Index a verdict document into Elasticsearch. Returns True on success."""
    es_url = getattr(settings, "elasticsearch_url", None)
    if not es_url:
        return False
    try:
        import httpx
    except ImportError:
        return False

    parsed = verdict_doc.get("parsed") or {}
    l1 = verdict_doc.get("l1") or {}
    l2 = verdict_doc.get("l2") or {}
    l3 = verdict_doc.get("l3") or {}
    l5 = verdict_doc.get("l5") or {}

    doc = {
        "@timestamp": datetime.now(UTC).isoformat(),
        "verdict": verdict_doc.get("verdict"),
        "confidence": verdict_doc.get("confidence", 0.0),
        "blocked_at": verdict_doc.get("blocked_at"),
        "email_id": verdict_doc.get("email_id"),
        "sender": parsed.get("from_header"),
        "sender_domain": parsed.get("sender_domain"),
        "sender_ip": parsed.get("sender_ip"),
        "subject": parsed.get("subject"),
        "url_count": len(parsed.get("urls") or []),
        "attachment_count": len(parsed.get("attachment_hashes") or []),
        "l1_hits": l1.get("hits", []),
        "l1_verdict": l1.get("verdict"),
        "l2_engine_scores": l2.get("engine_scores", {}),
        "l2_verdict": l2.get("verdict"),
        "l2_confidence": l2.get("confidence"),
        "l3_verdict": l3.get("verdict") if l3 else None,
        "l3_score": l3.get("score") if l3 else None,
        "l3_final_url": l3.get("final_url") if l3 else None,
        "l3_page_findings": l3.get("page_findings") if l3 else [],
        "l3_ocr_findings": l3.get("ocr_findings") if l3 else [],
        "ml_score": l5.get("ml_score") if l5 else None,
        "ml_label": l5.get("ml_label") if l5 else None,
        "ml_available": l5.get("ml_available", False) if l5 else False,
    }

    sl = chr(47)
    today = datetime.now(UTC).strftime("%Y.%m.%d")
    index = f"phishguard-verdicts-{today}"
    url = es_url.rstrip(sl) + sl + index + sl + "_doc"

    user = getattr(settings, "elasticsearch_username", "")
    pwd = getattr(settings, "elasticsearch_password", "")
    auth = (user, pwd) if user else None

    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.post(url, json=doc, auth=auth, timeout=10)
            resp.raise_for_status()
            logger.info("es_indexed", verdict=doc["verdict"], index=index)
            return True
    except Exception as exc:
        logger.warning("es_export_error", error=str(exc))
        return False
