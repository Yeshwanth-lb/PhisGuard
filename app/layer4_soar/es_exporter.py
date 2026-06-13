"""Layer 4 - Elasticsearch exporter: index every verdict document."""
import json
import structlog
from datetime import datetime, timezone
from typing import Optional
logger = structlog.get_logger()


async def export_to_es(verdict_doc: dict, settings) -> bool:
    """Index a verdict document into Elasticsearch. Returns True on success."""
    es_url = getattr(settings, "elasticsearch_url", None)
    if not es_url:
        logger.debug("es_export_skipped", reason="no_url")
        return False
    try:
        import httpx
    except ImportError:
        logger.warning("httpx_missing")
        return False
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict_doc.get("verdict"),
        "confidence": verdict_doc.get("confidence", 0.0),
        "blocked_at": verdict_doc.get("blocked_at"),
        "sender_domain": (verdict_doc.get("parsed") or {}).get("sender_domain"),
        "l1_hits": (verdict_doc.get("l1") or {}).get("hits", []),
        "l2_scores": (verdict_doc.get("l2") or {}).get("engine_scores", {}),
    }
    sl = chr(47)
    index = "phishguard-verdicts"
    url = es_url.rstrip(sl) + sl + index + sl + "_doc"
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, json=doc, timeout=10)
            resp.raise_for_status()
            logger.info("es_indexed", verdict=doc["verdict"], status=resp.status_code)
            return True
    except Exception as exc:
        logger.warning("es_export_error", error=str(exc))
        return False
