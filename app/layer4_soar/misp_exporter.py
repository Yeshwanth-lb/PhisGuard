"""Layer 4 - MISP exporter: publish IOCs as MISP threat events."""
import structlog
from datetime import datetime, timezone
logger = structlog.get_logger()


def _build_misp_event(verdict_doc: dict) -> dict:
    parsed = verdict_doc.get("parsed") or {}
    sender = parsed.get("from_header", "")
    subject = parsed.get("subject", "")
    urls = parsed.get("urls", [])
    conf = verdict_doc.get("confidence", 0.0)
    attrs = []
    if sender:
        attrs.append({"type": "email-src", "value": sender, "category": "Payload delivery"})
    for u in urls:
        attrs.append({"type": "url", "value": u, "category": "External analysis"})
    return {
        "Event": {
            "info": f"PhishGuard detection: {subject}",
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "threat_level_id": "1",
            "analysis": "2",
            "distribution": "1",
            "Attribute": attrs,
        }
    }


async def export_to_misp(verdict_doc: dict, settings) -> bool:
    misp_url = getattr(settings, "misp_url", None)
    misp_key = getattr(settings, "misp_api_key", None)
    if not misp_url or not misp_key:
        return False
    verdict = verdict_doc.get("verdict", "")
    if verdict not in ("phishing",):
        return False
    try:
        import httpx
        event = _build_misp_event(verdict_doc)
        sl = chr(47)
        url = misp_url.rstrip(sl) + sl + "events"
        hdrs = {"Authorization": misp_key, "Accept": "application/json", "Content-Type": "application/json"}
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.post(url, json=event, headers=hdrs, timeout=15)
            resp.raise_for_status()
            logger.info("misp_exported")
            return True
    except Exception as exc:
        logger.warning("misp_error", error=str(exc))
        return False
