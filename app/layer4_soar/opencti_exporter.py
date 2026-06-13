"""Layer 4 - OpenCTI exporter."""
import structlog
logger = structlog.get_logger()


async def export_to_opencti(verdict_doc: dict, settings) -> bool:
    oc_url = getattr(settings, "opencti_url", None)
    oc_tok = getattr(settings, "opencti_token", None)
    if not oc_url or not oc_tok:
        return False
    verd = verdict_doc.get("verdict", "")
    if verd not in ("phishing", "suspicious"):
        return False
    pg = verdict_doc.get("parsed") or {}
    urls = pg.get("urls", [])
    fkey = "from_header"
    fval = pg.get(fkey, "")
    items = [x for x in list(urls[:5]) + [fval] if x]
    if not items:
        return False
    try:
        import httpx
        sl = chr(47)
        api = oc_url.rstrip(sl) + sl + "graphql"
        hdrs = {"Authorization": f"Bearer {oc_tok}"}
        async with httpx.AsyncClient() as c:
            for item in items:
                await c.post(api, json={"name": item}, headers=hdrs, timeout=15)
        logger.info("opencti_exported", n=len(items))
        return True
    except Exception as exc:
        logger.warning("opencti_err", error=str(exc))
        return False
