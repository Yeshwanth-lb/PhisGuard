"""PhishGuard analysis pipeline orchestrator."""
import structlog
from typing import Optional
from app.parser.email_parser import parse_email
from app.parser.url_extractor import extract_urls, resolve_shortened_urls
from app.layer1.verdicts import run_layer1
from app.layer1.cache import L1Cache

logger = structlog.get_logger()

_cache: Optional[L1Cache] = None


async def get_cache(redis_url: str) -> L1Cache:
    """Return (or lazily create) the shared L1Cache instance."""
    global _cache
    if _cache is None:
        _cache = L1Cache(redis_url=redis_url)
        await _cache.connect()
    return _cache


async def analyze_email(raw_eml: bytes, settings) -> dict:
    """Full analysis pipeline. Returns a verdict dict."""
    parsed = parse_email(raw_eml)
    if not parsed:
        return {"verdict": "error", "reason": "parse_failed"}

    sender_ip = parsed.get("sender_ip")
    body_text = parsed.get("body_text", "") or ""
    body_html = parsed.get("body_html", "") or ""
    att_hashes = parsed.get("attachment_hashes", [])

    raw_urls = extract_urls(body_text=body_text, body_html=body_html)
    urls = await resolve_shortened_urls(raw_urls)

    cache = await get_cache(settings.redis_url)
    l1 = await run_layer1(
        sender_ip=sender_ip,
        urls=urls,
        attachment_hashes=att_hashes,
        settings=settings,
        cache=cache,
    )

    if l1["verdict"] == "quarantine":
        logger.info("quarantine_at_l1", sender_ip=sender_ip, hits=len(l1["hits"]))
        return {
            "verdict": "phishing",
            "confidence": 1.0,
            "blocked_at": "layer1",
            "hits": l1["hits"],
            "parsed": parsed,
        }

    return {
        "verdict": l1["verdict"],
        "confidence": 0.5 if l1["verdict"] == "suspicious" else 0.0,
        "blocked_at": None,
        "l1": l1,
        "parsed": parsed,
    }
