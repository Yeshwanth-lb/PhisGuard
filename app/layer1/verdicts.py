"""Aggregate Layer 1 OSINT results into a single L1 verdict."""
import asyncio
import structlog
from typing import Optional, List
from app.layer1.cache import L1Cache
from app.layer1.osint_client import (
    vt_check_ip, vt_check_url,
    abuseipdb_check, urlhaus_check,
    spamhaus_check, misp_check,
)

logger = structlog.get_logger()

QUARANTINE_THRESHOLD = 1   # any single malicious hit -> quarantine
SUSPICIOUS_SCORE     = 50  # AbuseIPDB score >= 50 -> suspicious
MAX_URLS_PER_EMAIL   = 10  # cap URL checks to avoid rate limits


async def run_layer1(
    sender_ip: Optional[str],
    urls: List[str],
    attachment_hashes: List[str],
    settings,
    cache: L1Cache,
) -> dict:
    """
    Run all 5 OSINT sources concurrently.
    Returns dict with keys: verdict, hits, details.
    verdict is one of: clean | suspicious | quarantine
    """
    tasks = []

    if sender_ip:
        tasks.append(vt_check_ip(sender_ip, settings.virustotal_api_key, cache))
        tasks.append(abuseipdb_check(sender_ip, settings.abuseipdb_api_key, cache))
        tasks.append(spamhaus_check(sender_ip, cache))
        tasks.append(misp_check(sender_ip, settings.misp_url, settings.misp_api_key, cache))

    for url in urls[:MAX_URLS_PER_EMAIL]:
        tasks.append(vt_check_url(url, settings.virustotal_api_key, cache))
        tasks.append(urlhaus_check(url, cache))

    if not tasks:
        return {"verdict": "clean", "hits": [], "details": []}

    results = await asyncio.gather(*tasks, return_exceptions=True)
    hits: list = []
    details: list = []
    max_abuse_score = 0

    for r in results:
        if isinstance(r, Exception):
            logger.warning("l1_task_error", error=str(r))
            continue
        details.append(r)
        if r.get("malicious"):
            hits.append(r)
        if r.get("source") == "abuseipdb":
            max_abuse_score = max(max_abuse_score, r.get("score", 0))

    if hits:
        verdict = "quarantine"
    elif max_abuse_score >= SUSPICIOUS_SCORE:
        verdict = "suspicious"
    else:
        verdict = "clean"

    logger.info(
        "l1_verdict",
        verdict=verdict,
        hits=len(hits),
        sources_checked=len(details),
    )
    return {"verdict": verdict, "hits": hits, "details": details}
