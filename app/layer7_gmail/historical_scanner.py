"""Layer 7 - Historical Gmail inbox scanner: batch-scans past messages."""
import asyncio
import structlog
from typing import Callable, Optional
from .gmail_client import list_messages, fetch_raw_message, apply_label

logger = structlog.get_logger()


async def scan_inbox(
    analyze_fn: Callable,
    settings,
    query: str = "",
    max_messages: int = 500,
    concurrency: int = 5,
) -> dict:
    """Scan historical inbox messages concurrently. Returns summary counts."""
    stubs = list_messages(settings, query=query, max_results=max_messages)
    if not stubs:
        logger.info("scan_no_messages")
        return {"total": 0, "phishing": 0, "scanned": 0}
    sem = asyncio.Semaphore(concurrency)
    counts = {"total": len(stubs), "scanned": 0, "phishing": 0, "errors": 0}

    async def _process(stub: dict) -> None:
        msg_id = stub.get("id", "")
        async with sem:
            raw = fetch_raw_message(settings, msg_id)
            if not raw:
                counts["errors"] += 1
                return
            try:
                result = await analyze_fn(raw, settings)
                counts["scanned"] += 1
                verdict = result.get("verdict", "")
                if verdict == "phishing":
                    counts["phishing"] += 1
                    apply_label(settings, msg_id, settings.gmail_quarantine_label)
                else:
                    apply_label(settings, msg_id, settings.gmail_scanned_label)
            except Exception as exc:
                logger.warning("scan_err", msg_id=msg_id, error=str(exc))
                counts["errors"] += 1

    await asyncio.gather(*[_process(s) for s in stubs])
    logger.info("scan_complete", **counts)
    return counts
