"""Scrapling wrapper — adaptive resilient fetcher.

Routes through fetcher.py chokepoint first. Scrapling's anti-bot and
adaptive-selector features are used ONLY on public allowlisted sources —
never to defeat an access-control gate. Falls back to fetcher.fetch()
if Scrapling is unavailable.
"""
import structlog

from app.threatlens.scraper.fetcher import DisallowedSourceError, fetch, is_allowed

logger = structlog.get_logger()


async def get(url: str) -> str:
    """Fetch a page using Scrapling's resilient engine.

    Raises:
        DisallowedSourceError: if url is not on the allowlist.
    """
    if not is_allowed(url):
        raise DisallowedSourceError(
            f"scrapling_client: host not on allowlist — {url}"
        )

    try:
        from scrapling import AsyncFetcher  # type: ignore
        fetcher_s = AsyncFetcher(auto_match=False)
        page = await fetcher_s.get(url)
        return page.get_all_text(ignore_tags=["script", "style"]) or ""
    except Exception as exc:
        logger.debug("scrapling_unavailable", error=str(exc)[:100])

    return await fetch(url)
