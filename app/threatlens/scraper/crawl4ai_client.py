"""Crawl4AI wrapper — LLM-facing Markdown extractor.

Routes through fetcher.py chokepoint first. If Crawl4AI is unavailable,
falls back to fetcher.fetch() (plain httpx). This keeps the legal boundary
intact regardless of which extraction path runs.
"""
import structlog

from app.threatlens.scraper.fetcher import DisallowedSourceError, fetch, is_allowed

logger = structlog.get_logger()


async def get(url: str, query: str | None = None) -> str:
    """Fetch a page and return LLM-ready Markdown.

    Args:
        url:   The page to fetch. Must be on the allowlist.
        query: Optional relevance query for BM25/fit-markdown filtering.

    Raises:
        DisallowedSourceError: if url is not on the allowlist.
    """
    if not is_allowed(url):
        raise DisallowedSourceError(
            f"crawl4ai_client: host not on allowlist — {url}"
        )

    try:
        from crawl4ai import AsyncWebCrawler, CrawlerRunConfig  # type: ignore
        config = CrawlerRunConfig(
            word_count_threshold=10,
            only_text=False,
        )
        async with AsyncWebCrawler(headless=True, verbose=False) as crawler:
            result = await crawler.arun(url=url, config=config)
            if result.success and result.markdown:
                return result.markdown
            # Fall through to httpx on empty result
    except Exception as exc:
        logger.debug("crawl4ai_unavailable", error=str(exc)[:100])

    # Fallback — plain fetch (allowlist already confirmed above)
    return await fetch(url)
