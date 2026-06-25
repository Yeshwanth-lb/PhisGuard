"""Fast text extraction using trafilatura.

Used by agents that receive plain HTML pages and need clean article text
for LLM processing — stripping nav, ads, headers, footers.
"""
import structlog

logger = structlog.get_logger()


def extract(html: str) -> str:
    """Strip boilerplate from raw HTML and return clean main-content text."""
    if not html:
        return ""
    try:
        import trafilatura
        result = trafilatura.extract(
            html,
            include_links=False,
            include_images=False,
            include_tables=True,
            no_fallback=False,
        )
        return result or html[:4000]  # fallback to truncated raw if trafilatura gets nothing
    except Exception as exc:
        logger.debug("trafilatura_extract_failed", error=str(exc)[:80])
        return html[:4000]


async def fetch_and_extract(url: str) -> str:
    """Fetch an allowlisted URL and extract main text with trafilatura."""
    from app.threatlens.scraper import fetcher
    html = await fetcher.fetch(url)
    return extract(html)
