import re
import httpx
from bs4 import BeautifulSoup
from typing import List
import structlog

logger = structlog.get_logger()

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "tiny.cc", "is.gd", "buff.ly", "adf.ly",
    "rb.gy", "cutt.ly", "shorturl.at",
}

URL_REGEX = re.compile(r"https?://[^\s<>"'\)\]]+", re.IGNORECASE)
HREF_REGEX = re.compile(r"href=["']?(https?://[^"'>\s]+)", re.IGNORECASE)


def extract_urls(body_text: str = "", body_html: str = "") -> List[str]:
    found: set = set()
    if body_text:
        for url in URL_REGEX.findall(body_text):
            found.add(url.rstrip(".,;)"))
    if body_html:
        for url in HREF_REGEX.findall(body_html):
            found.add(url.rstrip(".,;)"))
        try:
            soup = BeautifulSoup(body_html, "lxml")
            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                if href.startswith("http"):
                    found.add(href.rstrip(".,;)"))
        except Exception:
            pass
    return list(found)


async def resolve_url(url: str, timeout: int = 10) -> str:
    ua = "Mozilla" + "/5.0 (compatible; PhishGuard-Scanner)"
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout,
            headers={"User-Agent": ua},
        ) as client:
            resp = await client.head(url)
            return str(resp.url)
    except Exception as e:
        logger.warning("url_resolve_failed", url=url, error=str(e))
        return url


async def resolve_shortened_urls(urls: List[str]) -> List[str]:
    resolved = []
    for url in urls:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc.lower().lstrip("www.")
            if domain in URL_SHORTENERS:
                real_url = await resolve_url(url)
                logger.info("shortened_url_resolved", original=url, resolved=real_url)
                resolved.append(real_url)
            else:
                resolved.append(url)
        except Exception:
            resolved.append(url)
    return resolved
