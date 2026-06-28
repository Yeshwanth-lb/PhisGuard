import asyncio
import ipaddress
import re
import socket
from urllib.parse import urlparse

import httpx
import structlog
from bs4 import BeautifulSoup

logger = structlog.get_logger()


def _is_public_host(host: str) -> bool:
    """True only if every IP `host` resolves to is a routable public address. Blocks
    SSRF to loopback / private / link-local (e.g. 169.254.169.254 cloud metadata) /
    reserved ranges. Fail-closed (unresolvable -> not public)."""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            return False
    return True

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "tiny.cc", "is.gd", "buff.ly", "adf.ly",
    "rb.gy", "cutt.ly", "shorturl.at",
}

URL_REGEX  = re.compile(r'https?://[A-Za-z0-9._%+~:/?#@!&()=;,\[\]-]+', re.IGNORECASE)
HREF_REGEX = re.compile(r'href=[\x22\x27]?(https?://[^\x22\x27>\s]+)', re.IGNORECASE)


def extract_urls(body_text: str = "", body_html: str = "") -> list[str]:
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


async def resolve_url(url: str, timeout: int = 10, max_redirects: int = 5) -> str:
    """Resolve a shortened URL to its final target, following redirects MANUALLY so each
    hop's host can be validated as public before we connect — preventing SSRF to internal
    hosts/cloud metadata via attacker-controlled redirects. If any hop targets a non-public
    host, we stop and return the last URL WITHOUT fetching it."""
    ua = "Mozilla" + "/5.0 (compatible; PhishGuard-Scanner)"
    loop = asyncio.get_event_loop()
    current = url
    try:
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=timeout, headers={"User-Agent": ua},
        ) as client:
            for _ in range(max_redirects):
                host = urlparse(current).hostname or ""
                if not await loop.run_in_executor(None, _is_public_host, host):
                    logger.warning("url_resolve_blocked_nonpublic", url=current)
                    return current
                resp = await client.head(current)
                loc = resp.headers.get("location")
                if resp.is_redirect and loc:
                    current = str(httpx.URL(resp.url).join(loc))
                    continue
                return str(resp.url)
            return current
    except Exception as e:
        logger.warning("url_resolve_failed", url=url, error=str(e))
        return url


async def resolve_shortened_urls(urls: list[str]) -> list[str]:
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
