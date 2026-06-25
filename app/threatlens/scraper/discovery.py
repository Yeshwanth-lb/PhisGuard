"""Optional Katana URL/endpoint discovery on allowlisted hosts.

Katana is a Go binary (MIT, by ProjectDiscovery). This module is a stub —
if Katana is installed and on PATH, it discovers URLs on a host before the
OSINT agent decides what to fetch. If absent, it returns [].

Install: go install github.com/projectdiscovery/katana/cmd/katana@latest
"""
import asyncio
import shutil

import structlog

from app.threatlens.scraper.fetcher import is_allowed

logger = structlog.get_logger()


async def discover(base_url: str, depth: int = 1, max_urls: int = 20) -> list[str]:
    """Run Katana on an allowlisted host and return discovered URLs.

    Returns [] if Katana is not installed or host is not on the allowlist.
    """
    if not is_allowed(base_url):
        logger.debug("katana_skip_not_allowlisted", url=base_url)
        return []

    if not shutil.which("katana"):
        logger.debug("katana_not_installed")
        return []

    try:
        proc = await asyncio.create_subprocess_exec(
            "katana",
            "-u", base_url,
            "-depth", str(depth),
            "-silent",
            "-no-color",
            "-max-response-body-size", "2000000",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        urls = [
            line.strip()
            for line in stdout.decode().splitlines()
            if line.strip() and is_allowed(line.strip())
        ]
        return urls[:max_urls]
    except Exception as exc:
        logger.debug("katana_error", error=str(exc)[:80])
        return []
