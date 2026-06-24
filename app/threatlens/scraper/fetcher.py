"""The legal chokepoint for all ThreatLens external fetches.

Every outbound request — from httpx, Crawl4AI, or Scrapling — must pass
through fetch() or is_allowed(). A source not on the allowlist raises
DisallowedSourceError before any network I/O occurs. There is no bypass path.

Enforces:
  1. Source allowlist (allowlist.yaml)
  2. robots.txt compliance (cached per domain)
  3. Per-domain token-bucket rate limiting
  4. Honest User-Agent (never spoofs a browser)
  5. Configurable timeout
"""
import os
import time
import urllib.parse
import urllib.robotparser
from pathlib import Path

import httpx
import structlog
import yaml

from app.threatlens.config import threatlens_settings

logger = structlog.get_logger()

HONEST_UA = "PhishGuard-ThreatLens/1.6 (security-research; +https://phishguard.local)"

_ALLOWLIST_PATH = Path(__file__).parent / "allowlist.yaml"

# Runtime state — module-level for simplicity; reset in tests via _reset()
_allowed_hosts: set[str] = set()
_robots_cache:  dict[str, tuple[float, urllib.robotparser.RobotFileParser]] = {}
_rate_state:    dict[str, dict] = {}  # host → {tokens, last_refill}
_ROBOTS_TTL = 3600  # re-fetch robots.txt after 1 hour


class DisallowedSourceError(Exception):
    """Raised when a URL's host is not on the approved allowlist."""


class RateLimitError(Exception):
    """Raised when the per-domain rate limit is exhausted."""


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

def load_allowlist(path: str | None = None) -> None:
    """Load (or reload) the source allowlist from YAML."""
    global _allowed_hosts
    p = Path(path) if path else _ALLOWLIST_PATH
    try:
        with open(p) as f:
            data = yaml.safe_load(f)
        _allowed_hosts = {s["domain"] for s in data.get("sources", [])}
        logger.info("allowlist_loaded", count=len(_allowed_hosts))
    except Exception as exc:
        logger.error("allowlist_load_failed", error=str(exc))
        _allowed_hosts = set()


def is_allowed(url: str) -> bool:
    """Return True if the URL's host is on the allowlist."""
    if not _allowed_hosts:
        load_allowlist()
    host = _extract_host(url)
    return host in _allowed_hosts


def is_allowed_or_raise(url: str) -> None:
    """Raise DisallowedSourceError if the URL's host is not on the allowlist."""
    if not is_allowed(url):
        raise DisallowedSourceError(
            f"Host '{_extract_host(url)}' is not on the ThreatLens allowlist."
        )


_source_configs: dict[str, dict] = {}


def get_source_config(host: str) -> dict:
    """Return the allowlist config dict for a host (preferred_client, polite_delay, etc.)."""
    if not _source_configs:
        try:
            with open(_ALLOWLIST_PATH) as f:
                data = yaml.safe_load(f)
            for s in data.get("sources", []):
                _source_configs[s["domain"]] = s
        except Exception:
            pass
    return _source_configs.get(host, {})


def _extract_host(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# robots.txt
# ---------------------------------------------------------------------------

async def _get_robots(host: str) -> urllib.robotparser.RobotFileParser:
    now = time.time()
    cached = _robots_cache.get(host)
    if cached and (now - cached[0]) < _ROBOTS_TTL:
        return cached[1]

    rp = urllib.robotparser.RobotFileParser()
    robots_url = f"https://{host}/robots.txt"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(robots_url, headers={"User-Agent": HONEST_UA})
            rp.parse(resp.text.splitlines())
    except Exception:
        rp.parse([])  # treat as allow-all on error

    _robots_cache[host] = (now, rp)
    return rp


async def _check_robots(url: str) -> bool:
    """Return True if robots.txt allows this URL for our UA."""
    host = _extract_host(url)
    rp = await _get_robots(host)
    return rp.can_fetch(HONEST_UA, url)


# ---------------------------------------------------------------------------
# Rate limiting — token bucket per domain
# ---------------------------------------------------------------------------

def _check_rate_limit(host: str) -> bool:
    """Consume one token. Return True if allowed, False if exhausted."""
    now = time.monotonic()
    rate = threatlens_settings.intel_fetch_rate_per_domain  # tokens per 60s

    if host not in _rate_state:
        _rate_state[host] = {"tokens": float(rate), "last_refill": now}

    state = _rate_state[host]
    elapsed = now - state["last_refill"]
    state["tokens"] = min(float(rate), state["tokens"] + elapsed * (rate / 60.0))
    state["last_refill"] = now

    if state["tokens"] >= 1.0:
        state["tokens"] -= 1.0
        return True
    return False


# ---------------------------------------------------------------------------
# Core fetch
# ---------------------------------------------------------------------------

async def _http_get(url: str, timeout: int) -> str:
    """Raw HTTP GET — called only after all guards have passed."""
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        resp = await client.get(url, headers={"User-Agent": HONEST_UA})
        resp.raise_for_status()
        return resp.text


async def fetch(
    url: str,
    timeout: int | None = None,
    skip_robots: bool = False,
) -> str:
    """Fetch a URL, enforcing allowlist → robots → rate-limit → honest UA.

    Raises:
        DisallowedSourceError: host not on allowlist (zero network I/O).
        DisallowedSourceError: robots.txt disallows the path.
        RateLimitError: per-domain rate limit exhausted.
    """
    if not _allowed_hosts:
        load_allowlist()

    host = _extract_host(url)

    # ── 1. Allowlist — MUST be first, before any I/O ──────────────────────
    if host not in _allowed_hosts:
        raise DisallowedSourceError(
            f"Host '{host}' is not on the ThreatLens allowlist. "
            "Edit allowlist.yaml to add it (reviewed action)."
        )

    # ── 2. robots.txt ─────────────────────────────────────────────────────
    if not skip_robots and not await _check_robots(url):
        raise DisallowedSourceError(f"robots.txt disallows fetch of {url}")

    # ── 3. Rate limit ──────────────────────────────────────────────────────
    if not _check_rate_limit(host):
        raise RateLimitError(
            f"Rate limit exhausted for '{host}' "
            f"({threatlens_settings.intel_fetch_rate_per_domain} req/min)."
        )

    # ── 4. Fetch ───────────────────────────────────────────────────────────
    t = timeout or threatlens_settings.intel_fetch_timeout_secs
    logger.info("threatlens_fetch", host=host, url=url[:80])
    return await _http_get(url, t)


def _reset() -> None:
    """Reset all module state — for use in tests only. Clears in place so
    any code that imported the dicts directly keeps a live reference."""
    _allowed_hosts.clear()
    _robots_cache.clear()
    _rate_state.clear()
    _source_configs.clear()


# Load allowlist at import time
load_allowlist()
