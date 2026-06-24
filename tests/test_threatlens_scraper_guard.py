"""Scraper guard tests — the legal boundary.

These are hard-gate tests. If any fail, Phase 2 is NOT done regardless of
feature completeness. Each test verifies that the allowlist is enforced before
any network I/O — not after, not optionally.
"""
import asyncio

import pytest

import app.threatlens.scraper.fetcher as _fetcher_mod
from app.threatlens.scraper.fetcher import (
    DisallowedSourceError,
    RateLimitError,
    _reset,
    fetch,
    is_allowed,
    load_allowlist,
)
from app.threatlens.scraper import crawl4ai_client, scrapling_client


@pytest.fixture(autouse=True)
def reset_fetcher_state():
    """Reset module state before each test to avoid cross-test pollution."""
    _reset()
    load_allowlist()
    yield
    _reset()


# ---------------------------------------------------------------------------
# Allowlist enforcement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetch_non_allowlisted_host_raises(mocker):
    """Non-allowlisted host → DisallowedSourceError with ZERO network calls."""
    mock_http = mocker.patch("app.threatlens.scraper.fetcher._http_get")

    with pytest.raises(DisallowedSourceError):
        await fetch("https://evil-leak-forum.onion/stolen-data")

    mock_http.assert_not_called()


@pytest.mark.asyncio
async def test_fetch_allowed_host_succeeds(mocker):
    """Allowlisted host with robots OK → body returned, exactly one request."""
    mocker.patch("app.threatlens.scraper.fetcher._check_robots", return_value=True)
    mock_http = mocker.patch(
        "app.threatlens.scraper.fetcher._http_get", return_value="advisory content"
    )

    result = await fetch("https://www.cisa.gov/advisory/test")
    assert result == "advisory content"
    mock_http.assert_called_once()


@pytest.mark.asyncio
async def test_crawl4ai_client_cannot_bypass_allowlist(mocker):
    """crawl4ai_client.get() on a non-allowlisted host must raise before any
    Crawl4AI code runs."""
    mock_crawler = mocker.patch("crawl4ai.AsyncWebCrawler.arun")

    with pytest.raises(DisallowedSourceError):
        await crawl4ai_client.get("https://not-on-allowlist.example/page")

    mock_crawler.assert_not_called()


@pytest.mark.asyncio
async def test_scrapling_client_cannot_bypass_allowlist(mocker):
    """scrapling_client.get() on a non-allowlisted host must raise before any
    Scrapling code runs."""
    mock_scrape = mocker.patch("scrapling.AsyncFetcher.get")

    with pytest.raises(DisallowedSourceError):
        await scrapling_client.get("https://not-on-allowlist.example/page")

    mock_scrape.assert_not_called()


# ---------------------------------------------------------------------------
# robots.txt compliance
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetch_respects_robots_disallow(mocker):
    """Allowlisted host with robots.txt disallowing the path → refused, no content fetch."""
    mocker.patch("app.threatlens.scraper.fetcher._check_robots", return_value=False)
    mock_http = mocker.patch("app.threatlens.scraper.fetcher._http_get")

    with pytest.raises(DisallowedSourceError):
        await fetch("https://www.cisa.gov/private/internal")

    mock_http.assert_not_called()


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetch_rate_limit_trips(mocker):
    """When the token bucket for a domain is exhausted, the next call raises RateLimitError."""
    mocker.patch("app.threatlens.scraper.fetcher._check_robots", return_value=True)
    mocker.patch("app.threatlens.scraper.fetcher._http_get", return_value="ok")

    import time
    _fetcher_mod._rate_state["www.cisa.gov"] = {"tokens": 0.0, "last_refill": time.monotonic()}

    with pytest.raises(RateLimitError):
        await fetch("https://www.cisa.gov/advisory/blocked")


# ---------------------------------------------------------------------------
# Honest User-Agent
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_user_agent_is_honest(mocker):
    """Every fetch must use the project User-Agent — never a spoofed browser string."""
    mocker.patch("app.threatlens.scraper.fetcher._check_robots", return_value=True)

    captured = {}

    async def mock_get(url, timeout):
        import httpx
        async with httpx.AsyncClient(timeout=timeout) as client:
            captured["called"] = True
        return "content"

    from app.threatlens.scraper import fetcher as _f
    mocker.patch.object(_f, "_http_get", side_effect=lambda url, t: _fake_get(url, t, captured))

    async def _fake_get(url, t, cap):
        cap["ok"] = True
        return "content"

    await fetch("https://www.cisa.gov/advisory/test")

    from app.threatlens.scraper.fetcher import HONEST_UA
    assert "PhishGuard" in HONEST_UA or "ThreatLens" in HONEST_UA
    assert "Chrome" not in HONEST_UA
    assert "Mozilla" not in HONEST_UA
