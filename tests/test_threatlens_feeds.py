"""feeds_client tests — typed parsing of all free JSON feeds. All mocked."""
import json
import time

import httpx
import pytest

from app.threatlens.scraper import feeds_client
from app.threatlens.scraper.fetcher import _reset, load_allowlist


@pytest.fixture(autouse=True)
def setup_allowlist():
    _reset()
    load_allowlist()
    yield
    _reset()


def _mock_response(status: int, body) -> httpx.Response:
    content = json.dumps(body).encode()
    return httpx.Response(status, content=content, headers={"content-type": "application/json"})


# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_feeds_ransomware_live_parses_victim_listing(mocker):
    """Mocked ransomware.live response → typed VictimListing with group/date/sector."""
    mock_data = [
        {"group_name": "BlackCat", "post_title": "AcmeMaritime Ltd", "discovered": "2026-01-15",
         "activity": "maritime", "country": "US"},
        {"group_name": "LockBit", "post_title": "SomeFarm Co", "discovered": "2026-01-10",
         "activity": "agriculture", "country": "IN"},
    ]
    mocker.patch("httpx.AsyncClient.get", return_value=_mock_response(200, mock_data))

    victims = await feeds_client.ransomwarelive_victims(["maritime", "agriculture"])

    assert len(victims) == 2
    assert victims[0].group == "BlackCat"
    assert victims[0].sector == "maritime"
    assert victims[0].date == "2026-01-15"
    assert victims[0].source == "ransomware.live"


@pytest.mark.asyncio
async def test_feeds_ransomlook_no_hit_returns_empty(mocker):
    """No matching sector/domain → []."""
    mocker.patch("httpx.AsyncClient.get", return_value=_mock_response(200, [
        {"group_name": "SomeGroup", "post_title": "Unrelated Corp", "sector": "gaming"}
    ]))

    victims = await feeds_client.ransomlook_victims(["maritime", "mining"])
    assert victims == []


@pytest.mark.asyncio
async def test_feeds_abusech_urlhaus_lookup(mocker):
    """Mocked URLhaus POST response → URLhausEntry with url_count."""
    mock_data = {
        "query_status": "is_host",
        "urlhaus_reference": "https://urlhaus.abuse.ch/host/evil.com/",
        "urls": [
            {"url": "http://evil.com/malware.exe", "url_status": "online"},
            {"url": "http://evil.com/payload.zip", "url_status": "offline"},
        ]
    }
    mocker.patch("httpx.AsyncClient.post", return_value=_mock_response(200, mock_data))

    entry = await feeds_client.urlhaus_host_lookup("evil.com")

    assert entry is not None
    assert entry.urls_on_this_host == 2
    assert len(entry.urls) == 2


@pytest.mark.asyncio
async def test_feeds_otx_pulse_parses_attack_references(mocker):
    """Mocked OTX domain response → OTXPulse with ATT&CK references extracted."""
    # Patch the key so the api_key check passes
    mocker.patch.object(
        feeds_client.threatlens_settings, "otx_api_key", "testkey", create=True
    )
    mock_data = {
        "pulse_info": {
            "pulses": [
                {
                    "id": "pulse123",
                    "name": "Credential Harvesting Campaign",
                    "description": "Phishing campaign targeting finance",
                    "attack_ids": [{"id": "T1566"}, {"id": "T1598"}],
                    "references": ["https://example.com/report"],
                    "adversary": "FIN7",
                    "tlp": "white",
                }
            ]
        }
    }
    mocker.patch("httpx.AsyncClient.get", return_value=_mock_response(200, mock_data))

    pulses = await feeds_client.otx_domain_lookup("evil-domain.com")

    assert len(pulses) == 1
    assert "T1566" in pulses[0].attack_ids
    assert "T1598" in pulses[0].attack_ids
    assert pulses[0].adversary == "FIN7"


@pytest.mark.asyncio
async def test_feeds_nvd_cve_filters_by_keyword(mocker):
    """Mocked NVD response — only NTN/5G/telecom CVEs returned, generic ones dropped."""
    mock_nvd = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-1111",
                    "descriptions": [{"lang": "en", "value": "5G core AMF vulnerability allows RCE"}],
                    "published": "2026-01-01",
                    "metrics": {},
                }
            },
            {
                "cve": {
                    "id": "CVE-2026-9999",
                    "descriptions": [{"lang": "en", "value": "WordPress plugin XSS vulnerability"}],
                    "published": "2026-01-02",
                    "metrics": {},
                }
            },
        ]
    }
    mocker.patch("httpx.AsyncClient.get", return_value=_mock_response(200, mock_nvd))

    cves = await feeds_client.nvd_cve_search(["5g core"])

    cve_ids = [c.cve_id for c in cves]
    assert "CVE-2026-1111" in cve_ids
    assert "CVE-2026-9999" not in cve_ids
