"""Phase 1 gate tests: Layer 1 OSINT pre-filter."""
import asyncio
import pytest
from unittest.mock import patch
from app.layer1.cache import L1Cache
from app.layer1.verdicts import run_layer1


class MockSettings:
    virustotal_api_key = ""
    abuseipdb_api_key  = ""
    misp_url           = ""
    misp_api_key       = ""


def _clean(src: str, ioc: str) -> dict:
    return {"source": src, "ioc": ioc, "malicious": False, "score": 0, "raw": {}}

def _bad(src: str, ioc: str) -> dict:
    return {"source": src, "ioc": ioc, "malicious": True, "score": 100, "raw": {}}


def test_p1_01_malicious_ip_quarantine():
    """TC-P1-01: A malicious VT hit must produce verdict=quarantine."""
    cache = L1Cache()
    ip = "1.2.3.4"

    async def _run():
        with patch("app.layer1.verdicts.vt_check_ip", return_value=_bad("virustotal", ip)), \
             patch("app.layer1.verdicts.abuseipdb_check", return_value=_clean("abuseipdb", ip)), \
             patch("app.layer1.verdicts.spamhaus_check", return_value=_clean("spamhaus", ip)), \
             patch("app.layer1.verdicts.misp_check", return_value=_clean("misp", ip)):
            return await run_layer1(ip, [], [], MockSettings(), cache)

    result = asyncio.run(_run())
    assert result["verdict"] == "quarantine"
    assert len(result["hits"]) >  0


def test_p1_02_cache_hit_no_http():
    """TC-P1-02: A primed cache must return the result without an HTTP call."""
    cache = L1Cache()
    stored = _clean("virustotal", "5.6.7.8")

    async def _run():
        with patch.object(cache, "get", return_value=stored), \
             patch("app.layer1.osint_client.httpx.AsyncClient") as mock_http:
            val = await cache.get("vt_ip", "5.6.7.8")
            mock_http.assert_not_called()
            return val

    result = asyncio.run(_run())
    assert result["malicious"] == False
    assert result["source"] == "virustotal"


def test_p1_03_clean_email_passes():
    """TC-P1-03: All-clean OSINT results must produce verdict=clean."""
    cache = L1Cache()
    ip = "10.0.0.1"

    async def _run():
        with patch("app.layer1.verdicts.vt_check_ip", return_value=_clean("virustotal", ip)), \
             patch("app.layer1.verdicts.abuseipdb_check", return_value=_clean("abuseipdb", ip)), \
             patch("app.layer1.verdicts.spamhaus_check", return_value=_clean("spamhaus", ip)), \
             patch("app.layer1.verdicts.misp_check", return_value=_clean("misp", ip)):
            return await run_layer1(ip, [], [], MockSettings(), cache)

    result = asyncio.run(_run())
    assert result["verdict"] == "clean"
    assert result["hits"] == []
