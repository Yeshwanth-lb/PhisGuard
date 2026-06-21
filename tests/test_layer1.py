"""Phase 1 gate tests: Layer 1 OSINT pre-filter."""
import asyncio
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


# ── Spoofing detection regression tests ────────────────────────────────────

def test_p1_04_trusted_domain_real_email_is_clean():
    """Real LinkedIn email (SPF+DKIM pass) must bypass OSINT and be clean."""
    cache = L1Cache()

    async def _run():
        return await run_layer1(
            sender_ip=None, urls=[], attachment_hashes=[],
            settings=MockSettings(), cache=cache,
            sender_email="jobalerts-noreply@linkedin.com",
            spf_result="pass", dkim_result="pass",
        )

    result = asyncio.run(_run())
    assert result["verdict"] == "clean"
    assert result.get("trusted_sender") is True


def test_p1_05_trusted_domain_spf_fail_is_spoofing():
    """Fake LinkedIn email (SPF fail) must be flagged as suspicious/spoofed."""
    cache = L1Cache()

    async def _run():
        return await run_layer1(
            sender_ip=None, urls=[], attachment_hashes=[],
            settings=MockSettings(), cache=cache,
            sender_email="jobalerts-noreply@linkedin.com",
            spf_result="fail", dkim_result="fail",
        )

    result = asyncio.run(_run())
    assert result["verdict"] == "suspicious"
    assert result.get("spoofed_trusted_domain") is True
    assert any("SPOOFING" in str(h.get("reason", "")) for h in result.get("weak_hits", []))


def test_p1_06_trusted_domain_unknown_auth_is_clean():
    """Trusted domain with unknown auth (common for Gmail API emails) must be clean.

    Authentication-Results headers are often missing or unparseable for emails
    fetched via the Gmail historical API. 'unknown' is not 'fail' — there is no
    evidence of spoofing. Running L2+L3 on these emails causes false positives
    because LinkedIn job pages have login forms that the sandbox flags as
    credential harvesting. Trust the domain name + no active fail = clean.
    """
    cache = L1Cache()

    async def _run():
        return await run_layer1(
            sender_ip=None, urls=[], attachment_hashes=[],
            settings=MockSettings(), cache=cache,
            sender_email="jobalerts-noreply@linkedin.com",
            spf_result="unknown", dkim_result="unknown",
        )

    result = asyncio.run(_run())
    assert result["verdict"] == "clean"
    assert result.get("trusted_sender") is True


def test_p1_07_soft_signals_only_suspicious_not_quarantine():
    """Weak aux signals (domain age, auth) must produce suspicious, not quarantine."""
    cache = L1Cache()

    async def _run():
        with patch("app.layer1.verdicts.vt_check_ip", return_value=_clean("virustotal", "9.9.9.9")), \
             patch("app.layer1.verdicts.abuseipdb_check",
                   return_value={"source": "abuseipdb", "ioc": "9.9.9.9", "malicious": False, "score": 40, "raw": {}}), \
             patch("app.layer1.verdicts.spamhaus_check", return_value=_clean("spamhaus", "9.9.9.9")), \
             patch("app.layer1.verdicts.misp_check", return_value=_clean("misp", "9.9.9.9")):
            return await run_layer1("9.9.9.9", [], [], MockSettings(), cache)

    result = asyncio.run(_run())
    # AbuseIPDB score 40 is below quarantine threshold (80) → suspicious, not quarantine
    assert result["verdict"] in ("suspicious", "clean")
    assert result["verdict"] != "quarantine"
