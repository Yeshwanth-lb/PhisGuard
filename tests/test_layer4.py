"""Phase 4 gate tests: SOAR + Threat Intel layer."""
import pytest
import asyncio


class FakeSettings:
    elasticsearch_url = None
    slack_webhook_url = None
    misp_url = None
    misp_api_key = None
    opencti_url = None
    opencti_token = None


PHISH_DOC = {
    "verdict": "phishing",
    "confidence": 0.95,
    "blocked_at": "layer2",
    "parsed": {
        "from_header": "attacker@evil.com",
        "subject": "Urgent action required",
        "urls": ["http://evil.com/steal"],
    },
}


@pytest.mark.asyncio
async def test_es_exporter_no_url():
    from app.layer4_soar.es_exporter import export_to_es
    result = await export_to_es(PHISH_DOC, FakeSettings())
    assert result is False


@pytest.mark.asyncio
async def test_slack_no_webhook():
    from app.layer4_soar.slack_notifier import notify_slack
    result = await notify_slack(PHISH_DOC, FakeSettings())
    assert result is False


@pytest.mark.asyncio
async def test_misp_no_config():
    from app.layer4_soar.misp_exporter import export_to_misp
    result = await export_to_misp(PHISH_DOC, FakeSettings())
    assert result is False


@pytest.mark.asyncio
async def test_opencti_no_config():
    from app.layer4_soar.opencti_exporter import export_to_opencti
    result = await export_to_opencti(PHISH_DOC, FakeSettings())
    assert result is False


@pytest.mark.asyncio
async def test_soar_orchestrator_graceful():
    from app.layer4_soar.soar_orchestrator import run_soar
    outcome = await run_soar(PHISH_DOC, FakeSettings())
    assert isinstance(outcome, dict)
    assert set(outcome.keys()) == {"es", "slack", "misp", "opencti"}
    assert all(v is False for v in outcome.values())


@pytest.mark.asyncio
async def test_slack_skips_clean_verdict():
    from app.layer4_soar.slack_notifier import notify_slack
    clean = {**PHISH_DOC, "verdict": "clean"}
    result = await notify_slack(clean, FakeSettings())
    assert result is False
