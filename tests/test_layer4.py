"""Phase 4 gate tests: SOAR + Threat Intel layer."""

import pytest


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
    # MISP exporter now returns a dict; with no credentials it should be not_applicable
    assert isinstance(result, dict)
    assert result["exported"] is False
    assert result["export_status"] == "not_applicable"


@pytest.mark.asyncio
async def test_misp_no_config_clean_verdict():
    from app.layer4_soar.misp_exporter import export_to_misp
    clean = {**PHISH_DOC, "verdict": "clean"}
    result = await export_to_misp(clean, FakeSettings())
    assert result["export_status"] == "not_applicable"


@pytest.mark.asyncio
async def test_misp_event_contains_no_pii():
    """MISP event attributes must be only IoC types — no subject, body, or recipient."""
    from app.layer4_soar.misp_exporter import _build_misp_event
    doc = {
        "verdict": "phishing",
        "confidence": 0.95,
        "blocked_at": "layer2",
        "parsed": {
            "sender_ip": "1.2.3.4",
            "sender_domain": "evil.com",
            "from_header": "attacker@evil.com",
            "subject": "URGENT: reset your password",
            "body_text": "Click here now: http://evil.com/steal",
            "urls": ["http://evil.com/steal"],
            "attachment_hashes": ["abcd1234"],
        },
    }
    event = _build_misp_event(doc, FakeSettings())
    attrs = event["Event"]["Attribute"]
    allowed_types = {"ip-src", "url", "sha256", "domain", "text"}
    for attr in attrs:
        assert attr["type"] in allowed_types, f"Unexpected attribute type: {attr['type']}"
    # Verify no PII fields
    all_values = " ".join(str(a.get("value", "")) for a in attrs)
    assert "URGENT: reset" not in all_values, "Subject leaked into MISP event"
    assert "Click here now" not in all_values, "Body content leaked into MISP event"
    assert "attacker@evil.com" not in all_values, "Email address leaked into MISP event"


@pytest.mark.asyncio
async def test_misp_event_ioc_types():
    """MISP event must include sender IP, domain, URLs, and hashes when present."""
    from app.layer4_soar.misp_exporter import _build_misp_event
    doc = {
        "verdict": "phishing",
        "confidence": 0.92,
        "blocked_at": "layer1",
        "parsed": {
            "sender_ip": "10.0.0.1",
            "sender_domain": "badactor.xyz",
            "from_header": "x@badactor.xyz",
            "subject": "...",
            "urls": ["http://badactor.xyz/payload"],
            "attachment_hashes": ["deadbeef" * 8],
        },
    }
    event = _build_misp_event(doc, FakeSettings())
    attrs = event["Event"]["Attribute"]
    types_present = {a["type"] for a in attrs}
    assert "ip-src" in types_present
    assert "domain" in types_present
    assert "url" in types_present
    assert "sha256" in types_present


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
    expected = {"es", "slack", "misp", "opencti", "jira", "email", "denylist"}
    assert expected.issubset(set(outcome.keys()))
    # Non-dict results for unconfigured integrations
    for k in ("es", "slack", "opencti", "jira", "email"):
        assert outcome[k] is False, f"expected {k} False with no config"
    # MISP returns a rich dict even when unconfigured
    misp_result = outcome["misp"]
    assert isinstance(misp_result, dict)
    assert misp_result["export_status"] == "not_applicable"


@pytest.mark.asyncio
async def test_slack_skips_clean_verdict():
    from app.layer4_soar.slack_notifier import notify_slack
    clean = {**PHISH_DOC, "verdict": "clean"}
    result = await notify_slack(clean, FakeSettings())
    assert result is False
