"""Tests for ThreatLens smart Slack alerts."""
import time
import uuid

import pytest

from app.threatlens.models import ActorCluster, AdversaryProfile, IoCSet, TTP
from app.threatlens.slack_notifier import _should_alert, alert_if_critical


def _profile(
    severity: str = "high",
    confidence: str = "moderate",
    surface_zones: list[str] | None = None,
    ttps: list[str] | None = None,
) -> AdversaryProfile:
    return AdversaryProfile(
        id=str(uuid.uuid4()),
        cluster_id="c1",
        generated_at=time.time(),
        assessed_identity="Test Actor",
        assessed_intent="credential_harvesting",
        severity=severity,
        confidence=confidence,
        surface_zones=surface_zones or [],
        ttps=[TTP(attack_id=t, name=t, tactic="initial-access", evidence_ref="ev") for t in (ttps or [])],
        summary="Test summary.",
        model="test",
    )


def _cluster() -> ActorCluster:
    ts = time.time()
    return ActorCluster(
        id="c1",
        created_at=ts, updated_at=ts, first_seen=ts, last_seen=ts,
        member_scan_ids=["s1", "s2"],
        dominant_intent="credential_harvesting",
        iocs=IoCSet(domains=["evil.com"]),
        targets={}, signature={}, status="active",
    )


# ---------------------------------------------------------------------------

def test_should_alert_critical_surface_zone():
    """ground_station_ingress → always alert regardless of confidence."""
    p = _profile(surface_zones=["ground_station_ingress"], confidence="speculative")
    alert, reason = _should_alert(p)
    assert alert is True
    assert "critical_surface" in reason


def test_should_alert_ntn_5g_core():
    """ntn_5g_core → always alert."""
    p = _profile(surface_zones=["ntn_5g_core", "corporate_it"])
    alert, reason = _should_alert(p)
    assert alert is True
    assert "ntn_5g_core" in reason


def test_should_alert_confirmed_confidence():
    """confirmed confidence → alert even without critical zone."""
    p = _profile(confidence="confirmed", surface_zones=["corporate_it"])
    alert, reason = _should_alert(p)
    assert alert is True
    assert reason == "confirmed_threat_actor"


def test_should_alert_high_severity_gcp():
    """high severity + gcp_infra → alert."""
    p = _profile(severity="high", confidence="moderate", surface_zones=["gcp_infra"])
    alert, reason = _should_alert(p)
    assert alert is True
    assert "gcp_infra" in reason


def test_no_alert_corporate_it_only():
    """corporate_it alone → no alert (too common)."""
    p = _profile(severity="high", confidence="moderate", surface_zones=["corporate_it"])
    alert, reason = _should_alert(p)
    assert alert is False


def test_no_alert_low_severity_gcp():
    """low severity + gcp_infra → no alert."""
    p = _profile(severity="low", confidence="moderate", surface_zones=["gcp_infra"])
    alert, reason = _should_alert(p)
    assert alert is False


def test_no_alert_empty_zones_moderate():
    """No zones + moderate confidence → no alert."""
    p = _profile(severity="medium", confidence="moderate", surface_zones=[])
    alert, reason = _should_alert(p)
    assert alert is False


@pytest.mark.asyncio
async def test_alert_skips_when_no_webhook(mocker, monkeypatch):
    """No webhook URL → silent skip, no HTTP call."""
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)   # don't fall back to ambient env
    mock_post = mocker.patch("httpx.AsyncClient.post")
    result = await alert_if_critical(_cluster(), _profile(surface_zones=["ground_station_ingress"]), webhook_url="")
    assert result is False
    mock_post.assert_not_called()


@pytest.mark.asyncio
async def test_alert_sends_when_critical_surface(mocker):
    """Critical surface + webhook → POST to Slack."""
    import httpx
    mock_resp = mocker.MagicMock()
    mock_resp.raise_for_status = mocker.MagicMock()
    mocker.patch("httpx.AsyncClient.post", return_value=mock_resp)

    result = await alert_if_critical(
        _cluster(),
        _profile(surface_zones=["ground_station_ingress"]),
        webhook_url="https://hooks.slack.com/test",
    )
    assert result is True
