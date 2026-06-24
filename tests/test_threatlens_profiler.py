"""Profiler tests — JSON contract, confidence clamping, attribution hedging, fallback."""
import json
import time

import pytest

from app.threatlens.models import ActorCluster, CorroboratedClaim, IoCSet, TTP
from app.threatlens.profiler import (
    _clamp_confidence,
    _deterministic_fallback,
    _hedge_apt,
    synthesize,
)


def _cluster() -> ActorCluster:
    ts = time.time()
    return ActorCluster(
        id="profiler-test-001",
        created_at=ts, updated_at=ts, first_seen=ts, last_seen=ts,
        member_scan_ids=["s1", "s2", "s3"],
        dominant_intent="bec_fraud",
        iocs=IoCSet(domains=["company-exec-wire.net"]),
        targets={}, signature={}, status="active",
    )


def _claims() -> list[CorroboratedClaim]:
    return [
        CorroboratedClaim(
            claim="Actor sends wire-fraud emails impersonating executives",
            supporting_sources=["https://cisa.gov/bec-advisory"],
            independent_source_count=1,
            confidence="moderate",
        )
    ]


def _ttps() -> list[TTP]:
    return [TTP(attack_id="T1566", name="Phishing", tactic="Initial Access", evidence_ref="ev1")]


_VALID_PROFILE_JSON = json.dumps({
    "assessed_identity": "Suspected BEC Actor",
    "suspected_apt": None,
    "assessed_intent": "Financial theft via BEC wire fraud",
    "severity": "high",
    "confidence": "moderate",
    "surface_zones": ["corporate_it"],
    "segments": [],
    "evidence": [
        {"claim": "Actor impersonates executives", "source": "https://cisa.gov/test", "evidence_ref": "ev1"}
    ],
    "summary": "This cluster shows BEC wire-fraud behavior consistent with financially motivated actors."
})


# ---------------------------------------------------------------------------
# Structured output
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_profiler_returns_structured_profile(mocker):
    """Valid mocked JSON → parsed AdversaryProfile with all required fields."""
    mocker.patch("app.llm.client.LLMClient.complete", return_value=_VALID_PROFILE_JSON)

    profile = await synthesize(_cluster(), _claims(), _ttps(), "moderate")

    assert profile.assessed_identity == "Suspected BEC Actor"
    assert profile.assessed_intent != ""
    assert profile.confidence == "moderate"
    assert profile.cluster_id == "profiler-test-001"
    assert len(profile.evidence) > 0
    assert all(e.raw.get("evidence_ref") for e in profile.evidence)


# ---------------------------------------------------------------------------
# Confidence clamping
# ---------------------------------------------------------------------------

def test_clamp_confidence_cannot_raise():
    """_clamp_confidence never returns a tier higher than max_allowed."""
    assert _clamp_confidence("confirmed", "moderate") == "moderate"
    assert _clamp_confidence("high",      "low")      == "low"
    assert _clamp_confidence("moderate",  "moderate") == "moderate"
    assert _clamp_confidence("low",       "high")     == "low"


@pytest.mark.asyncio
async def test_profiler_cannot_raise_confidence(mocker):
    """Claude returning confidence=confirmed when max=moderate → clamped to moderate."""
    high_conf_json = json.dumps({
        **json.loads(_VALID_PROFILE_JSON),
        "confidence": "confirmed",
    })
    mocker.patch("app.llm.client.LLMClient.complete", return_value=high_conf_json)

    profile = await synthesize(_cluster(), _claims(), _ttps(), "moderate")
    assert profile.confidence == "moderate"


# ---------------------------------------------------------------------------
# Attribution hedging
# ---------------------------------------------------------------------------

def test_hedge_apt_adds_prefix():
    assert _hedge_apt("APT28").startswith("possible association:")
    assert _hedge_apt("possible association: APT28") == "possible association: APT28"
    assert _hedge_apt(None) is None
    assert _hedge_apt("") is None


@pytest.mark.asyncio
async def test_profiler_attribution_is_hedged(mocker):
    """Claude returning bare APT name → prefixed with 'possible association: '."""
    apt_json = json.dumps({
        **json.loads(_VALID_PROFILE_JSON),
        "suspected_apt": "APT28",
    })
    mocker.patch("app.llm.client.LLMClient.complete", return_value=apt_json)

    profile = await synthesize(_cluster(), _claims(), _ttps(), "moderate")
    assert profile.suspected_apt is not None
    assert profile.suspected_apt.startswith("possible association:")


# ---------------------------------------------------------------------------
# Parse failure → repair → fallback
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_profiler_parse_failure_triggers_repair_then_fallback(mocker):
    """Two invalid JSON responses → one repair attempt → deterministic fallback returned."""
    call_count = 0

    async def mock_complete(self, system, user, max_tokens=1024):
        nonlocal call_count
        call_count += 1
        return "this is not valid JSON {{{"

    mocker.patch("app.llm.client.LLMClient.complete", mock_complete)

    profile = await synthesize(_cluster(), _claims(), _ttps(), "moderate")

    assert call_count == 2
    assert profile is not None
    assert profile.confidence == "speculative"
    assert profile.model == "fallback"


@pytest.mark.asyncio
async def test_profiler_fallback_never_freetext_attributes(mocker):
    """Fallback profile → suspected_apt is None, confidence=speculative, summary is templated."""
    mocker.patch("app.llm.client.LLMClient.complete", return_value="bad json")

    profile = await synthesize(_cluster(), _claims(), _ttps(), "high")

    assert profile.suspected_apt is None
    assert profile.confidence == "speculative"
    assert "unattributed" in profile.summary.lower() or "automated" in profile.summary.lower()
    assert profile.model == "fallback"
