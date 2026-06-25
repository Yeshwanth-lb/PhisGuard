"""Tests for the profile feedback loop — analyst corrections fed into next cycle."""
import time
import uuid

import pytest

from app.threatlens.models import ActorCluster, AdversaryProfile, CorroboratedClaim, IoCSet, TTP
from app.threatlens.profiler import _downgrade_for_feedback, synthesize
from app.threatlens.store import (
    get_cluster_feedback,
    init_db,
    save_profile_feedback,
    upsert_cluster,
    upsert_profile,
)


def _cluster(cid="c1") -> ActorCluster:
    ts = time.time()
    return ActorCluster(
        id=cid, created_at=ts, updated_at=ts, first_seen=ts, last_seen=ts,
        member_scan_ids=["s1", "s2"], dominant_intent="bec_fraud",
        iocs=IoCSet(domains=["evil.com"]), targets={}, signature={}, status="active",
    )


def _profile(pid, cid="c1", confidence="high") -> AdversaryProfile:
    return AdversaryProfile(
        id=pid, cluster_id=cid, generated_at=time.time(),
        assessed_identity="Test Actor", assessed_intent="bec_fraud",
        severity="high", confidence=confidence, summary="test", model="test",
    )


# ── Storage layer ─────────────────────────────────────────────────────────────

def test_feedback_resolves_cluster_id_from_profile(tmp_path):
    """save_profile_feedback auto-resolves cluster_id from the profile."""
    db = str(tmp_path / "t.db"); init_db(db_path=db)
    upsert_cluster(_cluster("c1"), db_path=db)
    upsert_profile(_profile("p1", "c1"), db_path=db)

    save_profile_feedback(profile_id="p1", rating="incorrect", notes="wrong intent", db_path=db)

    fb = get_cluster_feedback("c1", db_path=db)
    assert fb is not None
    assert fb["rating"] == "incorrect"
    assert fb["notes"] == "wrong intent"


def test_feedback_latest_wins(tmp_path):
    """When multiple feedback rows exist for a cluster, the latest is returned."""
    db = str(tmp_path / "t.db"); init_db(db_path=db)
    upsert_cluster(_cluster("c1"), db_path=db)
    upsert_profile(_profile("p1", "c1"), db_path=db)

    save_profile_feedback(profile_id="p1", rating="actionable", notes="first", db_path=db)
    time.sleep(0.01)
    save_profile_feedback(profile_id="p1", rating="incorrect", notes="second", db_path=db)

    fb = get_cluster_feedback("c1", db_path=db)
    assert fb["rating"] == "incorrect"
    assert fb["notes"] == "second"


def test_no_feedback_returns_none(tmp_path):
    db = str(tmp_path / "t.db"); init_db(db_path=db)
    assert get_cluster_feedback("nonexistent", db_path=db) is None


# ── Confidence downgrade logic ──────────────────────────────────────────────────

def test_downgrade_lowers_confidence_on_incorrect():
    """rating=incorrect drops the confidence ceiling one tier."""
    assert _downgrade_for_feedback("confirmed", {"rating": "incorrect"}) == "high"
    assert _downgrade_for_feedback("high",      {"rating": "incorrect"}) == "moderate"
    assert _downgrade_for_feedback("moderate",  {"rating": "incorrect"}) == "low"
    assert _downgrade_for_feedback("low",       {"rating": "incorrect"}) == "speculative"
    assert _downgrade_for_feedback("speculative", {"rating": "incorrect"}) == "speculative"


def test_downgrade_noop_on_other_ratings():
    """Non-incorrect feedback does not change confidence."""
    assert _downgrade_for_feedback("high", {"rating": "actionable"}) == "high"
    assert _downgrade_for_feedback("high", {"rating": "not_actionable"}) == "high"
    assert _downgrade_for_feedback("high", None) == "high"


# ── Synthesize applies feedback ─────────────────────────────────────────────────

_VALID_JSON = (
    '{"assessed_identity":"Test","suspected_apt":null,"assessed_intent":"bec",'
    '"severity":"high","confidence":"confirmed","surface_zones":[],"segments":[],'
    '"evidence":[{"claim":"x","source":"y","evidence_ref":"e1"}],"summary":"s"}'
)


@pytest.mark.asyncio
async def test_synthesize_caps_confidence_when_incorrect(mocker):
    """Feedback=incorrect with max=confirmed → profile confidence capped at high."""
    mocker.patch("app.llm.client.LLMClient.complete", return_value=_VALID_JSON)
    c = _cluster()
    claims = [CorroboratedClaim(claim="x", supporting_sources=[], independent_source_count=1, confidence="confirmed")]
    profile = await synthesize(
        c, claims, [], "confirmed",
        feedback={"rating": "incorrect", "notes": "this is not BEC"},
    )
    # confirmed → downgraded to high, and Claude's 'confirmed' is then clamped to high
    assert profile.confidence == "high"


@pytest.mark.asyncio
async def test_synthesize_feedback_note_in_prompt(mocker):
    """The analyst note is injected into the prompt sent to Claude."""
    captured = {}
    async def fake_complete(self, system, user, max_tokens=1024):
        captured["user"] = user
        return _VALID_JSON
    mocker.patch("app.llm.client.LLMClient.complete", fake_complete)

    c = _cluster()
    await synthesize(
        c, [], [], "moderate",
        feedback={"rating": "incorrect", "notes": "domain is actually legitimate vendor"},
    )
    assert "ANALYST FEEDBACK" in captured["user"]
    assert "legitimate vendor" in captured["user"]


@pytest.mark.asyncio
async def test_synthesize_no_feedback_unchanged(mocker):
    """No feedback → no feedback section, confidence not downgraded."""
    captured = {}
    async def fake_complete(self, system, user, max_tokens=1024):
        captured["user"] = user
        return _VALID_JSON
    mocker.patch("app.llm.client.LLMClient.complete", fake_complete)

    c = _cluster()
    profile = await synthesize(c, [], [], "confirmed", feedback=None)
    assert "ANALYST FEEDBACK" not in captured["user"]
    assert profile.confidence == "confirmed"
