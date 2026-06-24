"""Org assessor tests — synthesis, Skylo context, confidence discipline, fallback, export."""
import json
import time
import uuid

import pytest

from app.threatlens.models import AdversaryProfile, OrgThreatAssessment
from app.threatlens.org_assessor import assess, build_brief_html, _SYSTEM_PROMPT
from app.threatlens.store import init_db, upsert_profile


def _profile(cluster_id: str, confidence: str = "moderate", segments: list[str] | None = None) -> AdversaryProfile:
    return AdversaryProfile(
        id=str(uuid.uuid4()),
        cluster_id=cluster_id,
        generated_at=time.time(),
        assessed_identity="Test Actor",
        assessed_intent="credential_harvesting",
        severity="high",
        confidence=confidence,
        segments=segments or ["maritime"],
        summary="test summary",
        model="test",
    )


_VALID_ASSESSMENT = {
    "adversary_landscape": "NTN operators face espionage-motivated threat actors.",
    "surface_pressure": {"ntn_5g_core": 2, "ground_station_ingress": 1},
    "sector_pressure": {"maritime": 3},
    "strategic_intent": "espionage",
    "top_campaigns": [{"name": "PayPal Wave", "severity": "high", "description": "Credential harvesting"}],
    "confidence": "low",
    "summary": "Skylo faces espionage-focused actors targeting NTN infrastructure.",
}


@pytest.mark.asyncio
async def test_org_assessor_synthesizes_all_active_profiles(mocker, tmp_path):
    """3 profiles → assessment references all 3 source_profile_ids."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    ids = []
    for i in range(3):
        p = _profile(f"c{i}")
        upsert_profile(p, db_path=db_path)
        ids.append(p.id)

    mocker.patch("app.llm.client.LLMClient.complete", return_value=json.dumps(_VALID_ASSESSMENT))

    assessment = await assess(db_path=db_path)

    assert len(assessment.source_profile_ids) == 3
    assert set(assessment.source_profile_ids) == set(ids)


@pytest.mark.asyncio
async def test_org_assessor_skylo_contextualized(mocker, tmp_path):
    """System prompt must mention NTN-operator context (ntn, ground station, 5g, skylo)."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    system_prompt_lower = _SYSTEM_PROMPT.lower()
    assert any(kw in system_prompt_lower for kw in ["ntn", "ground station", "5g", "skylo"])


@pytest.mark.asyncio
async def test_org_assessor_confidence_cap(mocker, tmp_path):
    """All profiles moderate → assessment cannot be higher than moderate."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)
    upsert_profile(_profile("c1", confidence="moderate"), db_path=db_path)

    # LLM tries to return confirmed
    high_assessment = {**_VALID_ASSESSMENT, "confidence": "confirmed"}
    mocker.patch("app.llm.client.LLMClient.complete", return_value=json.dumps(high_assessment))

    assessment = await assess(db_path=db_path)

    assert assessment.confidence not in ("confirmed", "high")
    assert assessment.confidence in ("speculative", "low", "moderate")


@pytest.mark.asyncio
async def test_org_assessor_llm_fallback_no_freetext_attribution(mocker, tmp_path):
    """LLM returns bad JSON twice → deterministic fallback, no free-text attribution."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    mocker.patch("app.llm.client.LLMClient.complete", return_value="not valid json {{")

    assessment = await assess(db_path=db_path)

    assert assessment.confidence == "speculative"
    assert assessment.model == "fallback"
    summary_lower = assessment.summary.lower()
    assert "unattributed" in summary_lower or "automated" in summary_lower or "speculative" in summary_lower


def test_org_assessor_export_produces_leadership_brief():
    """build_brief_html → HTML contains summary, surface pressure, sector pressure, no email bodies."""
    assessment = OrgThreatAssessment(
        id="a1",
        generated_at=time.time(),
        adversary_landscape="NTN operators face espionage threats.",
        surface_pressure={"ntn_5g_core": 2, "gcp_infra": 1},
        sector_pressure={"maritime": 3},
        strategic_intent="espionage",
        confidence="low",
        summary="Leadership brief: NTN operators are under pressure.",
    )

    html = build_brief_html(assessment)

    assert "Leadership brief" in html or "leadership brief" in html.lower()
    assert "ntn_5g_core" in html
    assert "maritime" in html
    assert "body_text" not in html
    assert "body_html" not in html
    assert "password" not in html.lower()
