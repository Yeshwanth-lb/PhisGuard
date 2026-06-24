"""Fusion engine tests — the confidence-invariant hard gates.

These are security-critical tests. The confidence math must be deterministic
Python — not delegated to an LLM. If these fail, Phase 2 is not done.
"""
import time

import pytest

from app.threatlens.fusion_engine import run, _root_domain
from app.threatlens.models import ActorCluster, CorroboratedClaim, Finding, IoCSet


def _cluster() -> ActorCluster:
    ts = time.time()
    return ActorCluster(
        id="fusion-test-001",
        created_at=ts, updated_at=ts, first_seen=ts, last_seen=ts,
        member_scan_ids=["s1"],
        dominant_intent="credential_harvesting",
        iocs=IoCSet(domains=["paypa1-verify.com"]),
        targets={}, signature={}, status="active",
    )


def _finding(
    agent: str = "osint",
    claim: str = "actor uses phishing",
    source_url: str | None = "https://cisa.gov/test",
    confidence: str = "moderate",
    attack_id: str | None = None,
) -> Finding:
    return Finding(
        agent=agent,
        claim=claim,
        source_url=source_url,
        source_title=source_url,
        confidence=confidence,
        raw={"attack_id": attack_id} if attack_id else {},
    )


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_fusion_dedupes_identical_iocs_across_agents():
    """Two agents reporting the same claim → one CorroboratedClaim,
    independent_source_count reflects distinct root domains."""
    f1 = _finding(agent="osint",   source_url="https://cisa.gov/advisory/1")
    f2 = _finding(agent="osint2",  source_url="https://unit42.paloaltonetworks.com/report")

    claims, ttps, conf = run(_cluster(), [f1, f2])

    assert len(claims) == 1
    assert claims[0].independent_source_count == 2
    assert conf == "high"


# ---------------------------------------------------------------------------
# Confidence rules — the hard gates
# ---------------------------------------------------------------------------

def test_fusion_confidence_confirmed_only_on_feed_hit():
    """confirmed tier is ONLY reachable when agent='misp'. Even 5 OSINT sources
    agreeing cannot produce confirmed."""
    findings = [
        _finding(agent="osint",   source_url="https://cisa.gov/1"),
        _finding(agent="osint2",  source_url="https://unit42.paloaltonetworks.com/1"),
        _finding(agent="osint3",  source_url="https://securelist.com/1"),
    ]
    claims, _, conf = run(_cluster(), findings)
    assert conf != "confirmed"
    assert all(c.confidence != "confirmed" for c in claims)


def test_fusion_misp_hit_yields_confirmed():
    """A finding from agent='misp' → confidence=confirmed."""
    findings = [_finding(agent="misp", source_url=None)]
    claims, _, conf = run(_cluster(), findings)
    assert conf == "confirmed"
    assert any(c.confidence == "confirmed" for c in claims)


def test_fusion_two_independent_sources_yield_high():
    """Two findings from different root domains → high confidence."""
    f1 = _finding(agent="osint",  source_url="https://cisa.gov/advisory/bec")
    f2 = _finding(agent="attack", source_url="https://unit42.paloaltonetworks.com/bec")

    claims, _, conf = run(_cluster(), [f1, f2])
    assert conf == "high"


def test_fusion_single_source_yields_moderate():
    """One external source → moderate."""
    f = _finding(source_url="https://cisa.gov/advisory/test")
    _, _, conf = run(_cluster(), [f])
    assert conf == "moderate"


def test_fusion_two_findings_same_domain_not_independent():
    """Two pages from same root domain count as ONE independent source → moderate."""
    f1 = _finding(agent="osint",  source_url="https://reports.examplevendor.com/1")
    f2 = _finding(agent="osint2", source_url="https://blog.examplevendor.com/2")

    claims, _, conf = run(_cluster(), [f1, f2])
    assert claims[0].independent_source_count == 1
    assert conf == "moderate"


def test_fusion_all_sources_down_caps_confidence_speculative():
    """No external sources → internal-only evidence → confidence <= low."""
    f = _finding(source_url=None)  # no URL = internal only
    _, _, conf = run(_cluster(), [f])
    assert conf in ("speculative", "low")


def test_fusion_idempotent_on_unchanged_input():
    """Running fusion twice on identical inputs produces the same
    confidence — does not create duplicate claims."""
    findings = [_finding(source_url="https://cisa.gov/test")]
    claims1, ttps1, conf1 = run(_cluster(), findings)
    claims2, ttps2, conf2 = run(_cluster(), findings)

    assert conf1 == conf2
    assert len(claims1) == len(claims2)
