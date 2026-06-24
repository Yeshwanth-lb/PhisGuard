"""TTP Mapper tests — ATT&CK dedup, surface zone keyword mapping, evidence refs."""
import time

import pytest

from app.threatlens.models import ActorCluster, Finding, IoCSet
from app.threatlens.ttp_mapper import map_cluster, _map_surface_zones, _extract_ttps_from_findings
from app.threatlens.store import init_db, get_ttp_observations


def _cluster(intent: str = "credential_harvesting", domains: list[str] | None = None) -> ActorCluster:
    ts = time.time()
    return ActorCluster(
        id="ttp-test-001",
        created_at=ts, updated_at=ts, first_seen=ts, last_seen=ts,
        member_scan_ids=["s1"],
        dominant_intent=intent,
        iocs=IoCSet(domains=domains or ["evil.com"]),
        targets={}, signature={}, status="active",
    )


def _finding(agent: str, claim: str, attack_id: str | None = None, source_url: str | None = None) -> Finding:
    return Finding(
        agent=agent,
        claim=claim,
        source_url=source_url,
        source_title=source_url or agent,
        confidence="moderate",
        raw={"attack_id": attack_id, "name": f"Technique {attack_id}", "tactic": "Initial Access"} if attack_id else {},
    )


# ---------------------------------------------------------------------------

def test_ttp_dedupes_across_agent_and_misp(tmp_path):
    """T1566 from attack mapper + T1566 from MISP → one TTP entry, both refs retained."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    findings = [
        _finding("attack", "Phishing observed", attack_id="T1566"),
        _finding("misp", "MISP hit: T1566", attack_id="T1566"),
        _finding("attack", "Financial Theft", attack_id="T1657"),
    ]

    ttps, zones, segments = map_cluster(_cluster(), findings, db_path=db_path)

    attack_ids = [t.attack_id for t in ttps]
    assert attack_ids.count("T1566") == 1  # deduplicated
    assert "T1657" in attack_ids


def test_surface_zone_keyword_maps_ground_station(tmp_path):
    """Claim containing 'earth station gateway' → zone ground_station_ingress."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    findings = [_finding("telecom", "Attacker targeting earth station gateway infrastructure")]
    _, zones, _ = map_cluster(_cluster(), findings, db_path=db_path)

    assert "ground_station_ingress" in zones


def test_surface_zone_maps_ntn_5g_core(tmp_path):
    """'5G core AMF signaling' → ntn_5g_core zone."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    findings = [_finding("telecom", "Exploit targeting 5G core AMF signaling interface")]
    _, zones, _ = map_cluster(_cluster(intent="generic_phish"), findings, db_path=db_path)

    assert "ntn_5g_core" in zones


def test_surface_zone_no_keyword_unmapped_not_guessed(tmp_path):
    """No surface zone keywords → surface_zones is empty, no guessing."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    findings = [_finding("osint", "Generic threat activity observed with no specific surface indicators")]
    _, zones, _ = map_cluster(_cluster(intent="generic_phish"), findings, db_path=db_path)

    assert zones == []


def test_ttp_observations_written_with_evidence_refs(tmp_path):
    """Every persisted ttp_observation row has non-null evidence_ref and surface_zone."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    findings = [
        _finding("attack", "Phishing link observed", attack_id="T1566",
                 source_url="https://cisa.gov/test"),
        _finding("telecom", "5G core targeted", attack_id="T1566"),
    ]
    map_cluster(_cluster(), findings, db_path=db_path)

    obs = get_ttp_observations("ttp-test-001", db_path=db_path)
    assert len(obs) > 0
    assert all(o.evidence_ref for o in obs)
    assert all(o.surface_zone for o in obs)


def test_no_attack_id_findings_produce_no_ttps():
    """Findings without attack_id in raw → empty TTP list, no fabrication."""
    findings = [_finding("osint", "Some claim with no ATT&CK mapping")]
    ttps = _extract_ttps_from_findings(findings)
    assert ttps == {}
