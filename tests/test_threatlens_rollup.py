"""Rollup aggregation tests — sector, org, network views."""
import time
import uuid

import pytest

from app.threatlens.models import ActorCluster, AdversaryProfile, IoCSet, TTPObservation, TTP
from app.threatlens.sector_rollup import network_rollup, org_rollup, sector_rollup
from app.threatlens.store import init_db, upsert_cluster, upsert_profile, upsert_ttp_observation


def _profile(cluster_id: str, segments: list[str], severity: str = "medium", confidence: str = "moderate") -> AdversaryProfile:
    return AdversaryProfile(
        id=str(uuid.uuid4()),
        cluster_id=cluster_id,
        generated_at=time.time(),
        assessed_identity="Test Actor",
        assessed_intent="credential_harvesting",
        severity=severity,
        confidence=confidence,
        segments=segments,
        summary="test",
        model="test",
    )


def _cluster(cluster_id: str, recipients: list[str] | None = None) -> ActorCluster:
    ts = time.time()
    return ActorCluster(
        id=cluster_id,
        created_at=ts, updated_at=ts, first_seen=ts, last_seen=ts,
        member_scan_ids=["s1"],
        dominant_intent="bec_fraud",
        iocs=IoCSet(),
        targets={"recipients": recipients or [], "segments": []},
        signature={}, status="active",
    )


def _obs(cluster_id: str, surface_zone: str) -> TTPObservation:
    return TTPObservation(
        id=str(uuid.uuid4()),
        cluster_id=cluster_id,
        attack_id="T1566",
        tactic="initial-access",
        surface_zone=surface_zone,
        evidence_ref="test",
        observed_at=time.time(),
    )


# ---------------------------------------------------------------------------

def test_sector_rollup_counts_by_vertical(tmp_path):
    """Profiles [maritime, maritime, mining] → maritime:2 mining:1, desc order."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    upsert_profile(_profile("c1", ["maritime"]), db_path=db_path)
    upsert_profile(_profile("c2", ["maritime"]), db_path=db_path)
    upsert_profile(_profile("c3", ["mining"]),   db_path=db_path)

    rollup = sector_rollup(db_path=db_path)

    buckets = {b["label"]: b for b in rollup.buckets}
    assert buckets["maritime"]["count"] == 2
    assert buckets["mining"]["count"]   == 1
    assert rollup.buckets[0]["label"]   == "maritime"


def test_sector_rollup_severity_weighted(tmp_path):
    """maritime 1 critical+1 low vs mining 3 low → maritime ranks higher by severity score."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    upsert_profile(_profile("c1", ["maritime"], severity="critical"), db_path=db_path)
    upsert_profile(_profile("c2", ["maritime"], severity="low"),      db_path=db_path)
    upsert_profile(_profile("c3", ["mining"],   severity="low"),      db_path=db_path)
    upsert_profile(_profile("c4", ["mining"],   severity="low"),      db_path=db_path)
    upsert_profile(_profile("c5", ["mining"],   severity="low"),      db_path=db_path)

    rollup = sector_rollup(db_path=db_path)
    # maritime: score=4+1=5; mining: score=1+1+1=3 → maritime ranks first
    assert rollup.buckets[0]["label"] == "maritime"


def test_org_rollup_by_targeted_team(tmp_path):
    """Recipients mapping to ops + finance → both appear in org rollup."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    upsert_cluster(_cluster("c1", recipients=["ops@skylo.tech", "ground-station@skylo.tech"]), db_path=db_path)
    upsert_cluster(_cluster("c2", recipients=["finance@skylo.tech", "cfo@skylo.tech"]),        db_path=db_path)

    rollup = org_rollup(db_path=db_path)
    labels = [b["label"] for b in rollup.buckets]

    assert "ground-station-ops" in labels
    assert "finance" in labels


def test_network_rollup_by_surface_zone(tmp_path):
    """ttp_observations ntn_5g_core×3, gcp_infra×1 → correct counts."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    for _ in range(3):
        upsert_ttp_observation(_obs("c1", "ntn_5g_core"), db_path=db_path)
    upsert_ttp_observation(_obs("c1", "gcp_infra"), db_path=db_path)

    rollup = network_rollup(db_path=db_path)
    buckets = {b["label"]: b for b in rollup.buckets}

    assert buckets["ntn_5g_core"]["count"] == 3
    assert buckets["gcp_infra"]["count"]   == 1
    assert rollup.buckets[0]["label"]      == "ntn_5g_core"


def test_rollup_empty_state(tmp_path):
    """No profiles/clusters/observations → empty bucket lists, no error."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    assert sector_rollup(db_path=db_path).buckets  == []
    assert org_rollup(db_path=db_path).buckets     == []
    assert network_rollup(db_path=db_path).buckets == []
