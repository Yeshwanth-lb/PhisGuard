"""Tests for app/threatlens/store.py — Phase 1.

All tests use a temp SQLite DB (never the real data/phishguard.db).
No network calls, no LLM.
"""
import sqlite3
import time

import pytest

from app.threatlens.models import ActorCluster, IoCSet
from app.threatlens.store import (
    get_active_clusters,
    get_cluster,
    init_db,
    upsert_cluster,
)


def _make_cluster(
    cluster_id: str,
    status: str = "active",
    last_seen: float | None = None,
    created_at: float | None = None,
) -> ActorCluster:
    ts = last_seen or time.time()
    ca = created_at or ts
    return ActorCluster(
        id=cluster_id,
        created_at=ca,
        updated_at=ts,
        first_seen=ts,
        last_seen=ts,
        member_scan_ids=["scan-1"],
        dominant_intent="credential_harvesting",
        iocs=IoCSet(domains=["evil.com"], ips=["1.2.3.4"]),
        targets={"recipients": ["victim@company.com"], "segments": []},
        signature={"domain_base": "evil", "intent": "credential_harvesting"},
        status=status,
    )


def test_store_creates_all_tables(tmp_path):
    """Given a fresh temp DB; When init_db(); Then all five tables exist and a
    second call raises nothing (idempotent)."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    conn = sqlite3.connect(db_path)
    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    conn.close()

    assert "actor_clusters"       in tables
    assert "actor_profiles"       in tables
    assert "intel_sources"        in tables
    assert "ttp_observations"     in tables
    assert "org_threat_assessment" in tables

    # Second call must not raise
    init_db(db_path=db_path)


def test_store_upsert_cluster_inserts_then_updates(tmp_path):
    """Given id c1 absent; When upsert last_seen=100 then last_seen=200;
    Then one row, last_seen==200, created_at unchanged."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    c1 = _make_cluster("c1", created_at=50.0, last_seen=100.0)
    upsert_cluster(c1, db_path=db_path)

    c1.last_seen  = 200.0
    c1.updated_at = 200.0
    upsert_cluster(c1, db_path=db_path)

    result = get_cluster("c1", db_path=db_path)
    assert result is not None
    assert result.last_seen  == pytest.approx(200.0)
    assert result.created_at == pytest.approx(50.0)   # preserved

    # Only one row
    conn = sqlite3.connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM actor_clusters WHERE id='c1'").fetchone()[0]
    conn.close()
    assert count == 1


def test_store_get_active_excludes_dormant(tmp_path):
    """Given c1 active, c2 dormant; When get_active_clusters(); Then only c1 returned."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    upsert_cluster(_make_cluster("c1", status="active"),  db_path=db_path)
    upsert_cluster(_make_cluster("c2", status="dormant"), db_path=db_path)

    active_ids = [c.id for c in get_active_clusters(db_path=db_path)]

    assert "c1" in  active_ids
    assert "c2" not in active_ids


def test_store_roundtrip_preserves_json_fields(tmp_path):
    """Given a cluster with IoC and member JSON; When upsert then get;
    Then parsed IoCSet and member_scan_ids match originals exactly."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    original = _make_cluster("c1")
    original.member_scan_ids = ["s1", "s2", "s3"]
    original.iocs = IoCSet(
        domains=["bad.com", "evil.io"],
        ips=["10.0.0.1", "192.168.1.1"],
    )
    upsert_cluster(original, db_path=db_path)

    retrieved = get_cluster("c1", db_path=db_path)
    assert retrieved is not None
    assert retrieved.member_scan_ids == ["s1", "s2", "s3"]
    assert set(retrieved.iocs.domains) == {"bad.com", "evil.io"}
    assert set(retrieved.iocs.ips)     == {"10.0.0.1", "192.168.1.1"}
