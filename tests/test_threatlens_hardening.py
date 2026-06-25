"""Phase 5 hardening tests — dirty flag, caching, concurrency, retention, provenance."""
import asyncio
import time
import uuid

import pytest

from app.threatlens.config import threatlens_settings
from app.threatlens.models import ActorCluster, AdversaryProfile, IoCSet, TTP, CorroboratedClaim
from app.threatlens.store import (
    get_dirty_clusters,
    get_intel_sources,
    init_db,
    log_intel_source,
    mark_cluster_profiled,
    prune_old_intel_sources,
    upsert_cluster,
    upsert_profile,
)
from app.threatlens.agents.base_agent import BaseAgent, clear_cache, _cache
from app.threatlens.models import Finding


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cluster(cluster_id: str = "c1", ts: float | None = None) -> ActorCluster:
    now = ts or time.time()
    return ActorCluster(
        id=cluster_id,
        created_at=now, updated_at=now, first_seen=now, last_seen=now,
        member_scan_ids=["s1"],
        dominant_intent="bec_fraud",
        iocs=IoCSet(domains=["evil.com"]),
        targets={}, signature={"domain_base": "evil", "intent": "bec_fraud"},
        status="active",
    )


def _profile(cluster_id: str) -> AdversaryProfile:
    return AdversaryProfile(
        id=str(uuid.uuid4()),
        cluster_id=cluster_id,
        generated_at=time.time(),
        assessed_identity="Test Actor",
        assessed_intent="bec_fraud",
        severity="high",
        confidence="moderate",
        summary="test",
        model="test",
    )


@pytest.fixture(autouse=True)
def reset_agent_cache():
    clear_cache()
    yield
    clear_cache()


# ---------------------------------------------------------------------------
# Dirty flag
# ---------------------------------------------------------------------------

def test_dirty_flag_skips_unchanged_cluster(tmp_path):
    """Cluster that was profiled and hasn't changed → not in dirty list."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    c = _cluster("c1")
    upsert_cluster(c, db_path=db_path)
    upsert_profile(_profile("c1"), db_path=db_path)
    mark_cluster_profiled("c1", db_path=db_path)  # mark as clean

    dirty = get_dirty_clusters(db_path=db_path)
    assert len(dirty) == 0


def test_changed_cluster_reprofiled(tmp_path):
    """Cluster that received a new scan after last profile → appears in dirty list."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    c = _cluster("c1")
    upsert_cluster(c, db_path=db_path)
    mark_cluster_profiled("c1", db_path=db_path)

    # Simulate new scan joining: bump updated_at past last_profiled_at
    c.member_scan_ids.append("s2")
    c.updated_at = time.time() + 1
    upsert_cluster(c, db_path=db_path)

    dirty = get_dirty_clusters(db_path=db_path)
    assert len(dirty) == 1
    assert dirty[0].id == "c1"


# ---------------------------------------------------------------------------
# Cache TTL
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cache_ttl_expiry_refetches():
    """Agent returns cached result within TTL; re-fetches after TTL expires."""
    call_count = 0

    class TTLAgent(BaseAgent):
        name = "ttl_test"
        async def _run_impl(self, cluster):
            nonlocal call_count
            call_count += 1
            return [Finding(agent="ttl", claim="found", confidence="low")]

    agent = TTLAgent(timeout_secs=5)
    cluster = _cluster()

    # First call — populates cache
    await agent.run(cluster)
    assert call_count == 1

    # Second call within TTL — cache hit, no re-fetch
    await agent.run(cluster)
    assert call_count == 1

    # Manually expire the cache entry
    cache_key = ("ttl_test", cluster.id)
    stored_at, findings = _cache[cache_key]
    _cache[cache_key] = (stored_at - agent._cache_ttl - 1, findings)

    # Third call — TTL expired, must re-fetch
    await agent.run(cluster)
    assert call_count == 2


# ---------------------------------------------------------------------------
# Bounded concurrency
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bounded_concurrency_caps_parallel_clusters(mocker, tmp_path):
    """With max_concurrency=4 and 10 dirty clusters, at most 4 run at once."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    # Create 10 dirty clusters
    for i in range(10):
        upsert_cluster(_cluster(f"c{i}"), db_path=db_path)

    # Track max concurrency
    max_concurrent = [0]
    current = [0]

    async def mock_synthesize(cluster, *args, **kwargs):
        current[0] += 1
        max_concurrent[0] = max(max_concurrent[0], current[0])
        await asyncio.sleep(0.02)
        current[0] -= 1
        return _profile(cluster.id)

    mocker.patch("app.threatlens.profiler.synthesize", mock_synthesize)
    mocker.patch("app.threatlens.fusion_engine.run", return_value=([], [], "speculative"))
    mocker.patch("app.threatlens.ttp_mapper.map_cluster", return_value=([], [], []))
    mocker.patch("app.threatlens.agents.registry.active", return_value=[])
    mocker.patch.object(threatlens_settings, "intel_enabled", True)
    mocker.patch.object(threatlens_settings, "intel_max_cluster_concurrency", 4)

    from app.threatlens.orchestrator import run_cycle
    result = await run_cycle(db_path=db_path)

    assert max_concurrent[0] <= 4
    assert result["clusters_processed"] == 10


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------

def test_retention_prunes_old_intel_snapshots(tmp_path):
    """intel_sources rows older than retention_days are deleted; recent ones kept."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    old_ts = time.time() - 95 * 86400   # 95 days ago
    new_ts = time.time() - 5 * 86400    # 5 days ago

    log_intel_source("c1", "osint", "https://cisa.gov/old", "Old", "{}", "low",
                     db_path=db_path, fetched_at=old_ts)
    log_intel_source("c1", "osint", "https://cisa.gov/new", "New", "{}", "moderate",
                     db_path=db_path, fetched_at=new_ts)

    deleted = prune_old_intel_sources(retention_days=90, db_path=db_path)
    assert deleted == 1

    remaining = get_intel_sources("c1", db_path=db_path)
    assert len(remaining) == 1
    assert "new" in remaining[0]["source_url"]


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_every_fetch_logged_with_provenance(mocker, tmp_path):
    """After a cycle run, every agent finding with a source URL appears in intel_sources."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    c = _cluster("c1")
    upsert_cluster(c, db_path=db_path)

    # Create a mock agent that returns findings with and without source URLs
    test_findings = [
        Finding(agent="osint",  claim="Phishing found", source_url="https://cisa.gov/test",        confidence="moderate"),
        Finding(agent="attack", claim="T1566 mapped",   source_url=None,                            confidence="moderate"),
        Finding(agent="ioc",    claim="Bad domain",     source_url="https://urlhaus.abuse.ch/test", confidence="high"),
    ]

    class FakeAgent(BaseAgent):
        name = "fake_provenance"
        async def _run_impl(self, cluster):
            return test_findings

    mocker.patch("app.threatlens.agents.registry.active", return_value=[FakeAgent()])
    mocker.patch("app.threatlens.fusion_engine.run", return_value=([], [], "speculative"))
    mocker.patch("app.threatlens.ttp_mapper.map_cluster", return_value=([], [], []))
    mocker.patch("app.threatlens.profiler.synthesize", return_value=_profile("c1"))
    mocker.patch.object(threatlens_settings, "intel_enabled", True)

    from app.threatlens.orchestrator import run_cycle
    await run_cycle(db_path=db_path)

    rows = get_intel_sources("c1", db_path=db_path)
    # Only findings WITH source_url should be logged (2 out of 3)
    assert len(rows) == 2
    sources = {r["source_url"] for r in rows}
    assert "https://cisa.gov/test" in sources
    assert "https://urlhaus.abuse.ch/test" in sources
    # Every row must have required provenance fields
    for r in rows:
        assert r["source_url"]
        assert r["agent"]
        assert r["fetched_at"]
