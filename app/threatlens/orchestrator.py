"""ThreatLens orchestrator — runs one profiling cycle.

Phase 2: processes the top cluster by member count (vertical slice).
Phase 3+: full fan-out across all active clusters with bounded concurrency.
"""
from __future__ import annotations

import asyncio
import time

import structlog

from app.threatlens import fusion_engine, profiler, store
from app.threatlens.agents import registry
from app.threatlens.agents.attack_mapper_agent import AttackMapperAgent
from app.threatlens.agents.osint_report_agent import OsintReportAgent
from app.threatlens.config import threatlens_settings
from app.threatlens.models import Finding

logger = structlog.get_logger()

_DEFAULT_AGENTS = [OsintReportAgent(), AttackMapperAgent()]


def _bootstrap_registry() -> None:
    """Register default agents if the registry is empty."""
    if not registry.active():
        for agent in _DEFAULT_AGENTS:
            registry.register(agent)


async def run_cycle(db_path: str | None = None) -> dict:
    """Run one profiling cycle. Returns a summary dict."""
    if not threatlens_settings.intel_enabled:
        return {"skipped": True, "reason": "INTEL_ENABLED=false"}

    _bootstrap_registry()

    kwargs = {"db_path": db_path} if db_path else {}
    clusters = store.get_active_clusters(**kwargs)

    if not clusters:
        return {"clusters_processed": 0, "profiles_written": 0}

    # Phase 2: top cluster only (vertical slice)
    # Phase 3+: replace with bounded semaphore over all clusters
    target = sorted(clusters, key=lambda c: len(c.member_scan_ids), reverse=True)[:1]

    profiles_written = 0
    started = time.time()

    for cluster in target:
        # Run all agents concurrently
        agent_tasks = [agent.run(cluster) for agent in registry.active()]
        raw_results = await asyncio.gather(*agent_tasks, return_exceptions=True)

        all_findings: list[Finding] = []
        for result in raw_results:
            if isinstance(result, list):
                all_findings.extend(result)
            # exceptions are isolated — other agents' results still used

        # Fuse
        claims, ttps, max_conf = fusion_engine.run(cluster, all_findings)

        # Profile
        profile = await profiler.synthesize(cluster, claims, ttps, max_conf)

        # Persist
        store.upsert_profile(profile, **kwargs)
        profiles_written += 1

        logger.info(
            "threatlens_cycle_cluster_done",
            cluster=cluster.id[:8],
            findings=len(all_findings),
            confidence=max_conf,
            profile=profile.id[:8],
        )

    duration = time.time() - started
    logger.info(
        "threatlens_cycle_done",
        clusters=len(target),
        profiles=profiles_written,
        duration_secs=round(duration, 2),
    )
    return {
        "clusters_processed": len(target),
        "profiles_written": profiles_written,
        "duration_secs": round(duration, 2),
    }
