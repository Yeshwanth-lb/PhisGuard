"""ThreatLens orchestrator — runs one full profiling cycle.

Phase 5 hardening:
  - Only processes DIRTY clusters (updated since last profile) — skips unchanged
  - Logs provenance for every agent finding that has a source URL
  - Tracks per-run cost metrics (LLM calls, clusters skipped)
  - Bounded concurrency via semaphore (INTEL_MAX_CLUSTER_CONCURRENCY)

Agent fleet (10 total):
  Phase 2: osint_report, attack_mapper
  Phase 3 PRD: misp_opencti, ioc_reputation, cve, compromise, telecom_ntn
  Phase 3 bonus: network_intel (no key), greynoise, urlscan
"""
from __future__ import annotations

import asyncio
import json
import time

import structlog

from app.threatlens import fusion_engine, profiler, store, ttp_mapper
from app.threatlens.agents import registry
from app.threatlens.agents.attack_mapper_agent import AttackMapperAgent
from app.threatlens.agents.compromise_intel_agent import CompromiseIntelAgent
from app.threatlens.agents.cve_agent import CVEAgent
from app.threatlens.agents.greynoise_agent import GreyNoiseAgent
from app.threatlens.agents.ioc_reputation_agent import IoCReputationAgent
from app.threatlens.agents.misp_opencti_agent import MispOpenCTIAgent
from app.threatlens.agents.network_intel_agent import NetworkIntelAgent
from app.threatlens.agents.osint_report_agent import OsintReportAgent
from app.threatlens.agents.telecom_ntn_agent import TelecomNTNAgent
from app.threatlens.agents.urlscan_agent import URLScanAgent
from app.threatlens.config import threatlens_settings
from app.threatlens.models import Finding

logger = structlog.get_logger()

_ALL_AGENTS = [
    OsintReportAgent(),
    AttackMapperAgent(),
    MispOpenCTIAgent(),
    IoCReputationAgent(),
    CVEAgent(),
    CompromiseIntelAgent(),
    TelecomNTNAgent(),
    NetworkIntelAgent(),
    GreyNoiseAgent(),
    URLScanAgent(),
]


def _bootstrap_registry() -> None:
    if not registry.active():
        for agent in _ALL_AGENTS:
            registry.register(agent)


def _log_provenance(
    cluster_id: str,
    findings: list[Finding],
    db_path: str | None,
) -> None:
    """Write one intel_sources row per finding that has a source URL."""
    kwargs = {"db_path": db_path} if db_path else {}
    for f in findings:
        if f.source_url:
            store.log_intel_source(
                cluster_id=cluster_id,
                agent=f.agent,
                source_url=f.source_url,
                source_title=f.source_title or f.source_url,
                finding_json=json.dumps({"claim": f.claim, "confidence": f.confidence}),
                confidence=f.confidence,
                **kwargs,
            )


async def run_cycle(db_path: str | None = None) -> dict:
    """Run one profiling cycle. Returns a summary dict.

    Phase 5: only processes dirty clusters (skips unchanged ones).
    """
    if not threatlens_settings.intel_enabled:
        return {"skipped": True, "reason": "INTEL_ENABLED=false"}

    _bootstrap_registry()

    kwargs = {"db_path": db_path} if db_path else {}

    # Phase 5: use dirty clusters instead of all active clusters
    all_active = store.get_active_clusters(**kwargs)
    dirty_clusters = store.get_dirty_clusters(**kwargs)
    clusters_skipped = len(all_active) - len(dirty_clusters)

    if not dirty_clusters:
        logger.info(
            "threatlens_cycle_nothing_dirty",
            active=len(all_active),
            skipped=clusters_skipped,
        )
        return {
            "clusters_processed": 0,
            "clusters_skipped": clusters_skipped,
            "profiles_written": 0,
            "llm_calls": 0,
        }

    sem = asyncio.Semaphore(threatlens_settings.intel_max_cluster_concurrency)
    started = time.time()
    profiles_written = 0
    llm_calls = 0

    async def _process_one(cluster):
        nonlocal profiles_written, llm_calls
        async with sem:
            # 1. Run all agents in parallel
            agent_tasks = [agent.run(cluster) for agent in registry.active()]
            raw_results = await asyncio.gather(*agent_tasks, return_exceptions=True)

            all_findings: list[Finding] = []
            for result in raw_results:
                if isinstance(result, list):
                    all_findings.extend(result)

            # 2. Log provenance for every finding with a source URL
            _log_provenance(cluster.id, all_findings, db_path)

            # 3. Fusion
            claims, _, max_conf = fusion_engine.run(cluster, all_findings)

            # 4. TTP mapper
            ttps, surface_zones, segments = ttp_mapper.map_cluster(
                cluster, all_findings, **kwargs
            )

            # 5. Claude synthesizes — counts as 1 LLM call
            profile = await profiler.synthesize(
                cluster, claims, ttps, max_conf, surface_zones, segments
            )
            llm_calls += 1

            # 6. Persist profile + mark cluster as clean
            store.upsert_profile(profile, **kwargs)
            store.mark_cluster_profiled(cluster.id, **kwargs)
            profiles_written += 1

            logger.info(
                "threatlens_cluster_done",
                cluster=cluster.id[:8],
                findings=len(all_findings),
                ttps=len(ttps),
                zones=surface_zones,
                confidence=max_conf,
                profile=profile.id[:8],
            )

    await asyncio.gather(*[_process_one(c) for c in dirty_clusters])

    duration = time.time() - started
    summary = {
        "clusters_processed": len(dirty_clusters),
        "clusters_skipped":   clusters_skipped,
        "profiles_written":   profiles_written,
        "llm_calls":          llm_calls,
        "duration_secs":      round(duration, 2),
    }
    logger.info("threatlens_cycle_done", **summary)
    return summary
