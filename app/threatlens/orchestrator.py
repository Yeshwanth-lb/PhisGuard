"""ThreatLens orchestrator — runs one full profiling cycle.

Phase 3: all 10 agents run in parallel per cluster, TTP mapper adds
Skylo surface zone mapping, profiler receives full context.

Agent fleet (10 total):
  Phase 2: osint_report, attack_mapper
  Phase 3 PRD: misp_opencti, ioc_reputation, cve, compromise, telecom_ntn
  Phase 3 bonus: network_intel (no key), greynoise, urlscan
"""
from __future__ import annotations

import asyncio
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


async def run_cycle(db_path: str | None = None) -> dict:
    """Run one profiling cycle. Returns a summary dict."""
    if not threatlens_settings.intel_enabled:
        return {"skipped": True, "reason": "INTEL_ENABLED=false"}

    _bootstrap_registry()

    kwargs = {"db_path": db_path} if db_path else {}
    clusters = store.get_active_clusters(**kwargs)

    if not clusters:
        return {"clusters_processed": 0, "profiles_written": 0}

    # Phase 3: all active clusters, bounded by max concurrency
    sem = asyncio.Semaphore(threatlens_settings.intel_max_cluster_concurrency)
    started = time.time()
    profiles_written = 0

    async def _process_one(cluster):
        nonlocal profiles_written
        async with sem:
            # 1. Run all 10 agents in parallel
            agent_tasks = [agent.run(cluster) for agent in registry.active()]
            raw_results = await asyncio.gather(*agent_tasks, return_exceptions=True)

            all_findings: list[Finding] = []
            for result in raw_results:
                if isinstance(result, list):
                    all_findings.extend(result)

            # 2. Fusion — confidence math in Python
            claims, _, max_conf = fusion_engine.run(cluster, all_findings)

            # 3. TTP mapper — dedupe + Skylo surface zones
            ttps, surface_zones, segments = ttp_mapper.map_cluster(
                cluster, all_findings, **kwargs
            )

            # 4. Claude synthesizes the full profile
            profile = await profiler.synthesize(
                cluster, claims, ttps, max_conf, surface_zones, segments
            )

            # 5. Persist
            store.upsert_profile(profile, **kwargs)
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

    await asyncio.gather(*[_process_one(c) for c in clusters])

    duration = time.time() - started
    logger.info(
        "threatlens_cycle_done",
        clusters=len(clusters),
        profiles=profiles_written,
        duration_secs=round(duration, 2),
    )
    return {
        "clusters_processed": len(clusters),
        "profiles_written": profiles_written,
        "duration_secs": round(duration, 2),
    }
