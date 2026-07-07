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
from app.threatlens.agents.darkweb_agent import DarkWebAgent
from app.threatlens.config import threatlens_settings
from app.threatlens.models import Finding
from app.threatlens import neo4j_writer
from app.threatlens import slack_notifier as tl_slack

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
    DarkWebAgent(),        # IntelligenceX + CIRCL PassiveDNS + LeakIX
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
    alerts_sent = 0
    confirmed_count = 0
    critical_zone_count = 0
    from app.config import settings as _settings
    _webhook = getattr(_settings, "slack_webhook_url", "")

    async def _process_one(cluster):
        nonlocal profiles_written, llm_calls, alerts_sent, confirmed_count, critical_zone_count
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

            # 5. Claude synthesizes — counts as 1 LLM call.
            #    Apply any prior analyst feedback for this cluster (feedback loop).
            feedback = store.get_cluster_feedback(cluster.id, **kwargs)
            profile = await profiler.synthesize(
                cluster, claims, ttps, max_conf, surface_zones, segments,
                feedback=feedback,
            )
            llm_calls += 1

            # 6. Persist profile + mark cluster as clean
            store.upsert_profile(profile, **kwargs)
            store.mark_cluster_profiled(cluster.id, **kwargs)
            profiles_written += 1

            # 7. Smart Slack alert — fires for critical surfaces / confirmed matches
            if _webhook:
                sent = await tl_slack.alert_if_critical(
                    cluster, profile, webhook_url=_webhook
                )
                if sent:
                    alerts_sent += 1
                    if profile.confidence == "confirmed":
                        confirmed_count += 1
                    if set(profile.surface_zones or []) & {"ground_station_ingress", "ntn_5g_core"}:
                        critical_zone_count += 1

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

    # Send cycle summary to Slack if notable events occurred
    if _webhook:
        await tl_slack.send_cycle_summary(
            clusters_processed=len(dirty_clusters),
            profiles_written=profiles_written,
            confirmed_count=confirmed_count,
            critical_zones_count=critical_zone_count,
            webhook_url=_webhook,
        )

    # Push updated graph to Neo4j (non-blocking, silently skips if Neo4j unavailable)
    neo4j_result = {"skipped": True}
    try:
        neo4j_result = await _push_to_neo4j(db_path)
    except Exception as exc:
        logger.debug("neo4j_push_skipped", error=str(exc)[:80])

    duration = time.time() - started
    summary = {
        "clusters_processed": len(dirty_clusters),
        "clusters_skipped":   clusters_skipped,
        "profiles_written":   profiles_written,
        "llm_calls":          llm_calls,
        "alerts_sent":        alerts_sent,
        "duration_secs":      round(duration, 2),
        "neo4j":              neo4j_result,
    }
    logger.info("threatlens_cycle_done", **summary)
    return summary


async def _push_to_neo4j(db_path: str | None = None) -> dict:
    """Build the graph data and push to Neo4j after each cycle."""
    kwargs = {"db_path": db_path} if db_path else {}
    clusters = store.get_active_clusters(**kwargs)
    profiles_list = store.get_profiles(**kwargs)
    profiles = {p.cluster_id: p for p in profiles_list}

    NOISE = {"unknown", "legitimate", "clean", "unclear", "generic_phish", "", None}
    INTENT_META = {
        "credential_harvest":"#3b82f6","credential_harvesting":"#3b82f6",
        "bec_fraud":"#ef4444","fraud_payment":"#f97316","fraud_scam":"#f97316",
        "brand_impersonation":"#8b5cf6","executive_impersonation":"#a855f7",
    }
    GROUP_MAP = {
        "credential_harvest":"Credential Theft","credential_harvesting":"Credential Theft",
        "bec_fraud":"BEC Fraud","fraud_payment":"Financial Fraud","fraud_scam":"Financial Fraud",
        "brand_impersonation":"Impersonation","executive_impersonation":"Impersonation",
    }

    threat = [c for c in clusters if c.dominant_intent not in NOISE and len(c.member_scan_ids) >= 2]
    threat.sort(key=lambda c: len(c.member_scan_ids), reverse=True)
    top = threat[:30]

    nodes = []
    for c in top:
        p = profiles.get(c.id)
        intent = c.dominant_intent or "other"
        nodes.append({
            "id":           c.id[:12],
            "full_id":      c.id,
            "intent":       intent,
            "group":        GROUP_MAP.get(intent, "Other"),
            "group_color":  INTENT_META.get(intent, "#64748b"),
            "label":        intent.replace("_"," ").title(),
            "short_label":  (intent.replace("credential_harvest","Cred Theft")
                                   .replace("credential_harvesting","Cred Theft")
                                   .replace("bec_fraud","BEC Fraud")
                                   .replace("fraud_payment","Fin. Fraud")
                                   .replace("brand_impersonation","Brand Imp.")
                                   .replace("_"," ").title()),
            "member_count": len(c.member_scan_ids),
            "severity":     p.severity if p else "low",
            "confidence":   p.confidence if p else "speculative",
            "surface_zones": ",".join(p.surface_zones) if p else "",
            "ttp_ids":      ",".join(t.attack_id for t in p.ttps[:4]) if p else "",
            "summary":      (p.summary or "")[:150] if p else "",
            "domains":      ",".join(c.iocs.domains[:2]),
        })

    edges = []
    for i, c1 in enumerate(top):
        for c2 in top[i+1:]:
            p1, p2 = profiles.get(c1.id), profiles.get(c2.id)
            shared_ips = set(c1.iocs.ips) & set(c2.iocs.ips) - {""}
            if shared_ips:
                edges.append({"from":c1.id[:12],"to":c2.id[:12],"type":"shared_ip",
                              "label":f"Shared IP: {list(shared_ips)[0]}","weight":1.0})
                continue
            shared_domains = set(c1.iocs.domains) & set(c2.iocs.domains) - {""}
            if shared_domains:
                edges.append({"from":c1.id[:12],"to":c2.id[:12],"type":"shared_domain",
                              "label":f"Domain: {list(shared_domains)[0]}","weight":0.9})
                continue
            if p1 and p2:
                shared = {t.attack_id for t in p1.ttps} & {t.attack_id for t in p2.ttps}
                if len(shared) >= 3:
                    edges.append({"from":c1.id[:12],"to":c2.id[:12],"type":"shared_ttps",
                                  "label":f"{len(shared)} shared TTPs","weight":0.7})

    return await neo4j_writer.push_graph(nodes, edges)
