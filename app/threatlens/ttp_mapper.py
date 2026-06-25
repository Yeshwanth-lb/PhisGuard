"""TTP Mapper — consolidates ATT&CK techniques and maps to Skylo surface zones.

Takes findings from ALL agents, deduplicates ATT&CK technique IDs, maps the
cluster to Skylo's NTN attack-surface zones via keyword matching, and writes
ttp_observations to the database.

Mapping is keyword-based (deterministic). No guessing — if no keyword matches
a zone, the observation is written as 'unmapped'.
"""
from __future__ import annotations

import time
import uuid
from pathlib import Path

import yaml
import structlog

from app.threatlens import store
from app.threatlens.models import ActorCluster, Finding, TTP, TTPObservation

logger = structlog.get_logger()

_TAXONOMY_PATH = Path(__file__).parent / "data" / "attack_surface.yaml"
_taxonomy_cache: dict | None = None


def _load_taxonomy() -> dict:
    global _taxonomy_cache
    if _taxonomy_cache is None:
        try:
            with open(_TAXONOMY_PATH) as f:
                _taxonomy_cache = yaml.safe_load(f) or {}
        except Exception as exc:
            logger.warning("taxonomy_load_failed", error=str(exc))
            _taxonomy_cache = {}
    return _taxonomy_cache


def _extract_ttps_from_findings(findings: list[Finding]) -> dict[str, TTP]:
    """Extract and deduplicate TTPs from all agent findings by attack_id."""
    seen: dict[str, TTP] = {}
    for f in findings:
        raw = f.raw or {}
        aid = raw.get("attack_id", "")
        if not aid or not aid.startswith("T"):
            continue
        if aid not in seen:
            seen[aid] = TTP(
                attack_id=aid,
                name=raw.get("name", aid),
                tactic=raw.get("tactic", "unknown"),
                evidence_ref=f.source_title or f.agent or "unknown",
            )
    return seen


def _map_surface_zones(cluster: ActorCluster, findings: list[Finding]) -> list[str]:
    """Match cluster + findings text against Skylo surface zone keywords."""
    taxonomy = _load_taxonomy()
    zones = taxonomy.get("zones", [])

    # Build searchable text from cluster context + findings
    texts = [
        (cluster.dominant_intent or "").lower(),
        " ".join(cluster.iocs.domains).lower(),
        " ".join(f.claim.lower() for f in findings if f.claim),
    ]
    combined = " ".join(texts)

    matched = []
    for zone in zones:
        zone_id = zone.get("id", "")
        keywords = zone.get("keywords", [])
        for kw in keywords:
            if kw.lower() in combined:
                if zone_id not in matched:
                    matched.append(zone_id)
                break  # one keyword match per zone is enough

    return matched


def _map_segments(cluster: ActorCluster) -> list[str]:
    """Map targeted recipients to industry vertical segments."""
    taxonomy = _load_taxonomy()
    segments_config = taxonomy.get("segments", [])
    segment_ids = [s.get("id", "") for s in segments_config if s.get("id")]

    targets_text = " ".join([
        " ".join(cluster.targets.get("recipients", [])),
        " ".join(cluster.targets.get("segments", [])),
        cluster.dominant_intent or "",
    ]).lower()

    matched = []
    for seg in segment_ids:
        if seg.replace("_", " ") in targets_text or seg in targets_text:
            matched.append(seg)

    return matched


def map_cluster(
    cluster: ActorCluster,
    findings: list[Finding],
    db_path: str | None = None,
) -> tuple[list[TTP], list[str], list[str]]:
    """
    Main entry point.

    Returns (deduped_ttps, surface_zones, segments).
    Writes ttp_observations to the database as a side effect.
    """
    ttps_by_id = _extract_ttps_from_findings(findings)
    surface_zones = _map_surface_zones(cluster, findings)
    segments = _map_segments(cluster)

    now = time.time()
    kwargs = {"db_path": db_path} if db_path else {}

    for aid, ttp in ttps_by_id.items():
        zones_to_write = surface_zones if surface_zones else ["unmapped"]
        for zone in zones_to_write:
            obs = TTPObservation(
                id=str(uuid.uuid4()),
                cluster_id=cluster.id,
                attack_id=aid,
                tactic=ttp.tactic,
                surface_zone=zone,
                evidence_ref=ttp.evidence_ref,
                observed_at=now,
            )
            store.upsert_ttp_observation(obs, **kwargs)

    logger.info(
        "ttp_mapper_done",
        cluster=cluster.id[:8],
        ttps=len(ttps_by_id),
        zones=surface_zones,
        segments=segments,
    )
    return list(ttps_by_id.values()), surface_zones, segments
