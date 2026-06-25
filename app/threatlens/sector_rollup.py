"""Sector / Org / Network rollup aggregations.

Three views over the profile and TTP observation data:
  sector  — industry vertical pressure (maritime, logistics, mining…)
  org     — which internal Skylo team is being targeted
  network — which attack-surface zone is under the most pressure
"""
from __future__ import annotations

import os

from app.threatlens import store
from app.threatlens.models import Rollup

_DB_PATH = os.environ.get("PHISHGUARD_DB_PATH", "data/phishguard.db")
_SEV_SCORES = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def sector_rollup(db_path: str = _DB_PATH) -> Rollup:
    """Count and severity-weight profiles by industry vertical."""
    profiles = store.get_profiles(db_path=db_path)
    buckets: dict[str, dict] = {}
    for p in profiles:
        for seg in (p.segments or []):
            b = buckets.setdefault(seg, {"label": seg, "count": 0, "severity_score": 0})
            b["count"] += 1
            b["severity_score"] += _SEV_SCORES.get(p.severity, 0)
    return Rollup(
        dimension="sector",
        buckets=sorted(
            buckets.values(),
            key=lambda b: (b["severity_score"], b["count"]),
            reverse=True,
        ),
    )


def org_rollup(db_path: str = _DB_PATH) -> Rollup:
    """Count clusters by targeted internal Skylo team (derived from recipients)."""
    clusters = store.get_all_clusters(db_path=db_path)
    teams: dict[str, dict] = {}
    for c in clusters:
        for r in c.targets.get("recipients", []):
            team = _classify_team(r)
            if team:
                b = teams.setdefault(team, {"label": team, "count": 0, "severity_score": 0})
                b["count"] += 1
    return Rollup(
        dimension="org",
        buckets=sorted(teams.values(), key=lambda b: b["count"], reverse=True),
    )


def network_rollup(db_path: str = _DB_PATH) -> Rollup:
    """Count TTP observations by Skylo attack-surface zone."""
    obs = store.get_all_ttp_observations(db_path=db_path)
    zones: dict[str, dict] = {}
    for o in obs:
        if o.surface_zone and o.surface_zone != "unmapped":
            b = zones.setdefault(o.surface_zone, {"label": o.surface_zone, "count": 0, "severity_score": 0})
            b["count"] += 1
    return Rollup(
        dimension="network",
        buckets=sorted(zones.values(), key=lambda b: b["count"], reverse=True),
    )


def _classify_team(email: str) -> str | None:
    e = (email or "").lower()
    if any(k in e for k in ["finance", "cfo", "payroll", "invoice", "accounting", "treasury"]):
        return "finance"
    if any(k in e for k in ["ops", "operations", "ground", "network", "noc", "rf", "teleport"]):
        return "ground-station-ops"
    if any(k in e for k in ["engineer", "dev", "tech", "r&d", "research", "platform", "core"]):
        return "engineering"
    if any(k in e for k in ["hr", "people", "talent", "recruit", "hiring"]):
        return "hr"
    if any(k in e for k in ["exec", "ceo", "cto", "ciso", "vp", "president", "director", "chief"]):
        return "executive"
    if any(k in e for k in ["legal", "compliance", "audit", "risk", "counsel"]):
        return "legal-compliance"
    return None
