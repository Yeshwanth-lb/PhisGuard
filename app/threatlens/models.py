"""Pydantic models for ThreatLens.

All models are defined here upfront. Only IoCSet and ActorCluster are used in
Phase 1; the rest are exercised from Phase 2 onward.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


# ── Phase 1 ──────────────────────────────────────────────────────────────────

class IoCSet(BaseModel):
    domains: list[str] = []
    ips: list[str] = []
    url_patterns: list[str] = []
    registrars: list[str] = []
    asns: list[str] = []


class ActorCluster(BaseModel):
    id: str
    created_at: float
    updated_at: float
    first_seen: float
    last_seen: float
    member_scan_ids: list[str] = []
    dominant_intent: str | None = None
    iocs: IoCSet = Field(default_factory=IoCSet)
    targets: dict = Field(default_factory=dict)   # {recipients: [...], segments: [...]}
    signature: dict = Field(default_factory=dict)
    status: str = "active"                         # active | dormant | merged


# ── Phase 2+ ─────────────────────────────────────────────────────────────────

class Finding(BaseModel):
    """A single assessed statement from one agent, with a citation."""
    agent: str
    claim: str
    source_url: str | None = None
    source_title: str | None = None
    confidence: str  # confirmed | high | moderate | low | speculative
    raw: dict = Field(default_factory=dict)


class TTP(BaseModel):
    attack_id: str    # e.g. T1566
    name: str
    tactic: str
    evidence_ref: str


class CorroboratedClaim(BaseModel):
    """A claim that has been deduplicated and weighted across independent sources."""
    claim: str
    attack_id: str | None = None
    iocs: IoCSet | None = None
    supporting_sources: list[str] = []
    independent_source_count: int = 0
    confidence: str  # assigned deterministically by the fusion engine


class AdversaryProfile(BaseModel):
    id: str
    cluster_id: str
    generated_at: float
    assessed_identity: str
    suspected_apt: str | None = None
    assessed_intent: str
    severity: str       # critical | high | medium | low
    confidence: str     # confirmed | high | moderate | low | speculative
    ttps: list[TTP] = []
    surface_zones: list[str] = []
    segments: list[str] = []
    claims: list[CorroboratedClaim] = []
    evidence: list[Finding] = []
    summary: str = ""
    model: str = ""


class OrgThreatAssessment(BaseModel):
    """Leadership-facing, organization-wide strategic threat picture."""
    id: str
    generated_at: float
    adversary_landscape: str = ""
    surface_pressure: dict = Field(default_factory=dict)
    sector_pressure: dict = Field(default_factory=dict)
    strategic_intent: str = ""
    top_campaigns: list[dict] = []
    source_profile_ids: list[str] = []
    confidence: str = "speculative"
    evidence: list[Finding] = []
    summary: str = ""
    model: str = ""


class Rollup(BaseModel):
    """Aggregated view for sector / org / network-surface rollups."""
    dimension: str        # sector | org | network
    buckets: list[dict]   # [{label, count, severity_weighted_score}]
