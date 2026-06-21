from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    delivered = "delivered"
    quarantined = "quarantined"


class Layer1Verdict(str, Enum):
    clean = "clean"
    quarantine = "quarantine"


class Layer2Verdict(str, Enum):
    sandbox = "sandbox"
    deliver = "deliver"
    skipped = "skipped"


class Layer3Verdict(str, Enum):
    clean = "clean"
    malicious = "malicious"
    inconclusive = "inconclusive"
    skipped = "skipped"


class TriggeredTier(str, Enum):
    tier1 = "tier1"
    tier2 = "tier2"
    tier3 = "tier3"
    fallback = "fallback"
    skipped = "skipped"


class BaselineConfidence(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"
    none = "none"


class EmailContext(BaseModel):
    email_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sender_ip: str | None = None
    sender_domain: str | None = None
    sender_email: str | None = None
    recipient: str | None = None
    subject: str | None = None
    body_text: str | None = None
    body_html: str | None = None
    urls: list[str] = Field(default_factory=list)
    attachment_hashes: list[dict[str, str]] = Field(default_factory=list)
    headers: dict[str, Any] = Field(default_factory=dict)
    spf_result: str | None = None
    dkim_result: str | None = None
    dmarc_result: str | None = None
    send_timestamp: datetime | None = None
    raw_email: bytes | None = None


class NLPResult(BaseModel):
    intent_score: float = 0.5
    detected_patterns: list[str] = Field(default_factory=list)
    primary_intent: str = "clean"
    confidence: float = 0.0
    explanation: str = ""
    duration_ms: int = 0
    status: str = "ok"


class BehavioralResult(BaseModel):
    anomaly_score: float = 0.5
    baseline_confidence: BaselineConfidence = BaselineConfidence.none
    cold_start_tier: int = 0
    deviation_dimensions: dict[str, float] = Field(default_factory=dict)
    dominant_deviation: str = "none"
    emails_in_baseline: int = 0
    duration_ms: int = 0
    status: str = "ok"


class StructuralFlag(BaseModel):
    flag: str
    severity: str
    detail: str = ""


class StructuralResult(BaseModel):
    structural_score: float = 0.0
    red_flags: list[StructuralFlag] = Field(default_factory=list)
    domain_age_days: int | None = None
    auth_alignment: str = "unknown"
    attachment_risk: str = "none"
    duration_ms: int = 0
    status: str = "ok"


class Layer2Result(BaseModel):
    verdict: Layer2Verdict = Layer2Verdict.deliver
    triggered_tier: TriggeredTier = TriggeredTier.fallback
    triggered_engine: str | None = None
    composite_score: float = 0.0
    weights_used: dict[str, float] = Field(default_factory=dict)
    engine2_nlp: NLPResult | None = None
    engine3_behavioral: BehavioralResult | None = None
    engine4_structural: StructuralResult | None = None
    total_duration_ms: int = 0


class MISPExport(BaseModel):
    exported: bool = False
    misp_event_id: str | None = None
    misp_event_uuid: str | None = None
    misp_event_url: str | None = None
    attributes_exported: list[dict[str, str]] = Field(default_factory=list)
    threat_level: str | None = None
    tlp: str = "TLP:AMBER"
    tags: list[str] = Field(default_factory=list)
    exported_at: datetime | None = None
    export_status: str = "not_applicable"
    opencti_synced: bool = False


class PipelineEvent(BaseModel):
    email_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ingestion_source: str = "rest_api"
    sender_ip: str | None = None
    sender_domain: str | None = None
    subject: str | None = None
    recipient: str | None = None
    spf_result: str | None = None
    dkim_result: str | None = None
    dmarc_result: str | None = None
    layer1_verdict: Layer1Verdict | None = None
    layer1_flags: list[str] = Field(default_factory=list)
    layer1_misp_hit: bool = False
    layer1_misp_event_id: str | None = None
    layer2_verdict: Layer2Verdict | None = None
    layer2_result: Layer2Result | None = None
    layer2_composite_score: float = 0.0
    layer2_triggered_tier: TriggeredTier | None = None
    layer2_nlp_intent_score: float = 0.0
    layer2_nlp_primary_intent: str | None = None
    layer2_behavioral_anomaly_score: float = 0.0
    layer2_behavioral_dominant_deviation: str | None = None
    layer2_behavioral_cold_start_tier: int = 0
    layer2_structural_score: float = 0.0
    layer2_structural_red_flags: list[str] = Field(default_factory=list)
    layer3_verdict: Layer3Verdict | None = None
    layer3_redirect_chain: list[str] = Field(default_factory=list)
    layer3_final_url: str | None = None
    layer3_ocr_flags: list[str] = Field(default_factory=list)
    layer3_screenshot_path: str | None = None
    final_verdict: Verdict | None = None
    misp_export: MISPExport | None = None
    processing_time_ms: int = 0


class AnalyzeResponse(BaseModel):
    email_id: str
    verdict: Verdict
    confidence: float
    route: str
    threat_summary: str
    misp_event_id: str | None = None
    processing_time_ms: int
