from __future__ import annotations
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum
import uuid
from datetime import datetime


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
    sender_ip: Optional[str] = None
    sender_domain: Optional[str] = None
    sender_email: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    urls: List[str] = Field(default_factory=list)
    attachment_hashes: List[Dict[str, str]] = Field(default_factory=list)
    headers: Dict[str, Any] = Field(default_factory=dict)
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    send_timestamp: Optional[datetime] = None
    raw_email: Optional[bytes] = None


class NLPResult(BaseModel):
    intent_score: float = 0.5
    detected_patterns: List[str] = Field(default_factory=list)
    primary_intent: str = "clean"
    confidence: float = 0.0
    explanation: str = ""
    duration_ms: int = 0
    status: str = "ok"


class BehavioralResult(BaseModel):
    anomaly_score: float = 0.5
    baseline_confidence: BaselineConfidence = BaselineConfidence.none
    cold_start_tier: int = 0
    deviation_dimensions: Dict[str, float] = Field(default_factory=dict)
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
    red_flags: List[StructuralFlag] = Field(default_factory=list)
    domain_age_days: Optional[int] = None
    auth_alignment: str = "unknown"
    attachment_risk: str = "none"
    duration_ms: int = 0
    status: str = "ok"


class Layer2Result(BaseModel):
    verdict: Layer2Verdict = Layer2Verdict.deliver
    triggered_tier: TriggeredTier = TriggeredTier.fallback
    triggered_engine: Optional[str] = None
    composite_score: float = 0.0
    weights_used: Dict[str, float] = Field(default_factory=dict)
    engine2_nlp: Optional[NLPResult] = None
    engine3_behavioral: Optional[BehavioralResult] = None
    engine4_structural: Optional[StructuralResult] = None
    total_duration_ms: int = 0


class MISPExport(BaseModel):
    exported: bool = False
    misp_event_id: Optional[str] = None
    misp_event_uuid: Optional[str] = None
    misp_event_url: Optional[str] = None
    attributes_exported: List[Dict[str, str]] = Field(default_factory=list)
    threat_level: Optional[str] = None
    tlp: str = "TLP:AMBER"
    tags: List[str] = Field(default_factory=list)
    exported_at: Optional[datetime] = None
    export_status: str = "not_applicable"
    opencti_synced: bool = False


class PipelineEvent(BaseModel):
    email_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ingestion_source: str = "rest_api"
    sender_ip: Optional[str] = None
    sender_domain: Optional[str] = None
    subject: Optional[str] = None
    recipient: Optional[str] = None
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    layer1_verdict: Optional[Layer1Verdict] = None
    layer1_flags: List[str] = Field(default_factory=list)
    layer1_misp_hit: bool = False
    layer1_misp_event_id: Optional[str] = None
    layer2_verdict: Optional[Layer2Verdict] = None
    layer2_result: Optional[Layer2Result] = None
    layer2_composite_score: float = 0.0
    layer2_triggered_tier: Optional[TriggeredTier] = None
    layer2_nlp_intent_score: float = 0.0
    layer2_nlp_primary_intent: Optional[str] = None
    layer2_behavioral_anomaly_score: float = 0.0
    layer2_behavioral_dominant_deviation: Optional[str] = None
    layer2_behavioral_cold_start_tier: int = 0
    layer2_structural_score: float = 0.0
    layer2_structural_red_flags: List[str] = Field(default_factory=list)
    layer3_verdict: Optional[Layer3Verdict] = None
    layer3_redirect_chain: List[str] = Field(default_factory=list)
    layer3_final_url: Optional[str] = None
    layer3_ocr_flags: List[str] = Field(default_factory=list)
    layer3_screenshot_path: Optional[str] = None
    final_verdict: Optional[Verdict] = None
    misp_export: Optional[MISPExport] = None
    processing_time_ms: int = 0


class AnalyzeResponse(BaseModel):
    email_id: str
    verdict: Verdict
    confidence: float
    route: str
    threat_summary: str
    misp_event_id: Optional[str] = None
    processing_time_ms: int
