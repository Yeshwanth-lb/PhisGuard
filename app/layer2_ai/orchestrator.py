"""Engine 1 — Layer 2 AI Orchestrator.

Three-tier verdict logic (PRD Section 5.3.6):
  Tier 1: ANY single engine ≥ SINGLE_ENGINE_THRESHOLD (0.90) → phishing
  Tier 2: Weighted composite ≥ HIGH_CONF_THRESHOLD (0.55)    → phishing
  Tier 3: Weighted composite ≥ MED_CONF_THRESHOLD  (0.40)    → suspicious
  Fallback: below all thresholds                              → clean
"""
import asyncio

import structlog

from app.layer2_ai.behavioral import run_behavioral
from app.layer2_ai.nlp_engine import run_nlp
from app.layer2_ai.structural import run_structural
from app.llm.client import LLMClient

logger = structlog.get_logger()

WEIGHTS = {
    "structural": 0.30,
    "nlp":        0.50,
    "behavioral": 0.20,
}

SINGLE_ENGINE_THRESHOLD = 0.90   # Tier 1: one engine is overwhelming → phishing
HIGH_CONF_THRESHOLD     = 0.62   # Tier 2: composite score → phishing (raised from 0.55 to reduce false positives on marketing emails)
MED_CONF_THRESHOLD      = 0.42   # Tier 3: composite score → suspicious


async def run_layer2(parsed: dict, settings) -> dict:
    """Run all 3 AI engines concurrently, apply three-tier verdict logic."""

    # Build one shared LLM client for this request
    llm_client = LLMClient(settings)

    results = await asyncio.gather(
        run_structural(parsed),
        run_nlp(
            parsed,
            llm_client=llm_client,
            anthropic_max_tokens=getattr(settings, "anthropic_max_tokens", 1024),
        ),
        run_behavioral(parsed, settings=settings),
        return_exceptions=True,
    )

    engine_names = ["structural", "nlp", "behavioral"]
    scores:  dict = {}
    details: dict = {}

    for result, name in zip(results, engine_names):
        if isinstance(result, Exception):
            logger.warning("l2_engine_error", engine=name, error=str(result))
            scores[name]  = 0.0
            details[name] = {"engine": name, "score": 0.0, "status": "error"}
        else:
            scores[name]  = result.get("score", 0.0)
            details[name] = result

    weighted = sum(scores[k] * WEIGHTS[k] for k in WEIGHTS)

    # --- Three-tier verdict ---
    top_engine = max(scores, key=scores.get)
    top_score  = scores[top_engine]

    if top_score >= SINGLE_ENGINE_THRESHOLD:
        # Tier 1: one engine has overwhelming evidence
        verdict       = "phishing"
        triggered_tier = "tier1"
        triggered_by   = top_engine
    elif weighted >= HIGH_CONF_THRESHOLD:
        # Tier 2: cumulative evidence
        verdict       = "phishing"
        triggered_tier = "tier2"
        triggered_by   = "composite"
    elif weighted >= MED_CONF_THRESHOLD:
        # Tier 3: moderate suspicion
        verdict       = "suspicious"
        triggered_tier = "tier3"
        triggered_by   = "composite"
    else:
        verdict       = "clean"
        triggered_tier = "fallback"
        triggered_by   = None

    logger.info(
        "l2_verdict",
        verdict=verdict,
        confidence=round(weighted, 3),
        tier=triggered_tier,
        triggered_by=triggered_by,
        top_engine=top_engine,
        top_score=round(top_score, 3),
        provider=llm_client.provider,
    )

    return {
        "verdict":        verdict,
        "confidence":     round(weighted, 3),
        "triggered_tier": triggered_tier,
        "triggered_by":   triggered_by,
        "engine_scores":  scores,
        "engines":        details,
        "llm_provider":   llm_client.provider,
    }
