"""Engine 1 — Layer 2 AI Orchestrator.

Three-tier verdict logic (PRD Section 5.3.6), plus one NLP-specific rung:
  Tier 1:  ANY of structural/nlp ≥ SINGLE_ENGINE_THRESHOLD (0.90) → phishing
  Tier 2:  Weighted composite ≥ HIGH_CONF_THRESHOLD (0.70)        → phishing
  nlp_med: nlp alone ≥ NLP_MED_THRESHOLD (0.55)                   → suspicious
  Tier 3:  Weighted composite ≥ MED_CONF_THRESHOLD  (0.42)        → suspicious
  Fallback: below all thresholds                                  → clean

Why nlp_med exists: validated against 20 real-world phishing samples
(zefang-liu/phishing-email-dataset), old-style plain-text social-engineering
scams (fake loan approvals, lottery notices) carry no spoofed domain or brand
impersonation, so structural scores 0.0, and a first-contact sender means
behavioral sits at a flat cold-start value — leaving NLP as the only engine
that sees anything. Diluting a strong NLP read through the 0.30/0.50/0.20
composite was silently clearing 50% of those samples as clean (delivered with
no warning at all). nlp_med guarantees at least a "suspicious" hold whenever
NLP alone is moderately confident, regardless of composite dilution.

An earlier version of this also added an nlp_high rung (nlp ≥ 0.80 → straight
to phishing, skipping tier2). Reverted: real phishing samples needing that
rescue scored nlp=0.82, but the demo's own calibrated "suspicious" pool
(reward/delivery-scam lures, deliberately borderline) scored nlp 0.82-0.90 on
a live rerun — Claude's NLP score alone cannot reliably separate "genuinely
ambiguous, review-worthy" content from "confirmed fraud" in that band, so an
instant single-engine phishing verdict off NLP alone below the 0.90 tier-1 bar
is not safe. nlp_med (suspicious, not phishing) is the correct ceiling for
NLP-only evidence short of 0.90. Validated: 12/12 real safe emails stayed
clean (NLP scored 0.03-0.15) — comfortably below 0.55.
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
HIGH_CONF_THRESHOLD     = 0.70   # Tier 2: composite score → phishing (raised from 0.62 — borderline domain-age signals were escalating suspicious → phishing)
MED_CONF_THRESHOLD      = 0.42   # Tier 3: composite score → suspicious
NLP_MED_THRESHOLD       = 0.55   # nlp_med: nlp alone is moderately confident → suspicious, even if composite would clear as clean
SE_MED_THRESHOLD        = 0.45   # struct_socialeng: scam-language alone → suspicious (419/lottery/loan/BEC with a clean domain that composite would dilute to clean)


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

    # Tier 1 override is restricted to structural/nlp — deterministic and semantic
    # checks. behavioral is excluded: its per-sender Gaussian score can saturate to
    # 1.0 purely from a thin/near-uniform baseline (variance collapse on repeated
    # near-identical mail), which would let one noisy statistical signal override
    # two engines that both call the mail clean. behavioral still fully counts
    # toward the weighted composite (tier2/tier3) below.
    tier1_candidates = {k: v for k, v in scores.items() if k != "behavioral"}
    tier1_engine = max(tier1_candidates, key=tier1_candidates.get)
    tier1_score  = tier1_candidates[tier1_engine]

    nlp_score = scores.get("nlp", 0.0)
    se_score = (details.get("structural", {}) or {}).get("social_engineering_score", 0.0)

    if tier1_score >= SINGLE_ENGINE_THRESHOLD:
        # Tier 1: one engine has overwhelming evidence
        verdict       = "phishing"
        triggered_tier = "tier1"
        triggered_by   = tier1_engine
    elif weighted >= HIGH_CONF_THRESHOLD:
        # Tier 2: cumulative evidence
        verdict       = "phishing"
        triggered_tier = "tier2"
        triggered_by   = "composite"
    elif nlp_score >= NLP_MED_THRESHOLD:
        # nlp_med: Claude alone is moderately confident — hold for review even
        # if structural/behavioral would otherwise dilute this to clean.
        verdict       = "suspicious"
        triggered_tier = "nlp_med"
        triggered_by   = "nlp"
    elif se_score >= SE_MED_THRESHOLD:
        # struct_socialeng: scam-language patterns (419/lottery/loan/BEC) present
        # even though the sender domain is clean and NLP under-read — the exact
        # plain-text-scam profile that was slipping through as clean. Hold for review.
        verdict       = "suspicious"
        triggered_tier = "struct_socialeng"
        triggered_by   = "structural"
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

    # Only tier1 reports its raw triggering score — that verdict is already
    # "phishing", and the pipeline's downstream floor logic clamps a phishing
    # verdict's blended confidence to >=0.65 regardless of the input value.
    # nlp_med's verdict is "suspicious": reporting nlp_score (which can be as
    # high as 0.89) instead of the diluted composite would feed an inflated
    # base_conf into the pipeline's L2+L5 blend, pushing the suspicious floor
    # past the phishing cutoff and silently escalating the verdict downstream.
    if triggered_tier == "tier1":
        confidence = tier1_score
    else:
        confidence = weighted

    return {
        "verdict":        verdict,
        "confidence":     round(confidence, 3),
        "triggered_tier": triggered_tier,
        "triggered_by":   triggered_by,
        "engine_scores":  scores,
        "engines":        details,
        "llm_provider":   llm_client.provider,
    }
