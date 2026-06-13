"""Engine 1 - Layer 2 AI Orchestrator."""
import asyncio
import structlog
from app.layer2_ai.structural import run_structural
from app.layer2_ai.nlp_engine import run_nlp
from app.layer2_ai.behavioral import run_behavioral

logger = structlog.get_logger()

WEIGHTS = {
    "structural": 0.30,
    "nlp":        0.50,
    "behavioral": 0.20,
}

HIGH_CONF_THRESHOLD = 0.65
MED_CONF_THRESHOLD = 0.40


async def run_layer2(parsed: dict, settings) -> dict:
    """Run all 3 AI engines concurrently, produce weighted verdict."""
    results = await asyncio.gather(
        run_structural(parsed),
        run_nlp(parsed, settings.openai_api_key),
        run_behavioral(parsed),
        return_exceptions=True,
    )
    engine_names = ["structural", "nlp", "behavioral"]
    scores: dict = {}; details: dict = {}
    for result, name in zip(results, engine_names):
        if isinstance(result, Exception):
            logger.warning("l2_engine_error", engine=name, error=str(result))
            scores[name] = 0.0
            details[name] = {"engine": name, "score": 0.0}
        else:
            scores[name] = result.get("score", 0.0)
            details[name] = result
    weighted = sum(scores[k] * WEIGHTS[k] for k in WEIGHTS)
    if weighted >= HIGH_CONF_THRESHOLD:
        verdict = "phishing"
    elif weighted >= MED_CONF_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "clean"
    logger.info("l2_verdict", verdict=verdict, confidence=round(weighted, 3))
    return {
        "verdict": verdict,
        "confidence": round(weighted, 3),
        "engine_scores": scores,
        "engines": details,
    }
