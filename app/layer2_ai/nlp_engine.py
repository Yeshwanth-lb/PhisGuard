"""Engine 2 — NLP Intent Analyst.

Uses the unified LLMClient — works with Claude, OpenAI, Gemini, or the
built-in heuristic fallback (zero API key required).

Provider is selected once at startup via LLM_PROVIDER env var (or auto-detected
from whichever API key is set). The NLP engine does not care which provider
is underneath — it just calls client.complete().
"""
import json

import structlog

from app.llm.client import LLMClient

logger = structlog.get_logger()

_PROMPT_PATH_V2 = "app/layer2_ai/prompts/nlp_system_prompt_v2.txt"
_PROMPT_PATH_V1 = "app/layer2_ai/prompts/nlp_system_prompt_v1.txt"


def _load_prompt() -> str:
    for path in (_PROMPT_PATH_V2, _PROMPT_PATH_V1):
        try:
            with open(path) as f:
                return f.read()
        except FileNotFoundError:
            continue
    return (
        "You are a phishing detection AI. Analyze the email and return JSON with:\n"
        "phishing_score (0.0-1.0), intent (string), tactics (list), reasoning (string)."
    )


def _build_user_content(parsed: dict) -> str:
    subject = parsed.get("subject", "") or ""
    body = (parsed.get("body_text", "") or "")[:3000]
    fh = parsed.get("from_header", "") or ""
    spf_v = parsed.get("spf_result", "unknown")
    dkim_v = parsed.get("dkim_result", "unknown")
    return "\n".join([
        "From: " + fh,
        "Subject: " + subject,
        "SPF: " + str(spf_v) + "  DKIM: " + str(dkim_v),
        "",
        "Body:",
        body,
    ])


def _parse_response(raw: str) -> dict:
    text = raw.strip()
    if "```" in text:
        text = text.split("```")[1].lstrip("json").strip()
    if not text.startswith("{"):
        i = text.find("{")
        j = text.rfind("}")
        if i >= 0 and j > i:
            text = text[i: j + 1]
    data = json.loads(text)
    score = float(data.get("phishing_score", data.get("score", 0.0)))
    return {
        "engine": "nlp",
        "score": min(max(score, 0.0), 1.0),
        "intent": data.get("intent", "unknown"),
        "tactics": data.get("tactics", []),
        "reasoning": data.get("reasoning", ""),
    }


def _heuristic_nlp(text: str) -> dict:
    """Rule-based fallback — no API key needed. Always available."""
    t = text.lower()
    score = 0.0
    tactics = []

    urgency_words = [
        "urgent", "immediately", "act now", "within 24 hours", "account suspended",
        "verify now", "limited time", "expires today", "last chance", "final notice",
        "action required", "respond immediately", "failure to respond", "warning",
    ]
    hits = sum(1 for w in urgency_words if w in t)
    if hits >= 3:
        score += 0.35; tactics.append("urgency")
    elif hits >= 1:
        score += 0.15; tactics.append("urgency")

    cred_words = [
        "verify your account", "confirm your password", "enter your password",
        "update your credentials", "sign in to confirm", "re-enter your",
        "validate your", "your account has been", "unusual activity",
        "suspicious login", "security alert", "click here to verify",
    ]
    hits = sum(1 for w in cred_words if w in t)
    if hits >= 2:
        score += 0.40; tactics.append("credential_harvesting")
    elif hits >= 1:
        score += 0.20; tactics.append("credential_harvesting")

    bec_words = [
        "wire transfer", "bank transfer", "send funds", "transfer funds",
        "gift card", "purchase gift cards", "redemption code",
        "routing number", "new banking details", "updated payment", "change of account",
    ]
    hits = sum(1 for w in bec_words if w in t)
    if hits >= 2:
        score += 0.45; tactics.append("bec_fraud")
    elif hits >= 1:
        score += 0.25; tactics.append("bec_fraud")

    exec_words = [
        "ceo", "cfo", "chief executive", "chief financial", "president",
        "board of directors", "strictly confidential", "do not discuss",
    ]
    if sum(1 for w in exec_words if w in t) >= 1:
        score += 0.20; tactics.append("executive_impersonation")

    brands = [
        "paypal", "microsoft", "apple", "amazon", "google", "netflix",
        "bank of america", "wells fargo", "chase bank", "irs", "fedex",
        "dhl", "usps", "dropbox", "docusign", "office 365",
    ]
    if sum(1 for b in brands if b in t) >= 1:
        score += 0.15; tactics.append("brand_impersonation")

    link_words = ["click here", "click the link", "click below", "login here", "verify here"]
    hits = sum(1 for w in link_words if w in t)
    if hits >= 2:
        score += 0.20; tactics.append("suspicious_links")
    elif hits >= 1:
        score += 0.10; tactics.append("suspicious_links")

    pii_words = [
        "social security", "ssn", "date of birth", "credit card",
        "card number", "cvv", "pin number", "passport",
    ]
    if sum(1 for w in pii_words if w in t) >= 1:
        score += 0.30; tactics.append("pii_request")

    score = round(min(score, 1.0), 4)

    if "bec_fraud" in tactics:
        intent = "bec"
    elif "credential_harvesting" in tactics or "pii_request" in tactics:
        intent = "credential_harvesting"
    elif score > 0.3:
        intent = "generic_phish"
    else:
        intent = "clean"

    return {
        "engine": "nlp",
        "score": score,
        "intent": intent,
        "tactics": tactics,
        "reasoning": f"Heuristic — tactics: {', '.join(tactics) or 'none'}",
        "provider": "heuristic",
    }


async def run_nlp(
    parsed: dict,
    # Legacy keyword args kept for backward compatibility with orchestrator.py
    openai_api_key: str = "",
    anthropic_api_key: str = "",
    gemini_api_key: str = "",
    anthropic_model: str = "",
    anthropic_max_tokens: int = 1024,
    llm_client: LLMClient = None,
    settings=None,
) -> dict:
    """Run NLP intent analysis via the unified LLM client.

    Provider selection order (first match wins):
      1. Explicit LLM_PROVIDER env var / settings.llm_provider
      2. Auto-detect from available API keys: Claude → OpenAI → Gemini
      3. Built-in heuristic (no API key required)
    """
    user_content = _build_user_content(parsed)
    system_prompt = _load_prompt()

    # Build a temporary client from legacy kwargs if no unified client passed.
    # This keeps the orchestrator.py call signature working without changes.
    if llm_client is None:
        class _TempSettings:
            pass
        s = _TempSettings()
        s.anthropic_api_key = anthropic_api_key
        s.openai_api_key = openai_api_key
        s.gemini_api_key = gemini_api_key
        s.anthropic_model = anthropic_model or "claude-opus-4-7"
        s.llm_provider = getattr(settings, "llm_provider", "auto") if settings else "auto"
        s.llm_model = getattr(settings, "llm_model", "") if settings else ""
        client = LLMClient(s)
    else:
        client = llm_client

    # Heuristic path — no network call
    if not client.is_ai_powered:
        result = _heuristic_nlp(user_content)
        logger.info("nlp_ok", provider="heuristic", score=result["score"])
        return result

    # AI path
    async def _one_call() -> dict | None:
        raw = await client.complete(system_prompt, user_content, max_tokens=anthropic_max_tokens)
        if not raw:
            return None
        try:
            r = _parse_response(raw)
            r["provider"] = client.provider
            r["model"] = client.model
            return r
        except Exception as exc:
            logger.warning("nlp_parse_failed", provider=client.provider, error=str(exc))
            return None

    n_samples = 1
    if settings is not None:
        n_samples = max(1, int(getattr(settings, "nlp_self_consistency_samples", 1) or 1))

    if n_samples <= 1:
        result = await _one_call()
        if result is None:
            logger.warning("nlp_ai_empty_response_using_heuristic", provider=client.provider)
            return _heuristic_nlp(user_content)
        logger.info("nlp_ok", provider=client.provider, score=result["score"])
        return result

    # Self-consistency: sample N times, take the MEDIAN-scored result. The median
    # sample is returned whole so intent/tactics/reasoning stay consistent with
    # the reported score. Reduces borderline flip-flop; distribution unchanged.
    import asyncio as _aio
    results = [r for r in await _aio.gather(*[_one_call() for _ in range(n_samples)]) if r is not None]
    if not results:
        logger.warning("nlp_ai_all_samples_failed_using_heuristic", provider=client.provider)
        return _heuristic_nlp(user_content)
    results.sort(key=lambda r: r.get("score", 0.0))
    median = results[len(results) // 2]
    scores = [round(r.get("score", 0.0), 3) for r in results]
    logger.info("nlp_ok", provider=client.provider, score=median["score"],
                self_consistency_n=len(results), sample_scores=scores)
    return median
