"""Engine 2 - NLP Intent Analyst (GPT-4 via LangChain)."""
import json
import structlog

logger = structlog.get_logger()
_PROMPT_PATH = "app/layer2_ai/prompts/nlp_system_prompt_v1.txt"

_DEFAULT_RESULT = {
    "engine": "nlp",
    "score": 0.0,
    "intent": "unknown",
    "tactics": [],
    "reasoning": "NLP engine not configured",
}

def _load_prompt() -> str:
    try:
        with open(_PROMPT_PATH) as f:
            return f.read()
    except Exception:
        return "Analyze the email. Return JSON with phishing_score (0.0-1.0)."


async def run_nlp(parsed: dict, openai_api_key: str) -> dict:
    """Engine 2: NLP Intent Analyst."""
    if not openai_api_key:
        return _DEFAULT_RESULT
    try:
        from langchain_openai import ChatOpenAI
        from langchain_core.messages import SystemMessage, HumanMessage
    except ImportError:
        logger.warning("langchain_not_installed")
        return _DEFAULT_RESULT
    subject = parsed.get("subject", "") or ""
    body = (parsed.get("body_text", "") or "")[:3000]
    from_hdr = parsed.get("from_header", "") or ""
    spf_v = parsed.get("spf_result", "unknown")
    dkim_v = parsed.get("dkim_result", "unknown")
    user_content = (
        f"From: {from_hdr}\n"
        f"Subject: {subject}\n"
        f"SPF: {spf_v}  DKIM: {dkim_v}\n\n"
        f"Body:\n{body}"
    )
    system_prompt = _load_prompt()
    try:
        cfg = dict(model="gpt-4o", temperature=0, max_tokens=512)
        cfg["api_key"] = openai_api_key
        llm = ChatOpenAI(**cfg)
        msgs = [SystemMessage(content=system_prompt), HumanMessage(content=user_content)]
        response = await llm.ainvoke(msgs)
        raw = response.content.strip()
        if "```" in raw:
            raw = raw.split("```")[1].lstrip("json").strip()
        data = json.loads(raw)
        score = float(data.get("phishing_score", data.get("score", 0.0)))
        return {
            "engine": "nlp",
            "score": min(max(score, 0.0), 1.0),
            "intent": data.get("intent", "unknown"),
            "tactics": data.get("tactics", []),
            "reasoning": data.get("reasoning", ""),
        }
    except Exception as exc:
        logger.warning("nlp_engine_error", error=str(exc))
        return dict(_DEFAULT_RESULT, reasoning=str(exc))
