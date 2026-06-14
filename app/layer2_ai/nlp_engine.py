"""Engine 2 - NLP Intent Analyst (Claude via LangChain)."""
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


async def run_nlp(parsed: dict, openai_api_key: str = "", anthropic_api_key: str = "") -> dict:
    """Engine 2: NLP Intent Analyst. Uses Claude if key present, else OpenAI."""
    api_key = anthropic_api_key or openai_api_key
    if not api_key:
        return _DEFAULT_RESULT
    subject = parsed.get("subject", "") or ""
    body = (parsed.get("body_text", "") or "")[:3000]
    fh = parsed.get("from_header", "") or ""
    spf_v = parsed.get("spf_result", "unknown")
    dkim_v = parsed.get("dkim_result", "unknown")
    user_content = f"From: {fh}\nSubject: {subject}\nSPF: {spf_v}  DKIM: {dkim_v}\n\nBody:\n{body}"
    system_prompt = _load_prompt()
    try:
        from langchain_core.messages import SystemMessage, HumanMessage
        if anthropic_api_key:
            from langchain_anthropic import ChatAnthropic  # type: ignore
            llm = ChatAnthropic(model="claude-3-5-haiku-20241022", temperature=0, max_tokens=512, api_key=anthropic_api_key)
        else:
            from langchain_openai import ChatOpenAI  # type: ignore
            llm = ChatOpenAI(model="gpt-4o", temperature=0, max_tokens=512, api_key=openai_api_key)
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
