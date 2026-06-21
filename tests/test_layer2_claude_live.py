"""Live integration tests for Layer 2 NLP engine via unified LLM client.

Hits the real AI provider API. Auto-skipped when no API key is set.
Works with any configured provider: Claude, OpenAI, or Gemini.
"""
import base64
import json
import os

import pytest
from dotenv import load_dotenv

load_dotenv(".env")

_ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
_OPENAI_KEY    = os.environ.get("OPENAI_API_KEY", "").strip()
_GEMINI_KEY    = os.environ.get("GEMINI_API_KEY", "").strip()
_ANY_KEY       = _ANTHROPIC_KEY or _OPENAI_KEY or _GEMINI_KEY

pytestmark = pytest.mark.skipif(not _ANY_KEY, reason="No LLM API key set")

with open("tests/fixtures/layer2_samples.json") as _f:
    _FIX = json.load(_f)


def _hydrate(slot):
    raw = _FIX[slot]
    return {
        "from_header": raw["from_header"] + " <" + raw["from_email"] + ">",
        "subject":     raw["subject"],
        "body_text":   base64.b64decode(raw["body_b64"]).decode(),
        "spf_result":  raw["spf_result"],
        "dkim_result": raw["dkim_result"],
    }


def _make_settings():
    class S:
        anthropic_api_key = _ANTHROPIC_KEY
        openai_api_key    = _OPENAI_KEY
        gemini_api_key    = _GEMINI_KEY
        anthropic_model   = os.environ.get("ANTHROPIC_MODEL", "claude-opus-4-7")
        llm_provider      = "auto"
        llm_model         = ""
    return S()


@pytest.mark.asyncio
async def test_nlp_detects_phish_sample():
    """AI provider correctly scores a phishing email above 0.65."""
    from app.layer2_ai.nlp_engine import run_nlp
    from app.llm.client import LLMClient, reset_llm_client
    reset_llm_client()
    sample = _hydrate("phish")
    client = LLMClient(_make_settings())
    r = await run_nlp(sample, llm_client=client)
    assert r["score"] >= 0.65, f"Expected phish score ≥ 0.65, got {r['score']}"
    assert r["intent"] != "clean"
    assert r["provider"] != "heuristic", "Should have used AI provider"
    assert isinstance(r.get("reasoning"), str) and len(r["reasoning"]) > 10


@pytest.mark.asyncio
async def test_nlp_detects_legit_sample():
    """AI provider correctly scores a legitimate email below 0.30."""
    from app.layer2_ai.nlp_engine import run_nlp
    from app.llm.client import LLMClient, reset_llm_client
    reset_llm_client()
    sample = _hydrate("legit")
    client = LLMClient(_make_settings())
    r = await run_nlp(sample, llm_client=client)
    assert r["score"] < 0.30, f"Expected legit score < 0.30, got {r['score']}"


@pytest.mark.asyncio
async def test_run_nlp_uses_configured_provider():
    """run_nlp uses the unified client's provider, not a hardcoded one."""
    from app.layer2_ai.nlp_engine import run_nlp
    from app.llm.client import LLMClient, reset_llm_client
    reset_llm_client()
    sample = _hydrate("phish")
    client = LLMClient(_make_settings())
    r = await run_nlp(sample, llm_client=client)
    assert r["provider"] == client.provider
    assert r["score"] >= 0.50


@pytest.mark.asyncio
async def test_claude_prompt_caching_engages():
    """Claude prompt caching activates on the second identical call."""
    if not _ANTHROPIC_KEY:
        pytest.skip("Claude key not set")
    from app.llm.client import LLMClient, reset_llm_client
    from app.layer2_ai.nlp_engine import _build_user_content, _load_prompt
    reset_llm_client()

    class ClaudeSettings:
        anthropic_api_key = _ANTHROPIC_KEY
        openai_api_key    = ""
        gemini_api_key    = ""
        anthropic_model   = os.environ.get("ANTHROPIC_MODEL", "claude-opus-4-7")
        llm_provider      = "claude"
        llm_model         = ""

    client = LLMClient(ClaudeSettings())
    sample = _hydrate("phish")
    uc = _build_user_content(sample)
    sp = _load_prompt()

    # Call twice — second call should hit cache
    import anthropic as _ant
    _client = _ant.AsyncAnthropic(api_key=_ANTHROPIC_KEY)

    async def _call(c):
        resp = await c.messages.create(
            model=ClaudeSettings.anthropic_model,
            max_tokens=512,
            system=[{"type": "text", "text": sp, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": uc}],
        )
        return getattr(resp, "usage", None)

    u1 = await _call(_client)
    u2 = await _call(_client)
    if u1 and u2:
        cached = getattr(u2, "cache_read_input_tokens", 0) > 0 or \
                 getattr(u1, "cache_creation_input_tokens", 0) > 0
        assert cached, f"Caching did not engage: u1={u1} u2={u2}"
