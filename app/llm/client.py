"""Unified LLM client — one interface, any provider.

Configure via .env:
    LLM_PROVIDER=claude        # claude | openai | gemini | heuristic | auto
    LLM_MODEL=claude-opus-4-7  # optional; sensible defaults per provider
    ANTHROPIC_API_KEY=sk-ant-...
    OPENAI_API_KEY=sk-...
    GEMINI_API_KEY=AIza...

With LLM_PROVIDER=auto (default), the system picks the first provider
that has an API key configured:  claude → openai → gemini → heuristic

The heuristic provider requires NO API key and uses keyword matching.
It's always available as a final fallback.
"""
import os

import structlog

logger = structlog.get_logger()

# Singleton — one client per process
_client_instance = None


# ---------------------------------------------------------------------------
# Provider implementations
# ---------------------------------------------------------------------------

async def _call_claude(
    system: str, user: str,
    api_key: str, model: str, max_tokens: int,
) -> str:
    import anthropic
    client = anthropic.AsyncAnthropic(api_key=api_key)
    # NOTE: temperature is intentionally left at the API default (1.0), NOT pinned
    # to 0. Pinning to 0 was tried and REVERTED: greedy decoding scores subtle
    # threats (BEC wire-fraud, docusign lures) systematically lower, dropping real
    # phishing to "clean" because the L2 thresholds were calibrated against the
    # temp=1 distribution. Making this deterministic safely requires re-fitting
    # HIGH_CONF/MED_CONF/NLP_MED thresholds against a held-out labeled eval set
    # (see the modern-eval-set work) — it is not a standalone one-liner.
    response = await client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=[{
            "type": "text",
            "text": system,
            "cache_control": {"type": "ephemeral"},  # 90% cost reduction on repeat calls
        }],
        messages=[{"role": "user", "content": user}],
    )
    return response.content[0].text


async def _call_openai(
    system: str, user: str,
    api_key: str, model: str, max_tokens: int,
) -> str:
    from openai import AsyncOpenAI
    client = AsyncOpenAI(api_key=api_key)
    response = await client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        temperature=0,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    return response.choices[0].message.content


async def _call_gemini(
    system: str, user: str,
    api_key: str, model: str, max_tokens: int,
) -> str:
    from google import genai
    from google.genai import types
    client = genai.Client(api_key=api_key, http_options={"api_version": "v1"})
    full_prompt = system + "\n\n" + user
    resp = await client.aio.models.generate_content(
        model=model,
        contents=full_prompt,
        config=types.GenerateContentConfig(temperature=0, max_output_tokens=max_tokens),
    )
    return resp.text.strip()


# ---------------------------------------------------------------------------
# Default models per provider
# ---------------------------------------------------------------------------

_DEFAULT_MODELS = {
    "claude":    "claude-opus-4-7",
    "openai":    "gpt-4o",
    "gemini":    "gemini-2.0-flash",
    "heuristic": "none",
}


# ---------------------------------------------------------------------------
# Unified client
# ---------------------------------------------------------------------------

class LLMClient:
    """Single LLM interface used by every layer that needs AI inference.

    Usage:
        client = LLMClient(settings)
        text = await client.complete(system_prompt, user_prompt)
        # or with metadata:
        result = await client.complete_with_meta(system_prompt, user_prompt)
    """

    def __init__(self, settings=None):
        self.provider, self.api_key, self.model = self._resolve(settings)
        logger.info("llm_client_init", provider=self.provider, model=self.model)

    def _resolve(self, settings) -> tuple[str, str, str]:
        """Pick provider, api_key, model from settings or env vars."""
        # Explicit override takes priority
        explicit = (
            getattr(settings, "llm_provider", None)
            or os.environ.get("LLM_PROVIDER", "auto")
        ).lower().strip()

        explicit_model = (
            getattr(settings, "llm_model", None)
            or os.environ.get("LLM_MODEL", "")
        ).strip()

        # Key lookup helpers
        def _key(attr, env):
            return (getattr(settings, attr, None) or os.environ.get(env, "")).strip()

        keys = {
            "claude":  _key("anthropic_api_key", "ANTHROPIC_API_KEY"),
            "openai":  _key("openai_api_key",    "OPENAI_API_KEY"),
            "gemini":  _key("gemini_api_key",     "GEMINI_API_KEY"),
        }

        # Model overrides per provider from settings
        model_overrides = {
            "claude": _key("anthropic_model", "ANTHROPIC_MODEL") or _DEFAULT_MODELS["claude"],
            "openai": os.environ.get("OPENAI_MODEL", _DEFAULT_MODELS["openai"]),
            "gemini": os.environ.get("GEMINI_MODEL", _DEFAULT_MODELS["gemini"]),
        }

        if explicit == "heuristic":
            return "heuristic", "", "none"

        if explicit != "auto" and explicit in keys:
            # User explicitly chose a provider
            key = keys[explicit]
            if not key:
                logger.warning("llm_explicit_provider_no_key", provider=explicit)
            model = explicit_model or model_overrides.get(explicit, _DEFAULT_MODELS.get(explicit, ""))
            return explicit, key, model

        # Auto-detect: first provider with a key wins
        for provider in ("claude", "openai", "gemini"):
            if keys[provider]:
                model = explicit_model or model_overrides[provider]
                return provider, keys[provider], model

        # Nothing configured — use heuristic (zero API key)
        return "heuristic", "", "none"

    @property
    def is_ai_powered(self) -> bool:
        return self.provider != "heuristic"

    async def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 1024) -> str:
        """Call the configured LLM and return raw text. Never raises — returns empty string on error."""
        try:
            if self.provider == "claude":
                return await _call_claude(system_prompt, user_prompt, self.api_key, self.model, max_tokens)
            if self.provider == "openai":
                return await _call_openai(system_prompt, user_prompt, self.api_key, self.model, max_tokens)
            if self.provider == "gemini":
                return await _call_gemini(system_prompt, user_prompt, self.api_key, self.model, max_tokens)
        except Exception as exc:
            logger.warning("llm_call_failed", provider=self.provider, error=str(exc))
        return ""

    async def complete_with_meta(
        self, system_prompt: str, user_prompt: str, max_tokens: int = 1024
    ) -> dict:
        """Call LLM and return response + metadata (provider, model, success flag)."""
        text = await self.complete(system_prompt, user_prompt, max_tokens)
        return {
            "text": text,
            "provider": self.provider,
            "model": self.model,
            "success": bool(text),
        }


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

def get_llm_client(settings=None) -> LLMClient:
    """Return the process-wide LLM client (created once, reused)."""
    global _client_instance
    if _client_instance is None:
        _client_instance = LLMClient(settings)
    return _client_instance


def reset_llm_client():
    """Force recreation of the singleton (used in tests)."""
    global _client_instance
    _client_instance = None
