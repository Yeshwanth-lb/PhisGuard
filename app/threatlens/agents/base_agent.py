"""Abstract base agent for ThreatLens enrichment.

Every concrete agent:
  - Implements _run_impl(cluster) → list[Finding]
  - Gets timeout, isolation, and in-memory caching for free from this base
  - Declares required_keys; if any key is blank → returns [] (not_configured)
  - Must call sanitize_text() on any scraped content before passing to an LLM
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from abc import ABC, abstractmethod

import structlog

from app.threatlens.config import threatlens_settings
from app.threatlens.models import ActorCluster, Finding

logger = structlog.get_logger()

# Simple in-memory TTL cache: (agent_name, cluster_id) → (stored_at, findings)
_cache: dict[tuple[str, str], tuple[float, list[Finding]]] = {}


class BaseAgent(ABC):
    """Abstract enrichment agent.

    Subclasses must set `name` and optionally `required_keys`.
    """

    name: str = "base"
    required_keys: list[str] = []

    def __init__(self, timeout_secs: int | None = None):
        self._timeout = timeout_secs or threatlens_settings.intel_agent_timeout_secs
        self._cache_ttl = threatlens_settings.intel_cache_ttl_secs

    # ── Public entrypoint ────────────────────────────────────────────────────

    async def run(self, cluster: ActorCluster) -> list[Finding]:
        """Run the agent with timeout, isolation, and caching.

        Always returns a list (never raises). Returns [] on timeout, error,
        or missing required keys.
        """
        if not self._is_configured():
            logger.info("agent_not_configured", agent=self.name)
            return []

        cache_key = (self.name, cluster.id)
        cached = _cache.get(cache_key)
        if cached and (time.time() - cached[0]) < self._cache_ttl:
            logger.debug("agent_cache_hit", agent=self.name, cluster=cluster.id[:8])
            return cached[1]

        try:
            findings = await asyncio.wait_for(
                self._run_impl(cluster),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("agent_timeout", agent=self.name, cluster=cluster.id[:8])
            return []
        except Exception as exc:
            logger.warning("agent_error", agent=self.name, error=str(exc)[:200])
            return []

        _cache[cache_key] = (time.time(), findings)
        return findings

    # ── Subclass contract ────────────────────────────────────────────────────

    @abstractmethod
    async def _run_impl(self, cluster: ActorCluster) -> list[Finding]:
        """Core agent logic — implement in subclass."""
        ...

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _is_configured(self) -> bool:
        """True if all required env keys are present (non-blank)."""
        import os
        for key in self.required_keys:
            if not os.environ.get(key, "").strip():
                return False
        return True

    @staticmethod
    def sanitize_text(text: str) -> str:
        """Harden scraped text against prompt injection before LLM use.

        Strips common injection markers. The profiler system prompt also frames
        all agent-supplied text as DATA not instructions — this is a second
        layer of defense.
        """
        injection_markers = [
            "ignore previous instructions",
            "ignore all previous",
            "disregard previous",
            "override instructions",
            "system prompt:",
            "new instructions:",
            "you are now",
            "forget everything",
        ]
        lower = text.lower()
        for marker in injection_markers:
            if marker in lower:
                idx = lower.find(marker)
                # Redact the injected portion
                text = text[:idx] + "[REDACTED]" + text[idx + len(marker):]
                lower = text.lower()
        return text

    @staticmethod
    def _cache_key_for(agent_name: str, cluster: ActorCluster) -> str:
        sig = hashlib.sha256(
            f"{agent_name}:{cluster.id}:{cluster.last_seen}".encode()
        ).hexdigest()[:12]
        return sig


def clear_cache() -> None:
    """Clear the in-memory agent cache — for use in tests."""
    _cache.clear()
