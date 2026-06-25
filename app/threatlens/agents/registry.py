"""Pluggable agent registry.

Adding a new agent: implement BaseAgent, then call register(MyAgent()).
The orchestrator iterates active() — no orchestrator change needed.
"""
from __future__ import annotations

from app.threatlens.agents.base_agent import BaseAgent

_registry: list[BaseAgent] = []


def register(agent: BaseAgent) -> None:
    _registry.append(agent)


def active() -> list[BaseAgent]:
    """All registered agents (configured or not — unconfigured agents
    self-report [] in their run() method)."""
    return list(_registry)


def clear() -> None:
    """Clear registry — for use in tests."""
    _registry.clear()
