"""Fusion & confidence engine — the deterministic synthesis core.

Parses ALL agent findings, normalizes, deduplicates, corroborates across
independent sources, and assigns a confidence tier using fixed Python rules
(never delegated to the LLM). The profiler then writes prose from the output.

Confidence scale (deterministic):
  confirmed  — MISP/OpenCTI hard match on a member IoC (agent name 'misp')
  high       — ≥2 independent OSINT sources agree (different root domains)
  moderate   — 1 credible external source
  low        — weak / circumstantial signal
  speculative — only internal cluster evidence, no external corroboration
"""
from __future__ import annotations

import re
import time
import uuid

import structlog

from app.threatlens.models import (
    ActorCluster,
    AdversaryProfile,
    CorroboratedClaim,
    Finding,
    IoCSet,
    TTP,
)

logger = structlog.get_logger()

_CONFIDENCE_ORDER = ["speculative", "low", "moderate", "high", "confirmed"]


def _conf_rank(c: str) -> int:
    try:
        return _CONFIDENCE_ORDER.index(c)
    except ValueError:
        return 0


def _root_domain(url: str | None) -> str:
    """Extract root domain (TLD+1) for independence check."""
    if not url:
        return ""
    try:
        import urllib.parse
        host = urllib.parse.urlparse(url).hostname or ""
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Normalize
# ---------------------------------------------------------------------------

def _normalize(findings: list[Finding]) -> list[Finding]:
    """Canonicalize: lowercase domains, strip whitespace from claims."""
    out = []
    for f in findings:
        if not f or not f.claim:
            continue
        out.append(Finding(
            agent=f.agent,
            claim=f.claim.strip(),
            source_url=(f.source_url or "").strip() or None,
            source_title=f.source_title,
            confidence=f.confidence if f.confidence in _CONFIDENCE_ORDER else "low",
            raw=f.raw,
        ))
    return out


# ---------------------------------------------------------------------------
# Deduplicate
# ---------------------------------------------------------------------------

def _dedupe(findings: list[Finding]) -> list[list[Finding]]:
    """Group findings that assert the same core claim.

    Simple approach: group by (agent, attack_id if present, else first 60 chars
    of claim). Each group becomes one CorroboratedClaim.
    """
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        attack_id = f.raw.get("attack_id", "") if f.raw else ""
        if attack_id:
            key = f"ttp:{attack_id}"
        else:
            key = f"claim:{f.claim[:60].lower()}"
        groups.setdefault(key, []).append(f)
    return list(groups.values())


# ---------------------------------------------------------------------------
# Corroborate & weight
# ---------------------------------------------------------------------------

def _assign_confidence(group: list[Finding]) -> tuple[str, int]:
    """Return (confidence_tier, independent_source_count) for a claim group."""
    # MISP hard match → confirmed (only path)
    if any(f.agent == "misp" for f in group):
        return "confirmed", len(group)

    # Count independent root domains
    roots = {_root_domain(f.source_url) for f in group if f.source_url}
    roots.discard("")
    independent = len(roots)

    if independent >= 2:
        return "high", independent
    if independent == 1:
        return "moderate", 1

    # Internal-only (e.g. attack mapper with no URL)
    has_internal = any(f for f in group if not f.source_url)
    if has_internal:
        return "low", 0

    return "speculative", 0


# ---------------------------------------------------------------------------
# Assemble TTPs
# ---------------------------------------------------------------------------

def _extract_ttps(findings: list[Finding]) -> list[TTP]:
    seen: set[str] = set()
    ttps: list[TTP] = []
    for f in findings:
        aid = (f.raw or {}).get("attack_id", "")
        if aid and aid not in seen:
            seen.add(aid)
            ttps.append(TTP(
                attack_id=aid,
                name=(f.raw or {}).get("name", aid),
                tactic=(f.raw or {}).get("tactic", "unknown"),
                evidence_ref=f.source_title or f.agent,
            ))
    return ttps


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run(
    cluster: ActorCluster,
    findings: list[Finding],
) -> tuple[list[CorroboratedClaim], list[TTP], str]:
    """Normalize → dedupe → corroborate → return (claims, ttps, max_confidence).

    The returned max_confidence is the highest tier supported by the evidence.
    The profiler receives this and CANNOT raise it — only lower it.
    """
    valid = _normalize([f for f in findings if f is not None])

    if not valid:
        return [], [], "speculative"

    groups = _dedupe(valid)
    claims: list[CorroboratedClaim] = []
    overall_rank = 0

    for group in groups:
        conf, independent_count = _assign_confidence(group)
        overall_rank = max(overall_rank, _conf_rank(conf))
        claims.append(CorroboratedClaim(
            claim=group[0].claim,
            attack_id=(group[0].raw or {}).get("attack_id") or None,
            supporting_sources=[
                f.source_url for f in group if f.source_url
            ],
            independent_source_count=independent_count,
            confidence=conf,
        ))

    ttps = _extract_ttps(valid)
    max_confidence = _CONFIDENCE_ORDER[min(overall_rank, len(_CONFIDENCE_ORDER) - 1)]

    logger.info(
        "fusion_done",
        cluster=cluster.id[:8],
        claims=len(claims),
        ttps=len(ttps),
        max_confidence=max_confidence,
    )
    return claims, ttps, max_confidence
