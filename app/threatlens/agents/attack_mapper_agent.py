"""ATT&CK Mapper Agent — maps cluster behavior to MITRE ATT&CK technique IDs.

Free, local, no network call. Uses the bundled attack_techniques.json and a
hardcoded intent → technique mapping. No LLM required.
"""
from __future__ import annotations

import json
from pathlib import Path

import structlog

from app.threatlens.agents.base_agent import BaseAgent
from app.threatlens.models import ActorCluster, Finding

logger = structlog.get_logger()

_TECHNIQUES_PATH = Path(__file__).parent.parent / "data" / "attack_techniques.json"

# Intent → list of ATT&CK technique IDs
_INTENT_TO_TECHNIQUES: dict[str, list[str]] = {
    "credential_harvesting":      ["T1566.002", "T1598.003", "T1539", "T1204.001"],
    "credential_harvest":         ["T1566.002", "T1598.003", "T1539", "T1204.001"],
    "bec_fraud":                  ["T1566", "T1534", "T1657", "T1656"],
    "fraud_payment":              ["T1566", "T1657", "T1656"],
    "fraud_scam":                 ["T1566", "T1657"],
    "brand_impersonation":        ["T1566", "T1656", "T1583.001"],
    "executive_impersonation":    ["T1566", "T1534", "T1657", "T1656"],
    "generic_phish":              ["T1566", "T1598"],
    "credential_theft":           ["T1566.002", "T1539"],
    "malware_delivery":           ["T1566.001", "T1204.002"],
    "unclear":                    ["T1566"],
}


class AttackMapperAgent(BaseAgent):
    name = "attack"
    required_keys = []  # free, local — always configured

    def __init__(self):
        super().__init__()
        self._techniques: dict[str, dict] = {}
        self._load_techniques()

    def _load_techniques(self) -> None:
        try:
            with open(_TECHNIQUES_PATH) as f:
                for t in json.load(f):
                    self._techniques[t["attack_id"]] = t
        except Exception as exc:
            logger.warning("attack_techniques_load_failed", error=str(exc))

    async def _run_impl(self, cluster: ActorCluster) -> list[Finding]:
        intent = (cluster.dominant_intent or "").lower().strip()
        technique_ids = _INTENT_TO_TECHNIQUES.get(intent, [])

        if not technique_ids:
            return []

        findings: list[Finding] = []
        for tid in technique_ids:
            t = self._techniques.get(tid)
            if not t:
                continue
            findings.append(Finding(
                agent=self.name,
                claim=(
                    f"Observed technique: {t['name']} ({t['attack_id']}) "
                    f"— tactic: {t['tactic']}"
                ),
                source_url=None,
                source_title="MITRE ATT&CK (local reference)",
                confidence="moderate",
                raw=t,
            ))

        logger.info(
            "attack_mapper_done",
            intent=intent,
            techniques=[(f.raw or {}).get("attack_id", "") for f in findings],
        )
        return findings
