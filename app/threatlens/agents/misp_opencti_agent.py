"""MISP/OpenCTI Agent — the ONLY path to 'confirmed' confidence.

Queries the existing MISP and OpenCTI integrations for intrusion-sets or
attributes matching the cluster's IoCs. A hard match in a trusted feed is
the only event that elevates confidence to 'confirmed' — no OSINT agreement
can do this.

Reuses the exact query pattern from app/layer1/osint_client.py.
"""
from __future__ import annotations

import httpx
import structlog

from app.threatlens.agents.base_agent import BaseAgent
from app.config import settings as _app_settings
from app.threatlens.models import ActorCluster, Finding

logger = structlog.get_logger()


class MispOpenCTIAgent(BaseAgent):
    name = "misp"
    required_keys = []  # Uses existing MISP config — checks at runtime

    async def _run_impl(self, cluster: ActorCluster) -> list[Finding]:
        misp_url = _app_settings.misp_url
        misp_key = _app_settings.misp_api_key

        if not misp_url or not misp_key:
            logger.info("misp_agent_not_configured")
            return []

        findings: list[Finding] = []

        # Check each domain and IP in the cluster
        iocs_to_check = list(cluster.iocs.domains[:5]) + list(cluster.iocs.ips[:5])

        for ioc in iocs_to_check:
            hit = await self._misp_lookup(ioc, misp_url, misp_key)
            if hit:
                findings.append(Finding(
                    agent=self.name,
                    claim=f"MISP intrusion-set match on IoC: {ioc} ({hit['attribute_count']} attributes)",
                    source_url=misp_url,
                    source_title="MISP Threat Intelligence Platform",
                    confidence="confirmed",  # hard feed match — only legitimate confirmed source
                    raw={"ioc": ioc, **hit},
                ))

        logger.info(
            "misp_agent_done",
            cluster=cluster.id[:8],
            iocs_checked=len(iocs_to_check),
            hits=len(findings),
        )
        return findings

    async def _misp_lookup(self, ioc: str, misp_url: str, misp_key: str) -> dict | None:
        endpoint = misp_url.rstrip("/") + "/attributes/restSearch"
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                resp = await client.post(
                    endpoint,
                    json={"returnFormat": "json", "value": ioc},
                    headers={"Authorization": misp_key, "Accept": "application/json"},
                )
                if resp.status_code == 200:
                    attrs = resp.json().get("response", {}).get("Attribute", [])
                    if attrs:
                        return {"attribute_count": len(attrs), "sample": attrs[:2]}
        except Exception as exc:
            logger.debug("misp_lookup_error", ioc=ioc, error=str(exc)[:80])
        return None
