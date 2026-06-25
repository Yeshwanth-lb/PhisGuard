"""GreyNoise Agent — internet noise vs. targeted threat classification.

GreyNoise tells you whether an IP is a known internet scanner/bot (noise)
or an actual targeted threat actor (signal). This directly answers whether
a cluster's sending IP is mass-scanning infrastructure vs. a dedicated
threat actor.

Free key required: greynoise.io/signup → env var GREYNOISE_API_KEY.
Returns [] when key is absent (not_configured).
"""
from __future__ import annotations

import httpx
import structlog

from app.threatlens.agents.base_agent import BaseAgent
from app.threatlens.config import threatlens_settings
from app.threatlens.models import ActorCluster, Finding
from app.threatlens.scraper.fetcher import HONEST_UA, is_allowed_or_raise

logger = structlog.get_logger()


class GreyNoiseAgent(BaseAgent):
    name = "greynoise"
    required_keys = []  # checked at runtime

    async def _run_impl(self, cluster: ActorCluster) -> list[Finding]:
        api_key = threatlens_settings.greynoise_api_key
        if not api_key:
            return []

        findings: list[Finding] = []

        for ip in cluster.iocs.ips[:5]:
            result = await self._lookup(ip, api_key)
            if result:
                findings.append(result)

        logger.info("greynoise_agent_done", cluster=cluster.id[:8], findings=len(findings))
        return findings

    async def _lookup(self, ip: str, api_key: str) -> Finding | None:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        try:
            is_allowed_or_raise(url)
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers={
                    "User-Agent": HONEST_UA,
                    "key": api_key,
                })
                if resp.status_code == 200:
                    d = resp.json()
                    classification = d.get("classification", "unknown")  # malicious | benign | unknown
                    noise = d.get("noise", False)
                    riot = d.get("riot", False)
                    name = d.get("name", "")

                    if classification == "malicious" and not noise:
                        return Finding(
                            agent=self.name,
                            claim=(
                                f"GreyNoise: IP {ip} classified as MALICIOUS targeted actor"
                                + (f" ({name})" if name else "")
                            ),
                            source_url=f"https://viz.greynoise.io/ip/{ip}",
                            source_title="GreyNoise",
                            confidence="high",
                            raw={"ip": ip, "classification": classification, "noise": noise, "name": name},
                        )
                    if noise or riot:
                        return Finding(
                            agent=self.name,
                            claim=(
                                f"GreyNoise: IP {ip} is internet background noise "
                                f"({'known scanner/CDN' if riot else 'mass scanner'}) — "
                                "may be shared infrastructure, not dedicated attacker"
                            ),
                            source_url=f"https://viz.greynoise.io/ip/{ip}",
                            source_title="GreyNoise",
                            confidence="low",
                            raw={"ip": ip, "classification": classification, "noise": noise, "riot": riot},
                        )
        except Exception as exc:
            logger.debug("greynoise_error", ip=ip, error=str(exc)[:80])
        return None
