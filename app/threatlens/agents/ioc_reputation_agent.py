"""IoC Reputation Agent — community threat feeds.

Queries free community feeds for the cluster's domains and IPs:
  - abuse.ch: URLhaus, ThreatFox  (free account key: ABUSECH_AUTH_KEY)
  - AlienVault OTX pulses          (free account key: OTX_API_KEY)
  - Pulsedive reputation           (free account key: PULSEDIVE_API_KEY)

All sources self-report not_configured when keys are absent.
"""
from __future__ import annotations

import structlog

from app.threatlens.agents.base_agent import BaseAgent
from app.threatlens.config import threatlens_settings
from app.threatlens.models import ActorCluster, Finding
from app.threatlens.scraper import feeds_client

logger = structlog.get_logger()


class IoCReputationAgent(BaseAgent):
    name = "ioc"
    required_keys = []  # gracefully skips sources whose keys are absent

    async def _run_impl(self, cluster: ActorCluster) -> list[Finding]:
        findings: list[Finding] = []

        for domain in cluster.iocs.domains[:5]:
            # URLhaus domain lookup
            entry = await feeds_client.urlhaus_host_lookup(domain)
            if entry and entry.urls_on_this_host > 0:
                findings.append(Finding(
                    agent=self.name,
                    claim=f"URLhaus: {entry.urls_on_this_host} malicious URL(s) hosted on {domain}",
                    source_url=f"https://urlhaus.abuse.ch/host/{domain}/",
                    source_title="URLhaus (abuse.ch)",
                    confidence="high",
                    raw={"domain": domain, "url_count": entry.urls_on_this_host},
                ))

            # ThreatFox lookup
            tf_hits = await feeds_client.threatfox_ioc_lookup(domain)
            for hit in tf_hits[:2]:
                findings.append(Finding(
                    agent=self.name,
                    claim=(
                        f"ThreatFox: domain {domain} associated with "
                        f"{hit.malware or hit.threat_type} "
                        f"(confidence {hit.confidence_level}%)"
                    ),
                    source_url="https://threatfox.abuse.ch",
                    source_title="ThreatFox (abuse.ch)",
                    confidence="high" if hit.confidence_level >= 75 else "moderate",
                    raw=hit.model_dump(),
                ))

            # OTX
            pulses = await feeds_client.otx_domain_lookup(domain)
            for pulse in pulses[:2]:
                findings.append(Finding(
                    agent=self.name,
                    claim=f"AlienVault OTX pulse: '{pulse.name}' includes {domain}",
                    source_url=f"https://otx.alienvault.com/indicator/domain/{domain}",
                    source_title="AlienVault OTX",
                    confidence="moderate",
                    raw={**pulse.model_dump(), "domain": domain},
                ))

        # Pulsedive for IPs
        for ip in cluster.iocs.ips[:3]:
            pd_result = await self._pulsedive_lookup(ip)
            if pd_result:
                findings.append(pd_result)

        logger.info("ioc_agent_done", cluster=cluster.id[:8], findings=len(findings))
        return findings

    async def _pulsedive_lookup(self, ip: str) -> Finding | None:
        api_key = threatlens_settings.pulsedive_api_key
        if not api_key:
            return None
        try:
            import httpx
            from app.threatlens.scraper.fetcher import is_allowed_or_raise, HONEST_UA
            url = "https://pulsedive.com/api/info.php"
            is_allowed_or_raise(url)
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, params={
                    "indicator": ip, "key": api_key, "pretty": "0"
                }, headers={"User-Agent": HONEST_UA})
                if resp.status_code == 200:
                    d = resp.json()
                    risk = d.get("risk", "unknown")
                    if risk in ("high", "critical", "medium"):
                        return Finding(
                            agent=self.name,
                            claim=f"Pulsedive: IP {ip} rated '{risk}' risk",
                            source_url=f"https://pulsedive.com/indicator/?ioc={ip}",
                            source_title="Pulsedive",
                            confidence="moderate",
                            raw={"ip": ip, "risk": risk},
                        )
        except Exception as exc:
            logger.debug("pulsedive_error", ip=ip, error=str(exc)[:80])
        return None
