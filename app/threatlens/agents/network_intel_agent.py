"""Network Intelligence Agent — IP infrastructure context.

Completely free, no API key required.

Sources:
  - Shodan InternetDB (internetdb.shodan.io) — open ports, vulns, hostnames per IP
  - BGPView (api.bgpview.io)                 — ASN, network owner, country, prefix

These two sources together answer: what infrastructure does this attacker's
IP belong to, what is exposed on it, and which organisation/ASN owns it?
"""
from __future__ import annotations

import structlog

from app.threatlens.agents.base_agent import BaseAgent
from app.threatlens.models import ActorCluster, Finding
from app.threatlens.scraper import feeds_client

logger = structlog.get_logger()


class NetworkIntelAgent(BaseAgent):
    name = "network"
    required_keys = []  # always active — no key needed

    async def _run_impl(self, cluster: ActorCluster) -> list[Finding]:
        findings: list[Finding] = []

        for ip in cluster.iocs.ips[:5]:
            # Shodan InternetDB
            entry = await feeds_client.shodan_internetdb(ip)
            if entry:
                if entry.vulns or entry.ports:
                    vuln_note = f", known vulns: {', '.join(entry.vulns[:3])}" if entry.vulns else ""
                    findings.append(Finding(
                        agent=self.name,
                        claim=(
                            f"Shodan InternetDB: IP {ip} has {len(entry.ports)} open port(s)"
                            f"{vuln_note}"
                        ),
                        source_url=f"https://internetdb.shodan.io/{ip}",
                        source_title="Shodan InternetDB",
                        confidence="moderate",
                        raw=entry.model_dump(),
                    ))

            # BGPView
            bgp = await feeds_client.bgpview_ip(ip)
            if bgp and bgp.asn:
                findings.append(Finding(
                    agent=self.name,
                    claim=(
                        f"BGPView: IP {ip} belongs to ASN {bgp.asn} "
                        f"({bgp.asn_description or 'unknown'}), "
                        f"country: {bgp.country_code or 'unknown'}, "
                        f"prefix: {bgp.prefix}"
                    ),
                    source_url=f"https://bgpview.io/ip/{ip}",
                    source_title="BGPView",
                    confidence="moderate",
                    raw=bgp.model_dump(),
                ))

        logger.info("network_agent_done", cluster=cluster.id[:8], findings=len(findings))
        return findings
