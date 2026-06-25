"""Dark Web Intelligence Agent — signals from the deep/dark web via clearnet providers.

This agent NEVER accesses Tor, I2P, or any dark web site directly.
It uses legitimate clearnet APIs from providers who do the dark web collection:

  IntelligenceX (intelx.io)  — searches pastes, dark web forums, Tor sites,
                                data leaks, breach records. They do the .onion
                                crawling; we read their index via API.

  CIRCL.lu PassiveDNS         — free passive DNS from Luxembourg's national CERT.
                                No key needed. Shows full DNS history — when a
                                domain was first/last seen, what IPs it resolved
                                to. Essential for mapping threat actor infrastructure.

  LeakIX (leakix.net)         — searches for exposed services and leaked data.
                                Provides signals about compromised infrastructure.

Legal boundary: same as all ThreatLens agents — allowlist-gated, signals only,
no PII stored, no stolen data downloaded. The providers carry the legal framing
for their dark web collection; we read their published indices.

Keys needed:
  INTELX_API_KEY   — free account at intelx.io/signup
  LEAKIX_API_KEY   — free account at leakix.net

CIRCL PassiveDNS requires no key.
"""
from __future__ import annotations

import structlog

from app.threatlens.agents.base_agent import BaseAgent
from app.threatlens.config import threatlens_settings
from app.threatlens.models import ActorCluster, Finding
from app.threatlens.scraper import feeds_client

logger = structlog.get_logger()

_INTELX_MEDIA_LABELS = {
    1: "paste site", 3: "document", 4: "Tor site", 5: "I2P",
    6: "ZeroNet", 7: "IRC", 8: "dark web forum", 9: "dark web", 14: "data leak", 26: "Telegram"
}


class DarkWebAgent(BaseAgent):
    """Queries dark/deep web indices via clearnet provider APIs.

    Three sources, each optional (returns [] if key absent):
      1. IntelligenceX — broad dark web + paste + breach search
      2. CIRCL.lu PassiveDNS — free passive DNS history
      3. LeakIX — exposed service / data leak signals
    """
    name = "darkweb"
    required_keys = []  # each source self-skips when its key is absent

    async def _run_impl(self, cluster: ActorCluster) -> list[Finding]:
        findings: list[Finding] = []
        intelx_key = threatlens_settings.intelx_api_key
        leakix_key = threatlens_settings.leakix_api_key
        monitored = threatlens_settings.monitored_domain_list

        # ── 1. IntelligenceX — dark web, pastes, Tor, forums, leaks ──────────
        if intelx_key:
            # Search for monitored Skylo domains + sector terms
            queries = list(monitored[:2])
            if cluster.dominant_intent and 'credential' in (cluster.dominant_intent or ''):
                queries.append('skylo.tech credentials')
            for q in queries[:2]:
                results = await feeds_client.intelx_search(q, intelx_key, max_results=5)
                for r in results:
                    source_label = r.bucket or f"source-{r.media}"
                    findings.append(Finding(
                        agent=self.name,
                        claim=(
                            f"IntelligenceX: mention of '{q}' found on {source_label} "
                            f"('{r.name[:50]}') — {r.date}"
                        ),
                        source_url="https://intelx.io",
                        source_title=f"IntelligenceX — {source_label}",
                        confidence="moderate",
                        raw={
                            "query": q,
                            "bucket": source_label,
                            "name": r.name[:80],
                            "date": r.date,
                            "media": r.media,
                        },
                    ))
        else:
            logger.debug("intelx_no_key_skip")

        # ── 2. CIRCL.lu Passive DNS — free, no key ─────────────────────────
        for domain in cluster.iocs.domains[:3]:
            records = await feeds_client.circl_passivedns(domain)
            if records:
                # Count unique IPs this domain has resolved to
                unique_ips = {r.rdata for r in records if r.rrtype in ('A', 'AAAA')}
                date_range = ""
                if records:
                    first = min((r.time_first for r in records if r.time_first), default="")
                    last  = max((r.time_last  for r in records if r.time_last),  default="")
                    if first and last:
                        date_range = f" (active {first} → {last})"
                if unique_ips:
                    findings.append(Finding(
                        agent=self.name,
                        claim=(
                            f"PassiveDNS: domain {domain} resolved to {len(unique_ips)} unique IP(s)"
                            f"{date_range} — IPs: {', '.join(list(unique_ips)[:3])}"
                        ),
                        source_url=f"https://www.circl.lu/pdns/query/{domain}",
                        source_title="CIRCL.lu Passive DNS (free)",
                        confidence="moderate",
                        raw={"domain": domain, "unique_ips": list(unique_ips)[:5], "record_count": len(records)},
                    ))

        # ── 3. LeakIX — exposed services / leaked data ─────────────────────
        if leakix_key:
            for domain in cluster.iocs.domains[:3]:
                leaks = await feeds_client.leakix_host(domain, leakix_key)
                for leak in leaks[:2]:
                    findings.append(Finding(
                        agent=self.name,
                        claim=(
                            f"LeakIX: exposed service on {domain}:{leak.port} "
                            f"({leak.protocol}/{leak.leak_type}) — {leak.summary[:80]}"
                        ),
                        source_url=f"https://leakix.net/host/{domain}",
                        source_title="LeakIX",
                        confidence="high" if leak.leak_type else "moderate",
                        raw={"domain": domain, "port": leak.port, "leak_type": leak.leak_type},
                    ))
        else:
            logger.debug("leakix_no_key_skip")

        logger.info(
            "darkweb_agent_done",
            cluster=cluster.id[:8],
            findings=len(findings),
            intelx=bool(intelx_key),
            leakix=bool(leakix_key),
        )
        return findings
