"""URLscan Agent — scan and analyse suspicious URLs.

URLscan.io takes a URL, renders it in a browser, and returns a full
analysis: screenshot, redirects, DNS, page title, detected phishing signals,
verdicts from community scans.

For ThreatLens: look up existing community scans for the cluster's domains.
No active scanning of unknown URLs (read-only from community database).

Free key required: urlscan.io/user/signup → env var URLSCAN_API_KEY.
Returns [] when key is absent.
"""
from __future__ import annotations

import httpx
import structlog

from app.threatlens.agents.base_agent import BaseAgent
from app.threatlens.config import threatlens_settings
from app.threatlens.models import ActorCluster, Finding
from app.threatlens.scraper.fetcher import HONEST_UA, is_allowed_or_raise

logger = structlog.get_logger()


class URLScanAgent(BaseAgent):
    name = "urlscan"
    required_keys = []  # checked at runtime

    async def _run_impl(self, cluster: ActorCluster) -> list[Finding]:
        api_key = threatlens_settings.urlscan_api_key
        if not api_key:
            return []

        findings: list[Finding] = []

        for domain in cluster.iocs.domains[:5]:
            result = await self._search(domain, api_key)
            if result:
                findings.append(result)

        logger.info("urlscan_agent_done", cluster=cluster.id[:8], findings=len(findings))
        return findings

    async def _search(self, domain: str, api_key: str) -> Finding | None:
        url = "https://urlscan.io/api/v1/search/"
        try:
            is_allowed_or_raise(url)
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    url,
                    params={"q": f"domain:{domain}", "size": 5},
                    headers={"User-Agent": HONEST_UA, "API-Key": api_key},
                )
                if resp.status_code == 200:
                    results = resp.json().get("results", [])
                    malicious = [r for r in results if r.get("verdicts", {}).get("overall", {}).get("malicious")]
                    if malicious:
                        sample = malicious[0]
                        return Finding(
                            agent=self.name,
                            claim=(
                                f"URLscan: {len(malicious)} malicious scan(s) found for domain {domain}. "
                                f"Sample: {sample.get('page', {}).get('title', '')[:80]}"
                            ),
                            source_url=f"https://urlscan.io/search/#domain:{domain}",
                            source_title="URLscan.io",
                            confidence="high",
                            raw={"domain": domain, "malicious_count": len(malicious), "sample": sample.get("id", "")},
                        )
                    if results:
                        return Finding(
                            agent=self.name,
                            claim=f"URLscan: {len(results)} community scan(s) found for domain {domain} (no malicious verdict)",
                            source_url=f"https://urlscan.io/search/#domain:{domain}",
                            source_title="URLscan.io",
                            confidence="low",
                            raw={"domain": domain, "scan_count": len(results)},
                        )
        except Exception as exc:
            logger.debug("urlscan_error", domain=domain, error=str(exc)[:80])
        return None
