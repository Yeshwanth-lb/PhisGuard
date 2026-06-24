"""CVE / Vulnerability Agent — NVD + CISA KEV + EPSS.

Pulls CVEs relevant to NTN / 5G / telecom / cloud — the technologies
Skylo operates. Filters by keyword relevance so generic WordPress CVEs
don't pollute the results.

Free sources, no key required (optional NVD key raises rate limit).
"""
from __future__ import annotations

import structlog

from app.threatlens.agents.base_agent import BaseAgent
from app.threatlens.models import ActorCluster, Finding
from app.threatlens.scraper import feeds_client

logger = structlog.get_logger()

_SEARCH_KEYWORDS = [
    "5g core", "ntn", "vran", "3gpp", "satellite", "telecom",
    "ground station", "gcp kubernetes", "modem firmware",
]

_KEV_RELEVANT_KEYWORDS = [
    "5g", "ntn", "telecom", "satellite", "ran", "modem",
    "gcp", "kubernetes", "cloud", "android", "qualcomm",
]


class CVEAgent(BaseAgent):
    name = "cve"
    required_keys = []  # fully free

    async def _run_impl(self, cluster: ActorCluster) -> list[Finding]:
        findings: list[Finding] = []

        # Build search terms from cluster context
        intent = cluster.dominant_intent or ""
        domains = " ".join(cluster.iocs.domains[:3])
        search_terms = self._build_search_terms(intent, domains)

        # NVD search
        cves = await feeds_client.nvd_cve_search(search_terms)

        # CISA KEV — check if any of our CVEs are known exploited
        kev_ids: set[str] = set()
        kev_list = await feeds_client.cisa_kev()
        for entry in kev_list:
            cve_id = entry.get("cveID", "")
            desc = (entry.get("vulnerabilityName", "") + " " + entry.get("product", "")).lower()
            if any(k in desc for k in _KEV_RELEVANT_KEYWORDS):
                kev_ids.add(cve_id)

        # EPSS scores for our CVEs
        cve_ids = [c.cve_id for c in cves if c.cve_id]
        epss = await feeds_client.epss_scores(cve_ids)

        for cve in cves:
            in_kev = cve.cve_id in kev_ids
            epss_score = epss.get(cve.cve_id)
            severity = "high" if (in_kev or (epss_score and epss_score > 0.5)) else "moderate"

            kev_note = " [CISA KEV — actively exploited]" if in_kev else ""
            epss_note = f" [EPSS: {epss_score:.1%}]" if epss_score else ""

            findings.append(Finding(
                agent=self.name,
                claim=(
                    f"CVE {cve.cve_id}: {cve.description[:150]}"
                    f"{kev_note}{epss_note}"
                ),
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
                source_title="NVD / CISA KEV",
                confidence=severity,
                raw={
                    "cve_id": cve.cve_id,
                    "cvss_score": cve.cvss_score,
                    "in_kev": in_kev,
                    "epss_score": epss_score,
                    "keywords": cve.keywords_matched,
                },
            ))

        logger.info("cve_agent_done", cluster=cluster.id[:8], cves=len(findings))
        return findings

    def _build_search_terms(self, intent: str, domains: str) -> list[str]:
        terms = []
        if "5g" in domains.lower() or "ntn" in domains.lower():
            terms.append("5g core ntn")
        if "credential" in intent or "phish" in intent:
            terms.append("phishing credential")
        terms += ["5g satellite telecom", "ntn ground station"]
        return list(dict.fromkeys(terms))[:3]
