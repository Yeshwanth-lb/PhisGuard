"""Compromise Intelligence Agent — signals-only breach and leak-site intel.

Answers: is Skylo / its partners / its industry sectors showing up in
breach data or ransomware leak-site victim listings?

LEGAL BOUNDARY — this agent:
  ✓ Reads clearnet APIs published by ransomware trackers (ransomware.live, RansomLook)
  ✓ Queries breach-directory metadata (XposedOrNot, HIBP)
  ✗ NEVER downloads stolen credential dumps or raw breach records
  ✗ NEVER stores PII, leaked passwords, or raw breach data
  ✗ NEVER accesses dark-web sites directly

Findings store SIGNALS only:
  - "Victim listing for sector X posted by group Y on date Z"
  - "Domain D appears in breach directory"
  NOT the underlying records.
"""
from __future__ import annotations

import os

import httpx
import structlog

from app.threatlens.agents.base_agent import BaseAgent
from app.threatlens.config import threatlens_settings
from app.threatlens.models import ActorCluster, Finding
from app.threatlens.scraper import feeds_client
from app.threatlens.scraper.fetcher import HONEST_UA, is_allowed_or_raise

logger = structlog.get_logger()

_SKYLO_SECTORS = ["maritime", "logistics", "mining", "agriculture", "automotive", "telecom", "satellite"]


class CompromiseIntelAgent(BaseAgent):
    name = "compromise"
    required_keys = []  # free sources always run; commercial sources self-skip when keyless

    async def _run_impl(self, cluster: ActorCluster) -> list[Finding]:
        findings: list[Finding] = []
        monitored = threatlens_settings.monitored_domain_list
        sectors = threatlens_settings.monitored_sector_list or _SKYLO_SECTORS

        # 1. Ransomware victim listings (no key needed)
        victims = await feeds_client.ransomwarelive_victims(sectors)
        victims += await feeds_client.ransomlook_victims(sectors)

        for v in victims[:10]:
            findings.append(Finding(
                agent=self.name,
                claim=(
                    f"Ransomware victim listing: '{v.victim}' posted by group '{v.group}' "
                    f"on {v.date} — sector: {v.sector or 'unspecified'} [{v.source}]"
                ),
                source_url=f"https://ransomware.live" if v.source == "ransomware.live" else "https://api.ransomlook.io",
                source_title=f"Ransomware victim tracker ({v.source})",
                confidence="moderate",  # single source, unverified — capped at moderate
                raw={
                    "group": v.group,
                    "sector": v.sector,
                    "date": v.date,
                    "source": v.source,
                    # victim name stored for provenance but NOT credential data
                },
            ))

        # 2. Breach-directory signals for monitored domains
        for domain in monitored[:5]:
            breach_signal = await self._xposedornot_check(domain)
            if breach_signal:
                findings.append(breach_signal)

        # 3. HIBP domain check (if key available)
        hibp_key = threatlens_settings.hibp_api_key
        if hibp_key:
            for domain in monitored[:3]:
                hibp_signal = await self._hibp_domain_check(domain, hibp_key)
                if hibp_signal:
                    findings.append(hibp_signal)

        logger.info("compromise_agent_done", cluster=cluster.id[:8], findings=len(findings))
        return findings

    async def _xposedornot_check(self, domain: str) -> Finding | None:
        url = f"https://xposedornot.com/api/v1/breach-analytics?email={domain}"
        try:
            is_allowed_or_raise(url)
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers={"User-Agent": HONEST_UA})
                if resp.status_code == 200:
                    d = resp.json()
                    breach_count = len(d.get("breaches", []))
                    if breach_count > 0:
                        return Finding(
                            agent=self.name,
                            claim=(
                                f"Breach exposure signal: domain '{domain}' appears in "
                                f"{breach_count} breach record(s) in XposedOrNot directory"
                            ),
                            source_url=f"https://xposedornot.com/xposed/{domain}",
                            source_title="XposedOrNot breach directory",
                            confidence="low",  # breach-directory signal, not confirmed record
                            raw={"domain": domain, "breach_count": breach_count},
                            # raw deliberately contains NO credential data
                        )
        except Exception as exc:
            logger.debug("xposedornot_error", domain=domain, error=str(exc)[:80])
        return None

    async def _hibp_domain_check(self, domain: str, api_key: str) -> Finding | None:
        url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
        try:
            is_allowed_or_raise(url)
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers={
                    "User-Agent": HONEST_UA,
                    "hibp-api-key": api_key,
                })
                if resp.status_code == 200:
                    breaches = resp.json()
                    if breaches:
                        return Finding(
                            agent=self.name,
                            claim=(
                                f"HIBP breach signal: domain '{domain}' appears in "
                                f"{len(breaches)} breach(es)"
                            ),
                            source_url=f"https://haveibeenpwned.com/DomainSearch",
                            source_title="Have I Been Pwned (domain search)",
                            confidence="moderate",
                            raw={"domain": domain, "breach_count": len(breaches)},
                        )
        except Exception as exc:
            logger.debug("hibp_error", domain=domain, error=str(exc)[:80])
        return None
