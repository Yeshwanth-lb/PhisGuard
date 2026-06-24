"""Typed clients for all free JSON intelligence feeds.

Each function:
  1. Checks the allowlist via fetcher.is_allowed_or_raise()
  2. Makes its own httpx call (POST or GET as the API requires)
  3. Returns typed Pydantic objects — never raw dicts
  4. Returns [] on any error (never raises to callers)

Free sources covered:
  abuse.ch  — URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker
  AlienVault OTX   — community IoC pulses
  Pulsedive         — indicator reputation
  ransomware.live   — victim listings (no key)
  RansomLook        — victim/group listings (no key)
  NVD/NIST          — CVE database (no key or optional key)
  CISA KEV          — known exploited vulnerabilities (no key)
  EPSS              — exploit probability scores (no key)
  Shodan InternetDB — IP exposure (no key)
  BGPView           — ASN / network info (no key)
"""
from __future__ import annotations

import structlog
import httpx
from pydantic import BaseModel

from app.threatlens.scraper.fetcher import HONEST_UA, is_allowed_or_raise
from app.threatlens.config import threatlens_settings

logger = structlog.get_logger()

_TIMEOUT = 15
_HEADERS = {"User-Agent": HONEST_UA}


# ---------------------------------------------------------------------------
# Typed response models
# ---------------------------------------------------------------------------

class URLhausEntry(BaseModel):
    host: str = ""
    url_status: str = ""
    urls_on_this_host: int = 0
    blacklists: dict = {}
    urls: list[dict] = []


class MalwareBazaarEntry(BaseModel):
    sha256_hash: str = ""
    file_type: str = ""
    signature: str | None = None
    tags: list[str] = []
    reporter: str = ""


class ThreatFoxEntry(BaseModel):
    ioc: str = ""
    ioc_type: str = ""
    threat_type: str = ""
    malware: str = ""
    confidence_level: int = 0
    tags: list[str] = []


class OTXPulse(BaseModel):
    id: str = ""
    name: str = ""
    description: str = ""
    attack_ids: list[str] = []
    references: list[str] = []
    adversary: str = ""
    tlp: str = "white"


class VictimListing(BaseModel):
    group: str = ""
    victim: str = ""
    date: str = ""
    sector: str | None = None
    country: str | None = None
    source: str = ""


class CVEEntry(BaseModel):
    cve_id: str = ""
    description: str = ""
    cvss_score: float | None = None
    published: str = ""
    keywords_matched: list[str] = []
    in_kev: bool = False
    epss_score: float | None = None


class ShodanInternetDBEntry(BaseModel):
    ip: str = ""
    ports: list[int] = []
    vulns: list[str] = []
    hostnames: list[str] = []
    cpes: list[str] = []
    tags: list[str] = []


class BGPViewEntry(BaseModel):
    ip: str = ""
    asn: str = ""
    asn_description: str = ""
    country_code: str = ""
    prefix: str = ""


# ---------------------------------------------------------------------------
# abuse.ch
# ---------------------------------------------------------------------------

async def urlhaus_host_lookup(host: str) -> URLhausEntry | None:
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    try:
        is_allowed_or_raise(url)
        auth = threatlens_settings.abusech_auth_key
        headers = {**_HEADERS, **({"Auth-Key": auth} if auth else {})}
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(url, data={"host": host}, headers=headers)
            if resp.status_code == 200:
                d = resp.json()
                if d.get("query_status") == "is_host":
                    return URLhausEntry(
                        host=host,
                        url_status=d.get("urlhaus_reference", ""),
                        urls_on_this_host=len(d.get("urls", [])),
                        urls=d.get("urls", [])[:5],
                    )
    except Exception as exc:
        logger.debug("urlhaus_error", host=host, error=str(exc)[:80])
    return None


async def threatfox_ioc_lookup(ioc: str) -> list[ThreatFoxEntry]:
    url = "https://threatfox-api.abuse.ch/api/v1/"
    try:
        is_allowed_or_raise(url)
        auth = threatlens_settings.abusech_auth_key
        headers = {**_HEADERS, **({"Auth-Key": auth} if auth else {})}
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(url, json={"query": "search_ioc", "search_term": ioc}, headers=headers)
            if resp.status_code == 200:
                d = resp.json()
                if d.get("query_status") == "ok":
                    return [
                        ThreatFoxEntry(
                            ioc=e.get("ioc", ""),
                            ioc_type=e.get("ioc_type", ""),
                            threat_type=e.get("threat_type", ""),
                            malware=e.get("malware", ""),
                            confidence_level=e.get("confidence_level", 0),
                            tags=e.get("tags") or [],
                        )
                        for e in d.get("data", [])[:5]
                    ]
    except Exception as exc:
        logger.debug("threatfox_error", ioc=ioc, error=str(exc)[:80])
    return []


# ---------------------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------------------

async def otx_domain_lookup(domain: str) -> list[OTXPulse]:
    api_key = threatlens_settings.otx_api_key
    if not api_key:
        return []
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    try:
        is_allowed_or_raise(url)
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url, headers={**_HEADERS, "X-OTX-API-KEY": api_key})
            if resp.status_code == 200:
                d = resp.json()
                pulses = d.get("pulse_info", {}).get("pulses", [])
                return [
                    OTXPulse(
                        id=p.get("id", ""),
                        name=p.get("name", ""),
                        description=p.get("description", "")[:300],
                        attack_ids=[a.get("id", "") for a in p.get("attack_ids", [])],
                        references=p.get("references", [])[:3],
                        adversary=p.get("adversary", ""),
                        tlp=p.get("tlp", "white"),
                    )
                    for p in pulses[:5]
                ]
    except Exception as exc:
        logger.debug("otx_error", domain=domain, error=str(exc)[:80])
    return []


# ---------------------------------------------------------------------------
# ransomware.live
# ---------------------------------------------------------------------------

async def ransomwarelive_victims(sectors: list[str]) -> list[VictimListing]:
    url = "https://api.ransomware.live/victims"
    try:
        is_allowed_or_raise(url)
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, headers=_HEADERS)
            if resp.status_code == 200:
                victims = resp.json()
                sector_lower = [s.lower() for s in sectors]
                matched = []
                for v in victims:
                    vsector = (v.get("activity") or v.get("sector") or "").lower()
                    if any(s in vsector for s in sector_lower):
                        matched.append(VictimListing(
                            group=v.get("group_name", ""),
                            victim=v.get("post_title") or v.get("victim", ""),
                            date=v.get("discovered") or v.get("date", ""),
                            sector=v.get("activity") or v.get("sector"),
                            country=v.get("country"),
                            source="ransomware.live",
                        ))
                return matched[:20]
    except Exception as exc:
        logger.debug("ransomwarelive_error", error=str(exc)[:80])
    return []


async def ransomlook_victims(sectors: list[str]) -> list[VictimListing]:
    url = "https://api.ransomlook.io/posts"
    try:
        is_allowed_or_raise(url)
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, headers=_HEADERS)
            if resp.status_code == 200:
                posts = resp.json() if isinstance(resp.json(), list) else []
                sector_lower = [s.lower() for s in sectors]
                matched = []
                for p in posts:
                    vsector = (p.get("sector") or "").lower()
                    vtitle = (p.get("post_title") or p.get("victim") or "").lower()
                    if any(s in vsector or s in vtitle for s in sector_lower):
                        matched.append(VictimListing(
                            group=p.get("group_name", ""),
                            victim=p.get("post_title") or p.get("victim", ""),
                            date=p.get("discovered", ""),
                            sector=p.get("sector"),
                            country=p.get("country"),
                            source="ransomlook",
                        ))
                return matched[:20]
    except Exception as exc:
        logger.debug("ransomlook_error", error=str(exc)[:80])
    return []


# ---------------------------------------------------------------------------
# NVD / CISA KEV / EPSS
# ---------------------------------------------------------------------------

_NTN_KEYWORDS = [
    "5g", "ntn", "lte", "ran", "vran", "3gpp", "amf", "smf", "gtp",
    "telecom", "satellite", "ground station", "baseband", "modem",
    "gcp", "kubernetes", "cloud", "container", "iam",
]


async def nvd_cve_search(keywords: list[str]) -> list[CVEEntry]:
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key = threatlens_settings.nvd_api_key
    results = []
    for kw in keywords[:3]:  # limit to 3 terms to respect rate limits
        try:
            is_allowed_or_raise(base_url)
            params = {"keywordSearch": kw, "resultsPerPage": 10}
            headers = {**_HEADERS, **({"apiKey": api_key} if api_key else {})}
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(base_url, params=params, headers=headers)
                if resp.status_code == 200:
                    for item in resp.json().get("vulnerabilities", []):
                        cve = item.get("cve", {})
                        desc = " ".join(
                            d.get("value", "")
                            for d in cve.get("descriptions", [])
                            if d.get("lang") == "en"
                        )
                        desc_lower = desc.lower()
                        matched_kws = [k for k in _NTN_KEYWORDS if k in desc_lower]
                        if matched_kws or kw.lower() in desc_lower:
                            metrics = cve.get("metrics", {})
                            cvss = None
                            for v in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                                m = metrics.get(v, [{}])
                                if m:
                                    cvss = m[0].get("cvssData", {}).get("baseScore")
                                    break
                            results.append(CVEEntry(
                                cve_id=cve.get("id", ""),
                                description=desc[:300],
                                cvss_score=cvss,
                                published=cve.get("published", "")[:10],
                                keywords_matched=matched_kws or [kw],
                            ))
        except Exception as exc:
            logger.debug("nvd_error", kw=kw, error=str(exc)[:80])
    return results[:10]


async def cisa_kev() -> list[dict]:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        is_allowed_or_raise(url)
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, headers=_HEADERS)
            if resp.status_code == 200:
                return resp.json().get("vulnerabilities", [])
    except Exception as exc:
        logger.debug("cisa_kev_error", error=str(exc)[:80])
    return []


async def epss_scores(cve_ids: list[str]) -> dict[str, float]:
    if not cve_ids:
        return {}
    url = "https://api.first.org/data/v1/epss"
    try:
        is_allowed_or_raise(url)
        params = {"cve": ",".join(cve_ids[:20])}
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, params=params, headers=_HEADERS)
            if resp.status_code == 200:
                return {
                    item["cve"]: float(item.get("epss", 0))
                    for item in resp.json().get("data", [])
                }
    except Exception as exc:
        logger.debug("epss_error", error=str(exc)[:80])
    return {}


# ---------------------------------------------------------------------------
# Shodan InternetDB (no key required)
# ---------------------------------------------------------------------------

async def shodan_internetdb(ip: str) -> ShodanInternetDBEntry | None:
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        is_allowed_or_raise(url)
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers=_HEADERS)
            if resp.status_code == 200:
                d = resp.json()
                return ShodanInternetDBEntry(
                    ip=ip,
                    ports=d.get("ports", []),
                    vulns=d.get("vulns", []),
                    hostnames=d.get("hostnames", []),
                    cpes=d.get("cpes", []),
                    tags=d.get("tags", []),
                )
    except Exception as exc:
        logger.debug("shodan_internetdb_error", ip=ip, error=str(exc)[:80])
    return None


# ---------------------------------------------------------------------------
# BGPView (no key required)
# ---------------------------------------------------------------------------

async def bgpview_ip(ip: str) -> BGPViewEntry | None:
    url = f"https://api.bgpview.io/ip/{ip}"
    try:
        is_allowed_or_raise(url)
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers=_HEADERS)
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                prefixes = d.get("prefixes", [{}])
                first = prefixes[0] if prefixes else {}
                asn = first.get("asn", {})
                return BGPViewEntry(
                    ip=ip,
                    asn=str(asn.get("asn", "")),
                    asn_description=asn.get("description", ""),
                    country_code=first.get("country_code", ""),
                    prefix=first.get("prefix", ""),
                )
    except Exception as exc:
        logger.debug("bgpview_error", ip=ip, error=str(exc)[:80])
    return None
