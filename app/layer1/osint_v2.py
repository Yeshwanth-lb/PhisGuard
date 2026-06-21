"""OSINT v2: phishtank, gsb, whois age, spf, dmarc, dkim."""
import asyncio
import re
from datetime import UTC, datetime

import httpx
import structlog

logger = structlog.get_logger()

_HTTPS = "https" + ":" + "//"
_PT = _HTTPS + "checkurl.phishtank.com/checkurl/"
_GSB = _HTTPS + "safebrowsing.googleapis.com/v4/threatMatches:find"


def _domain_of(s):
    s = s.strip()
    if "@" in s:
        return s.rsplit("@", 1)[-1].strip(">").lower()
    m = re.search(r"https?://([^/:]+)", s, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    return None


async def phishtank_check(url, api_key, cache):
    cached = await cache.get("phishtank", url)
    if cached:
        return cached
    out = {"source": "phishtank", "ioc": url, "malicious": False, "score": 0, "raw": {}}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            data = {"url": url, "format": "json"}
            if api_key:
                data["app_key"] = api_key
            resp = await client.post(_PT, data=data,
                headers={"User-Agent": "phishtank/PhishGuard"})
            if resp.status_code == 200:
                body = resp.json()
                results = body.get("results", {})
                in_db = results.get("in_database", False)
                ver = results.get("verified", False)
                vp = results.get("valid_phish", False)
                if in_db and ver and vp:
                    out["malicious"] = True
                    out["score"] = 100
                out["raw"] = results
    except Exception as exc:
        logger.warning("phishtank_error", url=url, error=str(exc))
    await cache.set("phishtank", url, out)
    return out


async def gsb_check(url, api_key, cache):
    cached = await cache.get("gsb", url)
    if cached:
        return cached
    out = {"source": "google_safe_browsing", "ioc": url, "malicious": False, "score": 0, "raw": {}}
    if not api_key:
        return out
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.5.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            full_url = _GSB + "?" + "key" + "=" + api_key
            resp = await client.post(full_url, json=payload)
            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                if matches:
                    out["malicious"] = True
                    out["score"] = 100
                out["raw"] = {"match_count": len(matches), "matches": matches}
    except Exception as exc:
        logger.warning("gsb_error", url=url, error=str(exc))
    await cache.set("gsb", url, out)
    return out


def _whois_age_sync(domain):
    try:
        import whois
        info = whois.whois(domain)
        created = info.creation_date
        if isinstance(created, list):
            created = created[0] if created else None
        if not created:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        now = datetime.now(UTC)
        return (now - created).days
    except Exception:
        return None


async def domain_age_check(domain, cache, threshold_days=30):
    cached = await cache.get("whois_age", domain)
    if cached:
        return cached
    out = {"source": "domain_age", "ioc": domain, "malicious": False, "score": 0, "raw": {}}
    loop = asyncio.get_event_loop()
    age_days = await loop.run_in_executor(None, _whois_age_sync, domain)
    if age_days is not None:
        out["raw"] = {"age_days": age_days, "threshold_days": threshold_days}
        if age_days < threshold_days:
            out["malicious"] = True
            out["score"] = max(20, 100 - age_days * 3)
    await cache.set("whois_age", domain, out)
    return out


def _dns_txt_sync(name):
    try:
        import dns.resolver
        res = dns.resolver.Resolver()
        res.timeout = 8
        res.lifetime = 12
        answers = res.resolve(name, "TXT")
        records = []
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            records.append(txt)
        return records
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except Exception:
        return None


async def spf_check(domain, cache):
    cached = await cache.get("spf", domain)
    if cached:
        return cached
    out = {"source": "spf", "ioc": domain, "malicious": False, "score": 0, "raw": {}}
    loop = asyncio.get_event_loop()
    records = await loop.run_in_executor(None, _dns_txt_sync, domain)
    if records is None:
        out["raw"] = {"reason": "dns_error"}
        await cache.set("spf", domain, out)
        return out
    spf_recs = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf_recs:
        out["malicious"] = True
        out["score"] = 30
        out["raw"] = {"reason": "no_spf_record"}
    else:
        rec = spf_recs[0]
        out["raw"] = {"record": rec}
        if "-all" not in rec and "~all" not in rec:
            out["score"] = 10
            out["raw"]["weak"] = True
    await cache.set("spf", domain, out)
    return out


async def dmarc_check(domain, cache):
    cached = await cache.get("dmarc", domain)
    if cached:
        return cached
    out = {"source": "dmarc", "ioc": domain, "malicious": False, "score": 0, "raw": {}}
    loop = asyncio.get_event_loop()
    records = await loop.run_in_executor(None, _dns_txt_sync, "_dmarc." + domain)
    if records is None:
        out["raw"] = {"reason": "dns_error"}
        await cache.set("dmarc", domain, out)
        return out
    dm = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dm:
        out["malicious"] = True
        out["score"] = 30
        out["raw"] = {"reason": "no_dmarc_record"}
    else:
        rec = dm[0]
        out["raw"] = {"record": rec}
        policy = "none"
        m = re.search(r"p\s*=\s*([a-z]+)", rec, re.IGNORECASE)
        if m:
            policy = m.group(1).lower()
        out["raw"]["policy"] = policy
        if policy == "none":
            out["score"] = 10
    await cache.set("dmarc", domain, out)
    return out


async def dkim_check(raw, cache, ck):
    out: dict = {}
    out["source"] = "dkim"
    out["ioc"] = ck
    out["malicious"] = False
    out["score"] = 0
    out["raw"] = {"note": "stub"}
    return out
