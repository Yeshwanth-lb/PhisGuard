"""Async OSINT lookups: VirusTotal, AbuseIPDB, URLhaus, Spamhaus, MISP."""
import asyncio
import socket

import httpx
import structlog

from app.layer1.cache import L1Cache

logger = structlog.get_logger()

_H  = "https://"
VT_IP_BASE   = _H + "www.virustotal.com/api/v3/ip_addresses/"
VT_URL_BASE  = _H + "www.virustotal.com/api/v3/urls/"
ABUSE_BASE   = _H + "api.abuseipdb.com/api/v2/check"
URLHAUS_BASE = _H + "urlhaus-api.abuse.ch/v1/url/"


async def vt_check_ip(ip: str, api_key: str, cache: L1Cache) -> dict:
    cached = await cache.get("vt_ip", ip)
    if cached:
        return cached
    result = {"source": "virustotal", "ioc": ip, "malicious": False, "score": 0, "raw": {}}
    if not api_key:
        return result
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(VT_IP_BASE + ip, headers={"x-apikey": api_key})
            if resp.status_code == 200:
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                mal = stats.get("malicious", 0)
                result["malicious"] = mal > 0
                result["score"] = mal
                result["raw"] = stats
    except Exception as exc:
        logger.warning("vt_ip_error", ip=ip, error=str(exc))
    await cache.set("vt_ip", ip, result)
    return result


async def vt_check_url(url: str, api_key: str, cache: L1Cache) -> dict:
    import base64
    cached = await cache.get("vt_url", url)
    if cached:
        return cached
    result = {"source": "virustotal", "ioc": url, "malicious": False, "score": 0, "raw": {}}
    if not api_key:
        return result
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(VT_URL_BASE + url_id, headers={"x-apikey": api_key})
            if resp.status_code == 200:
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                mal = stats.get("malicious", 0)
                result["malicious"] = mal > 0
                result["score"] = mal
                result["raw"] = stats
    except Exception as exc:
        logger.warning("vt_url_error", error=str(exc))
    await cache.set("vt_url", url, result)
    return result


async def abuseipdb_check(ip: str, api_key: str, cache: L1Cache) -> dict:
    cached = await cache.get("abuseipdb", ip)
    if cached:
        return cached
    result = {"source": "abuseipdb", "ioc": ip, "malicious": False, "score": 0, "raw": {}}
    if not api_key:
        return result
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                ABUSE_BASE,
                params={"ipAddress": ip, "maxAgeInDays": 30},
                headers={"Key": api_key, "Accept": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                result["malicious"] = score >= 80
                result["score"] = score
                result["raw"] = data
    except Exception as exc:
        logger.warning("abuseipdb_error", ip=ip, error=str(exc))
    await cache.set("abuseipdb", ip, result)
    return result


async def urlhaus_check(url: str, cache: L1Cache) -> dict:
    cached = await cache.get("urlhaus", url)
    if cached:
        return cached
    result = {"source": "urlhaus", "ioc": url, "malicious": False, "score": 0, "raw": {}}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(URLHAUS_BASE, data={"url": url})
            if resp.status_code == 200:
                data = resp.json()
                is_mal = data.get("query_status") == "is_malware"
                result["malicious"] = is_mal
                result["score"] = 100 if is_mal else 0
                result["raw"] = data
    except Exception as exc:
        logger.warning("urlhaus_error", error=str(exc))
    await cache.set("urlhaus", url, result)
    return result


def _spamhaus_lookup(ip: str) -> bool:
    """Synchronous reverse-DNS lookup against Spamhaus ZEN."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        rev = ".".join(reversed(parts))
        query = rev + ".zen.spamhaus.org"
        socket.gethostbyname(query)
        return True
    except socket.gaierror:
        return False


async def spamhaus_check(ip: str, cache: L1Cache) -> dict:
    cached = await cache.get("spamhaus", ip)
    if cached:
        return cached
    loop = asyncio.get_event_loop()
    listed = await loop.run_in_executor(None, _spamhaus_lookup, ip)
    result = {
        "source": "spamhaus",
        "ioc": ip,
        "malicious": listed,
        "score": 100 if listed else 0,
        "raw": {"zen_listed": listed},
    }
    await cache.set("spamhaus", ip, result)
    return result


async def misp_check(ioc: str, misp_url: str, misp_key: str, cache: L1Cache) -> dict:
    cached = await cache.get("misp", ioc)
    if cached:
        return cached
    result = {"source": "misp", "ioc": ioc, "malicious": False, "score": 0, "raw": {}}
    if not misp_url or not misp_key:
        return result
    endpoint = misp_url.rstrip("/") + "/attributes/restSearch"
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            resp = await client.post(
                endpoint,
                json={"returnFormat": "json", "value": ioc, "type": "ip-src"},
                headers={"Authorization": misp_key, "Accept": "application/json"},
            )
            if resp.status_code == 200:
                attrs = resp.json().get("response", {}).get("Attribute", [])
                found = len(attrs) > 0
                result["malicious"] = found
                result["score"] = 100 if found else 0
                result["raw"] = {"attribute_count": len(attrs)}
    except Exception as exc:
        logger.warning("misp_error", ioc=ioc, error=str(exc))
    await cache.set("misp", ioc, result)
    return result
