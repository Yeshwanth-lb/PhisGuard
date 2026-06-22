"""Aggregate Layer 1 OSINT + email-auth results into a single L1 verdict."""
import asyncio

import structlog

from app.layer1.osint_client import (
    abuseipdb_check,
    misp_check,
    spamhaus_check,
    urlhaus_check,
    vt_check_ip,
    vt_check_url,
)
from app.layer1.osint_v2 import (
    _domain_of,
    dkim_check,
    dmarc_check,
    domain_age_check,
    gsb_check,
    phishtank_check,
    spf_check,
)
from app.layer4_soar import denylist as deny_store

logger = structlog.get_logger()

# Domains we unconditionally trust — no OSINT checks run against their emails.
# These are major platforms whose URLs often appear in threat databases due to
# abuse by third parties, causing false positives on legitimate emails.
TRUSTED_SENDER_DOMAINS = {
    # Job / professional
    "linkedin.com", "indeed.com", "glassdoor.com", "naukri.com",
    "monster.com", "hackerearth.com", "hackerrank.com", "internshala.com",
    "shine.com", "foundit.in", "hirist.com",
    # Big tech
    "google.com", "gmail.com", "accounts.google.com", "mail.google.com",
    "microsoft.com", "live.com", "outlook.com", "office.com",
    "apple.com", "amazon.com", "amazonaws.com",
    # Communication / productivity
    "slack.com", "zoom.us", "teams.microsoft.com", "github.com",
    "notion.so", "atlassian.com", "jira.com", "confluence.com",
    "discord.com", "tryhackme.com",
    # Finance / banking
    "paypal.com", "stripe.com", "razorpay.com", "paytm.com",
    "sbi.co.in", "communications.sbi.co.in", "hdfcbank.com",
    "icicibank.com", "axisbank.com",
    # Social / apps
    "email.snapchat.com", "snapchat.com", "instagram.com",
    "twitter.com", "facebook.com",
    # Education / learning
    "coursera.org", "udemy.com", "edx.org", "use.ai", "heygen.com",
    # Indian e-commerce / brands
    "bewakoof.com", "myntra.com", "flipkart.com", "amazon.in",
    "meesho.com", "ajio.com", "nykaa.com", "swiggy.com", "zomato.com",
    # Cybersecurity / dev tools (common in developer inboxes)
    "leetcode.com", "hackthenorth.com", "replit.com", "cursor.com",
    "paperpal.com", "consensus.app", "maltego.com", "canva.com",
    # Notifications / marketing from known brands
    "email.openai.com", "coursera.org",
    # Org domain
    "skylo.tech",
}

_trusted_cache: dict = {"ts": 0.0, "domains": set()}


def _get_all_trusted() -> set:
    """Return hardcoded + user-added trusted domains, cached for 60 seconds."""
    import time as _time
    if _time.time() - _trusted_cache["ts"] > 60:
        try:
            from app import storage as _st
            dynamic = {r["domain"] for r in _st.list_trusted_domains()}
        except Exception:
            dynamic = set()
        _trusted_cache["domains"] = TRUSTED_SENDER_DOMAINS | dynamic
        _trusted_cache["ts"] = _time.time()
    return _trusted_cache["domains"]


MAX_URLS_PER_EMAIL = 10
HARD_QUARANTINE_SOURCES = {
    "virustotal",
    "urlhaus",
    "phishtank",
    "google_safe_browsing",
    "misp",
    "spamhaus",
}
AUX_SOURCES = {
    "abuseipdb",
    "domain_age",
    "spf",
    "dmarc",
    "dkim",
}

ABUSE_QUARANTINE_THRESHOLD = 80
ABUSE_SUSPICIOUS_THRESHOLD = 50
AUX_RISK_THRESHOLD = 60


async def run_layer1(
    sender_ip,
    urls,
    attachment_hashes,
    settings,
    cache,
    sender_email = None,
    raw_eml = None,
    spf_result: str = "unknown",
    dkim_result: str = "unknown",
    dmarc_result: str = "unknown",
):
    """Run all OSINT + auth checks concurrently and return aggregated verdict."""
    # Fast-path for trusted sender domains — BUT only if auth actually passes.
    # If SPF/DKIM fail for a trusted domain it means someone is SPOOFING that
    # domain (e.g. attacker pretending to be LinkedIn). That is MORE suspicious
    # than a random unknown sender, so we flag it immediately instead of trusting.
    if sender_email:
        _addr = sender_email.strip().lower()
        if "<" in _addr and ">" in _addr:
            _addr = _addr.split("<", 1)[1].split(">", 1)[0]
        _sender_domain = _addr.split("@")[-1].strip() if "@" in _addr else ""
        # Match exact domain OR any subdomain (e.g. e.linkedin.com, engagemail.microsoft.com)
        _all_trusted = _get_all_trusted()
        if _sender_domain in _all_trusted or \
           any(_sender_domain.endswith('.' + td) for td in _all_trusted):
            spf_pass  = spf_result  == "pass"
            dkim_pass = dkim_result == "pass"
            spf_fail  = spf_result  == "fail"
            dkim_fail = dkim_result == "fail"

            if spf_fail or dkim_fail:
                # Hard auth failure for a trusted domain = spoofing attempt.
                # Attackers can forge the From: header but cannot pass SPF/DKIM
                # because they don't control the real domain's servers/keys.
                logger.warning(
                    "l1_trusted_domain_spoofed",
                    domain=_sender_domain,
                    spf=spf_result, dkim=dkim_result,
                )
                return {
                    "verdict": "suspicious",
                    "hits": [],
                    "weak_hits": [{
                        "source": "spoof_detection",
                        "ioc": _sender_domain,
                        "malicious": True,
                        "score": 80,
                        "reason": (
                            f"SPOOFING DETECTED: email claims to be from "
                            f"{_sender_domain} (trusted platform) but "
                            f"SPF={spf_result} DKIM={dkim_result} — "
                            f"authentication failed. Real emails from this "
                            f"domain always pass both checks."
                        ),
                    }],
                    "detail_list": [],
                    "spoofed_trusted_domain": True,
                }

            if spf_pass and dkim_pass:
                # Both pass — genuinely from the trusted platform
                logger.info("l1_trusted_sender", domain=_sender_domain)
                return {
                    "verdict": "clean",
                    "hits": [], "weak_hits": [], "detail_list": [],
                    "trusted_sender": True,
                }

            # Auth is "unknown" — Authentication-Results header missing or unparseable.
            # This is common for emails fetched via Gmail API (historical scanner) where
            # the header format varies. "unknown" is NOT "fail" — there is no evidence
            # of spoofing, just missing evidence of authenticity.
            # For trusted domains, treat unknown auth as clean (low confidence).
            # The false-positive cost of running L2+L3 on LinkedIn/Google emails
            # (sandbox opens their login pages → flagged as credential harvesting)
            # is far higher than the theoretical risk of a spoofed email with no
            # Authentication-Results header at all.
            logger.info(
                "l1_trusted_domain_auth_unknown",
                domain=_sender_domain,
                spf=spf_result, dkim=dkim_result,
            )
            return {
                "verdict": "clean",
                "hits": [], "weak_hits": [], "detail_list": [],
                "trusted_sender": True,
                "trusted_sender_auth": "unknown",
            }

    deny_hits = []
    if sender_email:
        addr = sender_email.strip().lower()
        if "<" in addr and ">" in addr:
            addr = addr.split("<", 1)[1].split(">", 1)[0]
        d = deny_store.is_denied("sender", addr)
        if d:
            deny_hits.append({"provider": "denylist", "kind": "sender", "value": addr, "reason": d[0]})
        if "@" in addr:
            dom = addr.split("@")[-1]
            d = deny_store.is_denied("domain", dom)
            if d:
                deny_hits.append({"provider": "denylist", "kind": "domain", "value": dom, "reason": d[0]})
    if sender_ip:
        d = deny_store.is_denied("ip", sender_ip)
        if d:
            deny_hits.append({"provider": "denylist", "kind": "ip", "value": sender_ip, "reason": d[0]})
    if deny_hits:
        logger.info("l1_denylist_block", entries=deny_hits)
        return {"verdict": "quarantine", "hits": deny_hits, "checked": 1, "weak_total": 0, "abuse_max": 0}
    tasks = []
    pt_key = getattr(settings, 'phishtank_api_key', '')
    gsb_key = getattr(settings, 'google_safe_browsing_api_key', '')
    age_threshold = getattr(settings, 'l1_domain_age_days', 30)

    if sender_ip:
        tasks.append(vt_check_ip(sender_ip, settings.virustotal_api_key, cache))
        tasks.append(abuseipdb_check(sender_ip, settings.abuseipdb_api_key, cache))
        tasks.append(spamhaus_check(sender_ip, cache))
        tasks.append(misp_check(sender_ip, settings.misp_url, settings.misp_api_key, cache))

    sender_domain = _domain_of(sender_email) if sender_email else None
    if sender_domain:
        tasks.append(domain_age_check(sender_domain, cache, age_threshold))
        tasks.append(spf_check(sender_domain, cache))
        tasks.append(dmarc_check(sender_domain, cache))
        tasks.append(dkim_check(raw_eml, cache, sender_domain))

    for url in urls[:MAX_URLS_PER_EMAIL]:
        tasks.append(vt_check_url(url, settings.virustotal_api_key, cache))
        tasks.append(urlhaus_check(url, cache))
        tasks.append(phishtank_check(url, pt_key, cache))
        tasks.append(gsb_check(url, gsb_key, cache))
        domain = _domain_of(url)
        if domain:
            tasks.append(domain_age_check(domain, cache, age_threshold))

    if not tasks:
        return {'verdict': 'clean', 'hits': [], 'weak_hits': [], 'detail_list': []}

    results = await asyncio.gather(*tasks, return_exceptions=True)
    hits = []
    weak_hits = []
    detail_list = []
    abuse_max = 0
    weak_total = 0

    for r in results:
        if isinstance(r, Exception):
            logger.warning('l1_task_error', error=str(r))
            continue
        detail_list.append(r)
        src = r.get('source', '')
        if src in HARD_QUARANTINE_SOURCES and r.get('malicious'):
            hits.append(r)
        elif src in AUX_SOURCES:
            if r.get('malicious') or r.get('score', 0) > 0:
                weak_hits.append(r)
                weak_total += r.get('score', 0)
        if src == 'abuseipdb':
            abuse_max = max(abuse_max, r.get('score', 0))

    if hits:
        # Hard OSINT source confirmed malicious (VirusTotal, URLhaus, PhishTank, MISP, Spamhaus)
        verdict = 'quarantine'
    elif abuse_max >= ABUSE_QUARANTINE_THRESHOLD:
        # Sender IP has very high abuse confidence score
        verdict = 'quarantine'
    elif abuse_max >= ABUSE_SUSPICIOUS_THRESHOLD:
        # Sender IP has moderate abuse score — suspicious but don't quarantine yet
        verdict = 'suspicious'
    elif weak_total > 0:
        # Soft signals only (domain age, auth failures) — flag as suspicious for L2 analysis
        # Never quarantine on soft signals alone; L2 AI will make the real call
        verdict = 'suspicious'
    else:
        verdict = 'clean'

    logger.info('l1_verdict', verdict=verdict, hits=len(hits), weak=len(weak_hits), checked=len(detail_list), abuse_max=abuse_max, weak_total=weak_total)
    return {
        'verdict': verdict,
        'hits': hits,
        'weak_hits': weak_hits,
        'detail_list': detail_list,
        'abuse_max_score': abuse_max,
        'weak_total_score': weak_total,
    }
