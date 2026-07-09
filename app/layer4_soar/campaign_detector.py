"""Campaign detector — clusters phishing/suspicious emails into attack campaigns.

Two clustering dimensions:
  1. Normalized sender domain  — strips year/number suffixes so
     payment-hub-2026.com, payment-hub-2027.com → cluster "payment-hub"
  2. NLP intent                — groups emails sharing the same attack
     type (credential_harvesting, bec_fraud, brand_impersonation …)

A cluster with ≥ MIN_EMAILS members within the detection window = campaign.
"""
import json
import re
from app import db as _db
import time
from collections import defaultdict
from datetime import UTC, datetime


MIN_EMAILS   = 3    # minimum cluster size to declare a campaign
WINDOW_DAYS  = 7    # look-back window in days


def _normalize_domain(domain: str) -> str:
    """Strip TLD and trailing year/number suffixes for clustering."""
    if not domain:
        return ""
    domain = domain.lower().strip()
    # Remove common TLDs
    parts = domain.split(".")
    base = ".".join(parts[:-1]) if len(parts) > 1 else domain
    # Strip trailing -YYYY, -YY, -N suffixes  (e.g. -2026, -01)
    base = re.sub(r"[-_]\d{4}$", "", base)
    base = re.sub(r"[-_]\d{1,3}$", "", base)
    return base if len(base) >= 3 else ""


def _sender_domain(sender: str) -> str:
    if not sender:
        return ""
    m = re.search(r"@([\w.\-]+)", sender)
    return m.group(1).lower() if m else ""


def _extract_intent(data: dict) -> str:
    try:
        return (data.get("l2") or {}).get("engines", {}).get("nlp", {}).get("intent", "") or ""
    except Exception:
        return ""


def detect_campaigns(
    db_path: str = "data/phishguard.db",
    window_days: int = WINDOW_DAYS,
    min_emails: int = MIN_EMAILS,
) -> list[dict]:
    """Return a list of detected campaign dicts, sorted by email count descending."""
    since = time.time() - window_days * 86400

    try:
        conn = _db.connect(db_path)
        rows = conn.execute(
            """SELECT id, ts, verdict, sender, data_json
               FROM scans
               WHERE verdict IN ('phishing','suspicious')
                 AND ts >= ? AND deleted = 0
               ORDER BY ts DESC""",
            (since,),
        ).fetchall()
        conn.close()
    except Exception:
        return []

    emails = []
    for scan_id, ts, verdict, sender, data_json in rows:
        try:
            data = json.loads(data_json) if data_json else {}
        except Exception:
            data = {}

        domain      = _sender_domain(sender or "")
        domain_key  = _normalize_domain(domain)
        intent      = _extract_intent(data)

        emails.append({
            "id":           scan_id,
            "ts":           float(ts),
            "verdict":      verdict,
            "sender":       sender or "",
            "domain":       domain,
            "domain_key":   domain_key,
            "intent":       intent,
        })

    # ── 1. Domain-pattern clusters ────────────────────────────────────────
    domain_groups: dict[str, list] = defaultdict(list)
    for e in emails:
        if e["domain_key"]:
            domain_groups[e["domain_key"]].append(e)

    # ── 2. Intent clusters ────────────────────────────────────────────────
    intent_groups: dict[str, list] = defaultdict(list)
    for e in emails:
        intent = e["intent"]
        if intent and intent not in ("clean", "unknown", ""):
            intent_groups[intent].append(e)

    campaigns: list[dict] = []
    now = time.time()

    for pattern, group in domain_groups.items():
        if len(group) < min_emails:
            continue
        unique_domains = list(dict.fromkeys(e["domain"] for e in group))
        phish_count    = sum(1 for e in group if e["verdict"] == "phishing")
        sus_count      = len(group) - phish_count
        first_seen     = min(e["ts"] for e in group)
        last_seen      = max(e["ts"] for e in group)
        severity       = "critical" if len(group) >= 10 else ("high" if len(group) >= 5 else "medium")
        campaigns.append({
            "id":             f"domain:{pattern}",
            "type":           "domain_pattern",
            "pattern":        pattern,
            "name":           f'Domain pattern — "{pattern}*"',
            "email_count":    len(group),
            "phishing_count": phish_count,
            "suspicious_count": sus_count,
            "unique_domains": unique_domains[:5],
            "first_seen":     first_seen,
            "last_seen":      last_seen,
            "active":         last_seen > now - 86400,
            "severity":       severity,
            "scan_ids":       [e["id"] for e in group],
            "top_intent":     _most_common_intent(group),
        })

    # Intent campaigns — skip if already fully captured by a domain campaign
    domain_campaign_scan_ids: set[str] = set()
    for c in campaigns:
        domain_campaign_scan_ids.update(c["scan_ids"])

    for intent, group in intent_groups.items():
        if len(group) < min_emails:
            continue
        # Only count emails not already in a domain campaign
        fresh = [e for e in group if e["id"] not in domain_campaign_scan_ids]
        if len(fresh) < min_emails:
            continue
        first_seen = min(e["ts"] for e in fresh)
        last_seen  = max(e["ts"] for e in fresh)
        sev_map    = {"bec_fraud": "critical", "credential_harvesting": "high",
                      "brand_impersonation": "high", "executive_impersonation": "critical"}
        severity   = sev_map.get(intent, "medium")
        if len(fresh) >= 10:
            severity = "critical"
        campaigns.append({
            "id":               f"intent:{intent}",
            "type":             "intent",
            "pattern":          intent,
            "name":             intent.replace("_", " ").title() + " Campaign",
            "email_count":      len(fresh),
            "phishing_count":   sum(1 for e in fresh if e["verdict"] == "phishing"),
            "suspicious_count": sum(1 for e in fresh if e["verdict"] == "suspicious"),
            "unique_domains":   list(dict.fromkeys(e["domain"] for e in fresh))[:5],
            "first_seen":       first_seen,
            "last_seen":        last_seen,
            "active":           last_seen > now - 86400,
            "severity":         severity,
            "scan_ids":         [e["id"] for e in fresh],
            "top_intent":       intent,
        })

    campaigns.sort(key=lambda c: c["email_count"], reverse=True)
    return campaigns


def _most_common_intent(group: list) -> str:
    counts: dict[str, int] = defaultdict(int)
    for e in group:
        if e["intent"]:
            counts[e["intent"]] += 1
    return max(counts, key=counts.get) if counts else ""
