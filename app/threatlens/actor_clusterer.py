"""Actor clusterer — groups phishing/suspicious scans into candidate adversary clusters.

Extends the existing campaign detector's normalization helpers with a richer
composite signature (domain_base + intent + shared infrastructure) and
incremental, idempotent cluster refresh.

No external calls, no LLM — pure scan-data processing.
"""
import hashlib
import json
import os
from app import db as _db
import time

from app.layer4_soar.campaign_detector import (
    _extract_intent,
    _normalize_domain,
    _sender_domain,
)
from app.threatlens import store as _store
from app.threatlens.models import ActorCluster, IoCSet

_DB_PATH = os.environ.get('PHISHGUARD_DB_PATH', 'data/phishguard.db')

# Similarity weights — chosen so that:
#   domain_base + intent  = 0.40 + 0.35 = 0.75 ≥ 0.72  (year-variant domains with same intent cluster)
#   shared_ip + shared_asn = 0.45 + 0.30 = 0.75 ≥ 0.72  (shared C2 infrastructure clusters)
#   domain_base alone      = 0.40 < 0.72  (different-intent same-domain stays separate)
_W_DOMAIN = 0.40
_W_INTENT = 0.75   # intent-dominant: same attack-playbook merges into one campaign even
                   # across different sender domains (consolidates tiny near-duplicate clusters)
_W_IP     = 0.45
_W_ASN    = 0.30


def extract_signature(scan: dict) -> dict:
    """Extract the clustering signature from a scan dict.

    Returns a dict with keys: domain_base, intent, sender_ip, asn.
    Any field may be an empty string when data is absent.
    """
    sender = scan.get("sender") or ""
    data   = scan.get("data") or {}

    domain      = _sender_domain(sender)
    domain_base = _normalize_domain(domain)
    intent      = _extract_intent(data)

    l1         = data.get("l1") or {}
    sender_ip  = str(l1.get("sender_ip") or "").strip()
    asn        = str(l1.get("asn") or "").strip()

    return {
        "domain_base": domain_base,
        "intent":      intent,
        "sender_ip":   sender_ip,
        "asn":         asn,
    }


def signature_similarity(sig1: dict, sig2: dict) -> float:
    """Return a similarity score in [0.0, 1.0] between two cluster signatures."""
    score = 0.0

    d1,   d2   = sig1.get("domain_base") or "", sig2.get("domain_base") or ""
    i1,   i2   = sig1.get("intent")      or "", sig2.get("intent")      or ""
    ip1,  ip2  = sig1.get("sender_ip")   or "", sig2.get("sender_ip")   or ""
    asn1, asn2 = sig1.get("asn")         or "", sig2.get("asn")         or ""

    if d1   and d2   and d1   == d2:   score += _W_DOMAIN
    if i1   and i2   and i1   == i2:   score += _W_INTENT
    if ip1  and ip2  and ip1  == ip2:  score += _W_IP
    if asn1 and asn2 and asn1 == asn2: score += _W_ASN

    return min(score, 1.0)


def _cluster_id(sig: dict) -> str:
    """Stable, deterministic 16-char hex ID derived from the seed signature."""
    canonical = json.dumps(
        {k: sig.get(k, "") for k in sorted(sig)},
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _extract_iocs(scan: dict) -> IoCSet:
    """Pull observable IoCs from a scan dict (sender domain/IP, L1 hits)."""
    data = scan.get("data") or {}
    l1   = data.get("l1") or {}

    domains: list[str] = []
    ips:     list[str] = []

    sender_domain = _sender_domain(scan.get("sender") or "")
    if sender_domain:
        domains.append(sender_domain)

    sender_ip = str(l1.get("sender_ip") or "").strip()
    if sender_ip:
        ips.append(sender_ip)

    for hit in l1.get("hits") or []:
        h = str(hit).strip()
        if not h:
            continue
        # Heuristic: if it contains a letter it's a domain, otherwise an IP
        if any(c.isalpha() for c in h):
            if h not in domains:
                domains.append(h)
        else:
            if h not in ips:
                ips.append(h)

    return IoCSet(
        domains=list(dict.fromkeys(domains)),
        ips=list(dict.fromkeys(ips)),
    )


def _load_scans_from_db(db_path: str) -> list[dict]:
    """Load all phishing + suspicious scans from the scans table."""
    try:
        conn = _db.connect(db_path)
        rows = conn.execute(
            """SELECT id, ts, verdict, sender, data_json
               FROM scans
               WHERE verdict IN ('phishing', 'suspicious') AND deleted = 0
               ORDER BY ts ASC"""
        ).fetchall()
        conn.close()
    except Exception:
        return []

    result = []
    for row in rows:
        try:
            data = json.loads(row["data_json"]) if row["data_json"] else {}
        except Exception:
            data = {}
        result.append({
            "id":      row["id"],
            "ts":      float(row["ts"]),
            "verdict": row["verdict"],
            "sender":  row["sender"] or "",
            "data":    data,
        })
    return result


def refresh(
    new_scans: list[dict] | None = None,
    db_path:       str   = _DB_PATH,
    sim_threshold: float = 0.72,
    dormant_days:  int   = 14,
) -> list[ActorCluster]:
    """Incremental cluster refresh.

    If new_scans is provided, only those are processed.
    Otherwise all phishing/suspicious scans are loaded from the DB.

    Returns the list of active clusters after the run.
    Idempotent: re-running on unchanged input updates in place, no duplicates.
    """
    # 1. Load and filter scans
    scans = new_scans if new_scans is not None else _load_scans_from_db(db_path)
    scans = [s for s in scans if s.get("verdict") in ("phishing", "suspicious")]

    # 2. Load existing clusters (active + dormant)
    existing: dict[str, ActorCluster] = {
        c.id: c for c in _store.get_all_clusters(db_path=db_path)
    }

    if not scans and not existing:
        return []

    now = time.time()

    # 3. Match each scan to an existing cluster or seed a new one
    for scan in scans:
        sig     = extract_signature(scan)
        scan_id = scan["id"]
        scan_ts = float(scan.get("ts") or now)

        # Skip scans with no meaningful signal
        if not sig.get("domain_base") and not sig.get("intent"):
            continue

        best_id:  str | None = None
        best_sim: float      = 0.0
        for cid, cluster in existing.items():
            if cluster.status == "merged":
                continue
            sim = signature_similarity(sig, cluster.signature)
            if sim >= sim_threshold and sim > best_sim:
                best_sim = sim
                best_id  = cid

        if best_id:
            cluster = existing[best_id]
            if scan_id not in cluster.member_scan_ids:
                cluster.member_scan_ids.append(scan_id)
            cluster.last_seen  = max(cluster.last_seen, scan_ts)
            cluster.updated_at = now
            # Re-activate dormant clusters that see new activity
            if cluster.status == "dormant":
                cluster.status = "active"
            if not cluster.dominant_intent and sig.get("intent"):
                cluster.dominant_intent = sig["intent"]
        else:
            new_id = _cluster_id(sig)
            if new_id not in existing:
                existing[new_id] = ActorCluster(
                    id=new_id,
                    created_at=now,
                    updated_at=now,
                    first_seen=scan_ts,
                    last_seen=scan_ts,
                    member_scan_ids=[scan_id],
                    dominant_intent=sig.get("intent") or None,
                    iocs=_extract_iocs(scan),
                    targets={"recipients": [], "segments": []},
                    signature=sig,
                    status="active",
                )
            else:
                # Rare hash collision on 16-char prefix — absorb into the existing cluster
                existing[new_id].member_scan_ids.append(scan_id)

    # 4. Flip stale clusters to dormant
    cutoff = now - dormant_days * 86400
    for cluster in existing.values():
        if cluster.status == "active" and cluster.last_seen < cutoff:
            cluster.status     = "dormant"
            cluster.updated_at = now

    # 5. Persist all clusters
    for cluster in existing.values():
        _store.upsert_cluster(cluster, db_path=db_path)

    return [c for c in existing.values() if c.status == "active"]
