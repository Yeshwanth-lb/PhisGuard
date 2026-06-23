"""Tests for app/threatlens/actor_clusterer.py — Phase 1.

All tests use a temp SQLite DB and pre-built scan dicts.
No network calls, no LLM.
"""
import time

import pytest

from app.threatlens.actor_clusterer import (
    _cluster_id,
    extract_signature,
    refresh,
    signature_similarity,
)
from app.threatlens.store import get_cluster, init_db, upsert_cluster
from app.threatlens.models import ActorCluster, IoCSet


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_scan(
    scan_id: str,
    sender: str,
    intent: str = "credential_harvesting",
    verdict: str = "phishing",
    ts: float | None = None,
    sender_ip: str = "",
    asn: str = "",
) -> dict:
    ts = ts if ts is not None else time.time()
    data = {
        "l1": {"sender_ip": sender_ip, "asn": asn, "hits": []},
        "l2": {
            "engines": {
                "nlp": {"intent": intent, "score": 0.9, "tactics": []},
                "structural": {"findings": [], "score": 0.5},
                "behavioral": {"score": 0.3, "tier": 0},
            },
            "verdict": verdict,
            "confidence": 0.9,
        },
    }
    return {"id": scan_id, "ts": ts, "verdict": verdict, "sender": sender, "data": data}


# ── Signature extraction ──────────────────────────────────────────────────────

def test_signature_extraction_strips_year_suffix():
    """Given payment-hub-2026.com / bec_fraud; extract_signature returns
    domain_base='payment-hub' and intent='bec_fraud'."""
    scan = _make_scan("s1", "attacker@payment-hub-2026.com", intent="bec_fraud")
    sig = extract_signature(scan)
    assert sig["domain_base"] == "payment-hub"
    assert sig["intent"]      == "bec_fraud"


# ── Similarity ────────────────────────────────────────────────────────────────

def test_two_year_variant_domains_same_cluster(tmp_path):
    """Given payment-hub-2026.com + payment-hub-2027.com, same intent;
    When refresh; Then 1 cluster, both scans as members."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    now = time.time()
    s1 = _make_scan("s1", "x@payment-hub-2026.com", intent="bec_fraud", ts=now - 100)
    s2 = _make_scan("s2", "x@payment-hub-2027.com", intent="bec_fraud", ts=now - 50)

    clusters = refresh([s1, s2], db_path=db_path)

    assert len(clusters) == 1
    assert "s1" in clusters[0].member_scan_ids
    assert "s2" in clusters[0].member_scan_ids


def test_different_intent_same_domain_similarity_below_threshold():
    """Given acme.com/bec_fraud vs acme.com/credential_harvesting, no shared
    infra; signature_similarity < 0.72 — they should not auto-merge."""
    sig1 = {"domain_base": "acme", "intent": "bec_fraud",              "sender_ip": "", "asn": ""}
    sig2 = {"domain_base": "acme", "intent": "credential_harvesting",  "sender_ip": "", "asn": ""}
    assert signature_similarity(sig1, sig2) < 0.72


def test_shared_infra_raises_similarity():
    """Given different domains, same sender_ip + same ASN;
    signature_similarity >= 0.72."""
    sig1 = {"domain_base": "alpha-pay", "intent": "",   "sender_ip": "5.5.5.5", "asn": "AS12345"}
    sig2 = {"domain_base": "beta-bank", "intent": "",   "sender_ip": "5.5.5.5", "asn": "AS12345"}
    assert signature_similarity(sig1, sig2) >= 0.72


# ── Incremental refresh ───────────────────────────────────────────────────────

def test_incremental_join_does_not_recompute_existing(tmp_path):
    """Given c1=[s1]; When refresh([s2]) where s2 matches;
    Then c1=[s1,s2], no new cluster, created_at unchanged, last_seen updated."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    now = time.time()
    s1 = _make_scan("s1", "a@payment-hub-2026.com", intent="bec_fraud", ts=now - 100)
    s2 = _make_scan("s2", "a@payment-hub-2027.com", intent="bec_fraud", ts=now - 50)

    clusters1 = refresh([s1], db_path=db_path)
    assert len(clusters1) == 1
    original_created_at = clusters1[0].created_at
    original_id         = clusters1[0].id

    clusters2 = refresh([s2], db_path=db_path)
    assert len(clusters2) == 1
    assert clusters2[0].id == original_id
    assert "s1" in clusters2[0].member_scan_ids
    assert "s2" in clusters2[0].member_scan_ids
    assert clusters2[0].created_at == pytest.approx(original_created_at, abs=1.0)
    assert clusters2[0].last_seen  == pytest.approx(now - 50, abs=1.0)


def test_new_scan_no_match_seeds_new_cluster(tmp_path):
    """Given c1 already exists; new s9 has similarity 0.3 with c1;
    Then a second cluster is created with s9 as its sole member."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    s1 = _make_scan("s1", "a@payment-hub-2026.com",  intent="bec_fraud")
    s9 = _make_scan("s9", "z@totally-different.org", intent="brand_impersonation")

    clusters = refresh([s1, s9], db_path=db_path)

    assert len(clusters) == 2
    all_members = [mid for c in clusters for mid in c.member_scan_ids]
    assert "s1" in all_members
    assert "s9" in all_members


def test_stale_cluster_flips_to_dormant(tmp_path):
    """Given c1.last_seen 20 days ago, dormant_days=14;
    When refresh([]); Then c1.status == 'dormant'."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    old_ts = time.time() - 20 * 86400
    stale = ActorCluster(
        id="c1",
        created_at=old_ts,
        updated_at=old_ts,
        first_seen=old_ts,
        last_seen=old_ts,
        member_scan_ids=["s1"],
        dominant_intent="bec_fraud",
        iocs=IoCSet(),
        targets={},
        signature={"domain_base": "old-actor", "intent": "bec_fraud", "sender_ip": "", "asn": ""},
        status="active",
    )
    upsert_cluster(stale, db_path=db_path)

    refresh(new_scans=[], db_path=db_path, dormant_days=14)

    result = get_cluster("c1", db_path=db_path)
    assert result is not None
    assert result.status == "dormant"


def test_clean_scans_excluded_from_clustering(tmp_path):
    """Given verdicts [phishing, suspicious, clean, clean];
    When refresh; Then only the phishing + suspicious scans are members."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    scans = [
        _make_scan("p1", "a@evil-2026.com", verdict="phishing",   intent="bec_fraud"),
        _make_scan("s1", "a@evil-2027.com", verdict="suspicious", intent="bec_fraud"),
        _make_scan("c1", "legit@google.com", verdict="clean",     intent=""),
        _make_scan("c2", "news@bbc.com",     verdict="clean",     intent=""),
    ]
    clusters = refresh(scans, db_path=db_path)

    all_members = {mid for c in clusters for mid in c.member_scan_ids}
    assert "p1" in all_members
    assert "s1" in all_members
    assert "c1" not in all_members
    assert "c2" not in all_members


def test_cluster_id_is_stable_across_runs():
    """Given the same seed scan in two separate calls;
    Then _cluster_id(extract_signature(scan)) is identical both times."""
    scan = _make_scan("s1", "attacker@evil-domain-2026.com", intent="credential_harvesting")
    sig  = extract_signature(scan)
    assert _cluster_id(sig) == _cluster_id(sig)


def test_empty_scan_set_produces_no_clusters(tmp_path):
    """Given no new scans and empty DB;
    When refresh([]); Then [], no writes, no error."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path=db_path)

    result = refresh(new_scans=[], db_path=db_path)
    assert result == []
