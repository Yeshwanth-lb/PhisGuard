"""Tests for campaign detection module."""
import json
import os
import sqlite3
import tempfile
import time

import pytest

from app.layer4_soar.campaign_detector import _normalize_domain, detect_campaigns


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_db(rows: list) -> str:
    """Create a temp SQLite DB with the given scan rows. Caller must unlink."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE scans (
        id TEXT PRIMARY KEY, ts REAL, verdict TEXT,
        sender TEXT, data_json TEXT, deleted INTEGER DEFAULT 0
    )""")
    for r in rows:
        conn.execute(
            "INSERT INTO scans (id, ts, verdict, sender, data_json, deleted) VALUES (?,?,?,?,?,0)", r
        )
    conn.commit(); conn.close()
    return path


def _row(i, sender, verdict="phishing", intent="credential_harvesting", days_ago=0):
    ts   = time.time() - days_ago * 86400
    data = {"l2": {"engines": {"nlp": {"intent": intent}}}}
    return (f"scan-{i}", ts, verdict, sender, json.dumps(data))


# ── Domain normalisation ──────────────────────────────────────────────────────

class TestNormalizeDomain:
    def test_strips_year(self):
        assert _normalize_domain("payment-hub-2026.com") == "payment-hub"

    def test_strips_number(self):
        assert _normalize_domain("account-portal-01.net") == "account-portal"

    def test_removes_tld(self):
        assert _normalize_domain("paypal.com") == "paypal"

    def test_empty_input(self):
        assert _normalize_domain("") == ""

    def test_short_result_discarded(self):
        # "ab.com" → base "ab" → len 2 < 3 → excluded
        assert _normalize_domain("ab.com") == ""

    def test_multi_segment_domain(self):
        assert _normalize_domain("secure.paypa1-verify.com") == "secure.paypa1-verify"


# ── Campaign detection ────────────────────────────────────────────────────────

class TestDetectCampaigns:
    def test_empty_db(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE scans (id TEXT, ts REAL, verdict TEXT, sender TEXT, data_json TEXT, deleted INTEGER DEFAULT 0)")
        conn.commit(); conn.close()
        assert detect_campaigns(path) == []
        os.unlink(path)

    def test_below_min_no_campaign(self):
        rows = [_row(i, "x@paypa1-verify.com") for i in range(2)]
        path = _make_db(rows)
        assert detect_campaigns(path, min_emails=3) == []
        os.unlink(path)

    def test_domain_pattern_campaign(self):
        rows = [_row(i, f"u{i}@paypa1-verify.com") for i in range(3)]
        path = _make_db(rows)
        result = detect_campaigns(path, min_emails=3)
        assert any("paypa1-verify" in c["pattern"] for c in result)
        os.unlink(path)

    def test_different_year_domains_cluster(self):
        rows = [
            _row(0, "x@payment-hub-2025.com"),
            _row(1, "x@payment-hub-2026.com"),
            _row(2, "x@payment-hub-2027.com"),
        ]
        path = _make_db(rows)
        result = detect_campaigns(path, min_emails=3)
        assert any("payment-hub" in c["pattern"] for c in result)
        os.unlink(path)

    def test_intent_campaign(self):
        # Use completely different base domains so they don't cluster by domain
        # and the intent cluster isn't absorbed by a domain campaign
        domains = ["alpha-corp.com", "beta-systems.net", "gamma-services.io", "delta-tech.biz"]
        rows = [_row(i, f"x@{domains[i]}", intent="bec_fraud") for i in range(4)]
        path = _make_db(rows)
        result = detect_campaigns(path, min_emails=3)
        assert any(c["type"] == "intent" and c["pattern"] == "bec_fraud" for c in result)
        os.unlink(path)

    def test_clean_emails_ignored(self):
        rows = [_row(i, "x@paypa1.com", verdict="clean") for i in range(5)]
        path = _make_db(rows)
        assert detect_campaigns(path, min_emails=3) == []
        os.unlink(path)

    def test_active_flag_recent(self):
        rows = [_row(i, "x@paypa1.com", days_ago=0) for i in range(3)]
        path = _make_db(rows)
        result = detect_campaigns(path, min_emails=3)
        camp = next((c for c in result if "paypa1" in c["pattern"]), None)
        assert camp is not None and camp["active"] is True
        os.unlink(path)

    def test_active_flag_old(self):
        rows = [_row(i, "x@paypa1.com", days_ago=5) for i in range(3)]
        path = _make_db(rows)
        result = detect_campaigns(path, min_emails=3)
        camp = next((c for c in result if "paypa1" in c["pattern"]), None)
        assert camp is not None and camp["active"] is False
        os.unlink(path)

    def test_sorted_by_count_descending(self):
        rows = (
            [_row(i,   "x@paypa1.com")          for i in range(5)] +
            [_row(i+5, "x@micros0ft-alert.net") for i in range(3)]
        )
        path = _make_db(rows)
        result = detect_campaigns(path, min_emails=3)
        assert result[0]["email_count"] >= result[-1]["email_count"]
        os.unlink(path)

    def test_email_count_correct(self):
        rows = [_row(i, "x@paypa1.com") for i in range(4)]
        path = _make_db(rows)
        result = detect_campaigns(path, min_emails=3)
        camp = next((c for c in result if "paypa1" in c["pattern"]), None)
        assert camp is not None and camp["email_count"] == 4
        os.unlink(path)

    def test_bec_severity_critical(self):
        rows = [_row(i, f"x@d{i}.com", intent="bec_fraud") for i in range(3)]
        path = _make_db(rows)
        result = detect_campaigns(path, min_emails=3)
        bec = next((c for c in result if c["pattern"] == "bec_fraud"), None)
        assert bec is not None and bec["severity"] == "critical"
        os.unlink(path)

    def test_window_days_respected(self):
        # 3 old scans outside window, 3 recent ones — only recent cluster
        rows = (
            [_row(i,   "x@old-domain.com", days_ago=10) for i in range(3)] +
            [_row(i+3, "x@new-domain.com", days_ago=1)  for i in range(3)]
        )
        path = _make_db(rows)
        result = detect_campaigns(path, window_days=7, min_emails=3)
        patterns = [c["pattern"] for c in result]
        assert not any("old-domain" in p for p in patterns)
        assert any("new-domain" in p for p in patterns)
        os.unlink(path)
