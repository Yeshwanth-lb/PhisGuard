"""
Phase 2 gate tests — Engine 4 Structural, Engine 3 Behavioral, Engine 1 Orchestrator.
"""
import asyncio

from app.layer2_ai.behavioral import run_behavioral
from app.layer2_ai.orchestrator import run_layer2
from app.layer2_ai.structural import run_structural


# TC-P2-01: Brand impersonation raises structural score
def test_structural_brand_impersonation():
    parsed = {
        "sender_domain": "paypal-login.com",
        "from_header": "PayPal Security <security@paypal-login.com>",
        "reply_to": "",
        "body_html": "",
    }
    result = asyncio.run(run_structural(parsed))
    assert result["score"] >= 0.8, f"Expected high score, got {result}"
    assert any("brand_impersonation" in f for f in result["findings"])


# TC-P2-02: SPF+DKIM failures raise structural score
def test_structural_auth_failures():
    parsed = {
        "sender_domain": "legitimate.com",
        "from_header": "",
        "reply_to": "",
        "body_html": "",
        "spf_result": "fail",
        "dkim_result": "fail",
    }
    result = asyncio.run(run_structural(parsed))
    assert result["score"] >= 0.6, f"Expected elevated score, got {result}"
    assert any("auth_failures" in f for f in result["findings"])


# TC-P2-03: New sender → Tier 0 cold-start with context scorer
def test_behavioral_new_sender(tmp_path, monkeypatch):
    monkeypatch.setattr("app.layer2_ai.behavioral.BASELINE_DIR", str(tmp_path))
    parsed = {"sender_email": "new@unknown.xyz", "sender_domain": "unknown.xyz"}
    result = asyncio.run(run_behavioral(parsed))
    assert result["is_new_sender"] is True
    assert result["cold_start_tier"] == 0
    assert result["baseline_confidence"] == "none"
    # Tier 0 score = 0.60*ctx + 0.40*iso; with no high-value recipient and no ISO model,
    # ctx ≈ 0.15 (first-email bonus), iso = 0.5 (below min_samples) → ≈ 0.29
    assert 0.0 < result["score"] <= 0.5, f"Cold-start Tier 0 score out of expected range: {result}"


# TC-P2-03b: Tier 0 — email to CFO raises context score
def test_behavioral_tier0_high_value_recipient(tmp_path, monkeypatch):
    monkeypatch.setattr("app.layer2_ai.behavioral.BASELINE_DIR", str(tmp_path))
    parsed = {
        "sender_email": "vendor@new-domain.xyz",
        "sender_domain": "new-domain.xyz",
        "headers": {"To": "cfo@company.com"},
        "subject": "",
    }
    result = asyncio.run(run_behavioral(parsed))
    assert result["cold_start_tier"] == 0
    # CFO recipient bonus (+0.30) → ctx ≥ 0.30
    # Tier 0 final ≥ 0.60 * 0.30 + 0.40 * 0.5 = 0.18 + 0.20 = 0.38
    assert result["score"] >= 0.35, f"Expected elevated score for CFO recipient: {result}"


# TC-P2-03c: Tier 0 — normal employee, no risk signals → low score
def test_behavioral_tier0_low_risk(tmp_path, monkeypatch):
    monkeypatch.setattr("app.layer2_ai.behavioral.BASELINE_DIR", str(tmp_path))
    parsed = {
        "sender_email": "vendor@company.com",
        "sender_domain": "company.com",
        "headers": {"To": "engineer@org.com"},
        "subject": "Q2 report",
    }
    result = asyncio.run(run_behavioral(parsed))
    assert result["cold_start_tier"] == 0
    # No high-value recipient, first email → ctx ≈ 0.15, iso = 0.5 → ≈ 0.29
    assert result["score"] < 0.5, f"Low-risk new sender should be < 0.5: {result}"


# TC-P2-03d: Tier 1 after seeding 3 emails
def test_behavioral_tier1_after_few_emails(tmp_path, monkeypatch):
    import json, os
    monkeypatch.setattr("app.layer2_ai.behavioral.BASELINE_DIR", str(tmp_path))
    parsed = {"sender_email": "known@partner.com", "sender_domain": "partner.com"}

    # Seed 3 emails into baseline
    for _ in range(3):
        asyncio.run(run_behavioral(parsed))

    result = asyncio.run(run_behavioral(parsed))
    assert result["cold_start_tier"] == 1, f"Expected Tier 1 after 3 emails: {result}"
    assert result["baseline_confidence"] == "low"
    assert result["emails_in_baseline"] >= 3


# TC-P2-03e: Tier 3 after seeding 20+ emails — established sender
def test_behavioral_tier3_established_sender(tmp_path, monkeypatch):
    monkeypatch.setattr("app.layer2_ai.behavioral.BASELINE_DIR", str(tmp_path))
    parsed = {
        "sender_email": "alice@trusted.com",
        "sender_domain": "trusted.com",
        "subject": "Weekly sync notes",
        "body_text": "Hi team, here are the notes from today.",
    }
    # Seed 25 emails
    for _ in range(25):
        asyncio.run(run_behavioral(parsed))

    result = asyncio.run(run_behavioral(parsed))
    assert result["cold_start_tier"] == 3, f"Expected Tier 3 after 25 emails: {result}"
    assert result["baseline_confidence"] == "high"
    # Same-pattern email should score low in Tier 3
    assert result["score"] < 0.6, f"Established sender with consistent pattern should score low: {result}"


# TC-P2-A1: Typosquatting detection (Levenshtein ≤ 2)
def test_structural_typosquatting():
    parsed = {
        "sender_domain": "micosoft.com",  # 1 char off from "microsoft"
        "from_header": "",
        "reply_to": "",
        "body_html": "",
    }
    result = asyncio.run(run_structural(parsed))
    assert result["score"] >= 0.7, f"Typosquatting should score high: {result}"
    assert any("typosquatting" in f for f in result["findings"]), result["findings"]


# TC-P2-A2: Reply-To mismatch
def test_structural_reply_to_mismatch():
    parsed = {
        "sender_domain": "company.com",
        "from_header": "CEO <ceo@company.com>",
        "reply_to": "attacker@gmail.com",
        "body_html": "",
    }
    result = asyncio.run(run_structural(parsed))
    assert result["score"] >= 0.6, f"Reply-To mismatch should score ≥ 0.6: {result}"
    assert any("reply_to_mismatch" in f for f in result["findings"]), result["findings"]


# TC-P2-A3: Macro-capable attachment raises attachment_risk to critical
def test_structural_macro_attachment():
    parsed = {
        "sender_domain": "legit.com",
        "from_header": "",
        "reply_to": "",
        "body_html": "",
        "attachments": [
            {"filename": "invoice.docm", "content_type": "application/vnd.ms-word.document.macroEnabled.12", "sha256": "abc", "size": 1024},
        ],
    }
    result = asyncio.run(run_structural(parsed))
    assert result["attachment_risk"] == "critical", f"macroEnabled docm should be critical: {result}"
    assert result["score"] >= 0.9, f"Expected critical score for macro attachment: {result}"


# TC-P2-A4: Clean email has very low structural score
def test_structural_clean_email():
    parsed = {
        "sender_domain": "google.com",
        "from_header": "Google <noreply@google.com>",
        "reply_to": "",
        "body_html": "",
        "spf_result": "pass",
        "dkim_result": "pass",
        "dmarc_result": "pass",
    }
    result = asyncio.run(run_structural(parsed))
    assert result["score"] < 0.5, f"Clean email from google.com should score low: {result}"


# TC-P2-04: Orchestrator produces high-risk verdict for brand impersonation + auth fails
def test_orchestrator_high_risk_verdict():
    parsed = {
        "sender_domain": "amazon-verify.net",
        "from_header": "Amazon <noreply@amazon-verify.net>",
        "reply_to": "",
        "body_html": "",
        "spf_result": "fail",
        "dkim_result": "fail",
        "dmarc_result": "fail",
        "sender_email": "noreply@amazon-verify.net",
    }

    class FakeSettings:
        openai_api_key = ""

    result = asyncio.run(run_layer2(parsed, FakeSettings()))
    # No OpenAI key: NLP degrades to 0.0; structural must score high on its own
    assert result["engine_scores"]["structural"] >= 0.8
    assert "verdict" in result and "confidence" in result
