"""
Phase 2 gate tests — Engine 4 Structural, Engine 3 Behavioral, Engine 1 Orchestrator.
"""
import asyncio
import pytest
from unittest.mock import patch, AsyncMock
from app.layer2_ai.structural import run_structural
from app.layer2_ai.behavioral import run_behavioral
from app.layer2_ai.orchestrator import run_layer2



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


# TC-P2-03: New sender gets cold-start neutral score from behavioral engine
def test_behavioral_new_sender(tmp_path, monkeypatch):
    monkeypatch.setattr("app.layer2_ai.behavioral.BASELINE_DIR", str(tmp_path))
    parsed = {"sender_email": "new@unknown.xyz", "sender_domain": "unknown.xyz"}
    result = asyncio.run(run_behavioral(parsed))
    assert result["is_new_sender"] is True
    assert result["score"] == 0.2, f"Cold-start score should be 0.2, got {result}"


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
