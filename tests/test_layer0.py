"""Tests for Layer 0 trivial-clean pre-filter."""
import pytest

from app.layer0.pre_filter import MAX_BODY_LEN, run_layer0

_CLEAN = {
    "body_text": "Hi, can you join the 3pm call?",
    "subject": "Quick call",
    "attachment_hashes": [],
}


class TestLayer0HappyPath:
    def test_returns_clean_verdict(self):
        r = run_layer0(_CLEAN, [], "pass", "pass")
        assert r is not None
        assert r["verdict"] == "clean"
        assert r["confidence"] == 0.02
        assert r["fast_path"] == "layer0_trivial_clean"

    def test_metadata_fields_present(self):
        r = run_layer0(_CLEAN, [], "pass", "pass")
        assert r["l0"]["spf"]  == "pass"
        assert r["l0"]["dkim"] == "pass"
        assert r["l0"]["url_count"] == 0
        assert r["l0"]["attachment_count"] == 0
        assert r["l0"]["body_len"] == len(_CLEAN["body_text"].strip())

    def test_body_at_exact_limit_passes(self):
        parsed = {**_CLEAN, "body_text": "x" * MAX_BODY_LEN}
        assert run_layer0(parsed, [], "pass", "pass") is not None


class TestLayer0AuthFailures:
    def test_spf_fail(self):
        assert run_layer0(_CLEAN, [], "fail", "pass") is None

    def test_spf_unknown(self):
        assert run_layer0(_CLEAN, [], "unknown", "pass") is None

    def test_dkim_fail(self):
        assert run_layer0(_CLEAN, [], "pass", "fail") is None

    def test_dkim_unknown(self):
        assert run_layer0(_CLEAN, [], "pass", "unknown") is None

    def test_both_fail(self):
        assert run_layer0(_CLEAN, [], "fail", "fail") is None


class TestLayer0ContentFailures:
    def test_url_present(self):
        assert run_layer0(_CLEAN, ["http://example.com"], "pass", "pass") is None

    def test_multiple_urls(self):
        assert run_layer0(_CLEAN, ["http://a.com", "http://b.com"], "pass", "pass") is None

    def test_attachment_present(self):
        parsed = {**_CLEAN, "attachment_hashes": ["abc123"]}
        assert run_layer0(parsed, [], "pass", "pass") is None

    def test_body_too_long(self):
        parsed = {**_CLEAN, "body_text": "x" * (MAX_BODY_LEN + 1)}
        assert run_layer0(parsed, [], "pass", "pass") is None


class TestLayer0UrgencyKeywords:
    @pytest.mark.parametrize("phrase", [
        "Please verify your account now",
        "Your account has been suspended",
        "Act now before it expires",
        "Wire transfer required immediately",
        "Confirm your password",
        "Unusual sign-in detected",
    ])
    def test_urgency_in_body(self, phrase):
        parsed = {**_CLEAN, "body_text": phrase}
        assert run_layer0(parsed, [], "pass", "pass") is None

    def test_urgency_in_subject(self):
        parsed = {**_CLEAN, "subject": "Action Required: verify your account"}
        assert run_layer0(parsed, [], "pass", "pass") is None

    def test_non_urgent_body_passes(self):
        parsed = {**_CLEAN, "body_text": "Thanks for the update, see you tomorrow."}
        assert run_layer0(parsed, [], "pass", "pass") is not None
