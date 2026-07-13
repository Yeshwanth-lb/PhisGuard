"""Authenticated-sender fast-pass (option 2): a DMARC-aligned, established, non-abusive
sender isn't condemned by content tactics — fixes OTP/transactional false positives.
Safety: requires alignment AND reputation (not new domain, not abusive IP).

Layers are mocked (they need network); DKIM is mocked per-signature.
"""
import asyncio

import app.pipeline as pipeline


def _raw(from_addr="otp@bigbank.com"):
    # Includes a DKIM-Signature header (count matters; content is mocked) + phishy content
    # (OTP + verify link + urgency) that WOULD score as phishing without the fast-pass.
    return (
        f"From: {from_addr}\r\nTo: user@co.com\r\n"
        f"DKIM-Signature: v=1; a=rsa-sha256; d=bigbank.com; s=sel; h=from:subject; bh=a; b=b\r\n"
        f"Subject: Your OTP code is 123456 — verify now\r\n\r\n"
        f"Action required: verify within 24 hours: http://bigbank.com/verify?t=1\r\n"
    ).encode()


class _Settings:
    redis_url = "redis://x"
    auth_sender_fastpass = True
    l1_abuseipdb_threshold = 25
    enable_sandbox = False
    l3_trigger_threshold = 0.45
    ml_model_path = "data/model.pkl"


def _fake_dkim(monkeypatch, verified, dom="bigbank.com", h="from:subject"):
    import dkim

    class _F:
        def __init__(self, raw, *a, **k):
            self.domain = b""; self.signature_fields = {}

        def verify(self, idx=0, **k):
            self.domain = dom.encode(); self.signature_fields = {b"h": h.encode()}
            return verified
    monkeypatch.setattr(dkim, "DKIM", _F)


def _mock_layers(monkeypatch, l1):
    monkeypatch.setattr(pipeline, "run_layer0", lambda *a, **k: None)

    async def _cache(url):
        return object()
    monkeypatch.setattr(pipeline, "get_cache", _cache)

    async def _l1(**k):
        return l1
    monkeypatch.setattr(pipeline, "run_layer1", _l1)

    async def _post(final, settings, raw=b""):
        return final
    monkeypatch.setattr(pipeline, "_post_actions", _post)

    calls = {"l2": 0}

    async def _l2(parsed, settings):
        calls["l2"] += 1
        return {"verdict": "phishing", "confidence": 0.9}   # content looks phishy
    monkeypatch.setattr(pipeline, "run_layer2", _l2)
    return calls


_CLEAN_L1 = {"verdict": "clean", "hits": [], "weak_hits": [], "abuse_max_score": 0}


def test_aligned_established_sender_fast_passes(monkeypatch):
    _fake_dkim(monkeypatch, True)
    calls = _mock_layers(monkeypatch, dict(_CLEAN_L1))
    out = asyncio.run(pipeline.analyze_email(_raw(), _Settings()))
    assert out["verdict"] == "clean" and out.get("authenticated_sender") is True
    assert calls["l2"] == 0          # content analysis skipped for the authed sender


def test_new_domain_does_not_fast_pass(monkeypatch):
    _fake_dkim(monkeypatch, True)
    calls = _mock_layers(monkeypatch, {**_CLEAN_L1, "weak_hits": [{"source": "domain_age"}]})
    out = asyncio.run(pipeline.analyze_email(_raw(), _Settings()))
    assert calls["l2"] == 1 and out["verdict"] == "phishing"   # new domain → no pass


def test_unaligned_does_not_fast_pass(monkeypatch):
    _fake_dkim(monkeypatch, False)                              # DKIM fails to verify
    calls = _mock_layers(monkeypatch, dict(_CLEAN_L1))
    out = asyncio.run(pipeline.analyze_email(_raw(), _Settings()))
    assert calls["l2"] == 1 and out["verdict"] == "phishing"


def test_abusive_ip_does_not_fast_pass(monkeypatch):
    _fake_dkim(monkeypatch, True)
    calls = _mock_layers(monkeypatch, {**_CLEAN_L1, "abuse_max_score": 80})
    out = asyncio.run(pipeline.analyze_email(_raw(), _Settings()))
    assert calls["l2"] == 1 and out["verdict"] == "phishing"


def test_fastpass_disabled_runs_l2(monkeypatch):
    _fake_dkim(monkeypatch, True)
    calls = _mock_layers(monkeypatch, dict(_CLEAN_L1))
    s = _Settings(); s.auth_sender_fastpass = False
    out = asyncio.run(pipeline.analyze_email(_raw(), s))
    assert calls["l2"] == 1 and out["verdict"] == "phishing"   # toggle off → normal flow
