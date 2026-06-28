"""Receiver-level acceptance tests for the bombing triage wiring (Phase 1B).

The key guarantees, exercised end-to-end through handle_DATA with mocked Gmail/network:
  - an authenticated critical email is DELIVERED instantly mid-bomb, NOT buffered
  - structural noise is BUFFERED (durable), not delivered now
Bombing mode + first-contact are forced deterministically; DKIM is mocked.
"""
import asyncio

import app.layer7_gmail.smtp_receiver as rcv
import app.security.bombing_detector as bd
import app.storage as storage


class _Env:
    def __init__(self, content, mail_from, rcpts):
        self.content = content
        self.mail_from = mail_from
        self.rcpt_tos = rcpts


class _Sess:
    peer = ("198.51.100.7", 5555)


class _Srv:
    transport = None


def _setup(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "_DB_PATH", str(tmp_path / "recv.db"))
    storage.init_db()
    bd._state.clear()
    # Force active bombing mode for the handler path (record() → under_attack=True).
    monkeypatch.setattr(bd, "record", lambda *a, **k: (True, False))


def _mock_deliver(monkeypatch, sink):
    monkeypatch.setattr(
        "app.layer7_gmail.gmail_client.deliver_to_inbox",
        lambda settings, raw, label="": (sink.append(raw) or True),
    )


def test_tier1_authenticated_delivered_not_buffered(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(bd, "is_first_contact", lambda *a, **k: False)
    import dkim

    class _FakeDKIM:
        def __init__(self, raw, *a, **k):
            self.domain = b"hdfc.bank"; self.signature_fields = {b"h": b"from"}
        def verify(self, idx=0, **k):
            self.domain = b"hdfc.bank"; self.signature_fields = {b"h": b"from"}; return True
    monkeypatch.setattr(dkim, "DKIM", _FakeDKIM)
    delivered = []
    _mock_deliver(monkeypatch, delivered)

    async def _analyze(raw, settings):
        return {"verdict": "clean", "confidence": 0.1, "email_id": "scan-1",
                "l2": {"verdict": "clean"},
                "parsed": {"from_header": "alerts@hdfc.bank", "subject": "OTP code 1",
                           "sender_domain": "hdfc.bank"}}

    handler = rcv.PhishGuardSMTPHandler(_analyze, object())
    raw = (b"From: alerts@hdfc.bank\r\n"
           b"DKIM-Signature: v=1; a=rsa-sha256; d=hdfc.bank; s=s; h=from; bh=a; b=b\r\n"
           b"Subject: OTP code 1\r\n\r\nbody")
    resp = asyncio.run(handler.handle_DATA(_Srv(), _Sess(), _Env(raw, "alerts@hdfc.bank", ["victim@co.com"])))

    assert resp == "250 OK"
    assert len(delivered) == 1                              # delivered to inbox
    assert b"[PhishGuard-Priority]" in delivered[0]          # tagged priority
    assert storage.buffer_list_for_recipient("victim@co.com") == []   # NOT buffered


def test_tier2_noise_buffered_not_delivered(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(bd, "is_first_contact", lambda *a, **k: True)   # → Tier 2
    delivered = []
    _mock_deliver(monkeypatch, delivered)

    async def _analyze(raw, settings):
        return {"verdict": "clean", "confidence": 0.1, "email_id": "scan-2",
                "l2": {"verdict": "clean"},
                "parsed": {"from_header": "news@promo.com", "subject": "Newsletter",
                           "sender_domain": "promo.com"}}

    handler = rcv.PhishGuardSMTPHandler(_analyze, object())
    raw = (b"From: news@promo.com\r\nList-Unsubscribe: <mailto:u@promo.com>\r\n"
           b"Subject: Newsletter\r\n\r\nbody")
    resp = asyncio.run(handler.handle_DATA(_Srv(), _Sess(), _Env(raw, "news@promo.com", ["victim@co.com"])))

    assert resp == "250 OK"
    assert delivered == []                                  # buffered, not delivered now
    held = storage.buffer_list_for_recipient("victim@co.com")
    assert len(held) == 1
    assert held[0]["tier"] == "noise"
