"""Tests for flag-gated Gmail bombing ingestion (Phase 2).

INBOX_INGESTION_ENABLED off → fully dormant (no work, no Gmail calls).
On → Gmail-ingested messages feed the SAME shared pipeline as SMTP and get tiered.
The Gmail API is mocked — no real network.
"""
import asyncio
import base64

import app.security.bombing_pipeline as bp
import app.security.bombing_detector as bd
import app.storage as storage
import app.layer7_gmail.pubsub_watcher as pw


class _Settings:
    def __init__(self, enabled=False, impersonate="user@corp.com"):
        self.inbox_ingestion_enabled = enabled
        self.google_admin_impersonate_email = impersonate
        self.gmail_quarantine_label = "PG-Quarantine"
        self.gmail_scanned_label = "PG-Scanned"


def _tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "_DB_PATH", str(tmp_path / "gmail.db"))
    storage.init_db()
    bd._state.clear()


def _parsed(domain, subject):
    return {"sender_domain": domain, "from_header": f"x@{domain}", "subject": subject,
            "sender_email": f"x@{domain}", "return_path": "", "spf_result": "unknown"}


def _raw(frm, subj, extra=b""):
    return f"From: {frm}\r\nSubject: {subj}\r\n".encode() + extra + b"\r\nbody"


def test_flag_off_is_fully_dormant(tmp_path, monkeypatch):
    _tmp(tmp_path, monkeypatch)
    out = bp.ingest_gmail_message(_parsed("promo.com", "Confirm your email"),
                                  _raw("x@promo.com", "Confirm your email"),
                                  _Settings(enabled=False))
    assert out is None
    # nothing was recorded — the inbox is untouched
    assert bd.is_first_contact("user@corp.com", "x@promo.com") is True


def test_flag_on_feeds_detector_and_tiers(tmp_path, monkeypatch):
    _tmp(tmp_path, monkeypatch)
    s = _Settings(enabled=True, impersonate="user@corp.com")
    last = None
    for i in range(bd.VELOCITY_THRESHOLD):
        last = bp.ingest_gmail_message(_parsed(f"d{i}.com", "Confirm your email"),
                                       _raw(f"x@d{i}.com", "Confirm your email"),
                                       s, scan_id=f"g{i}")
    assert bd.is_under_attack("user@corp.com")
    assert last["under_attack"] is True
    # a noise email gets buffered via the Gmail path, same as SMTP
    bp.ingest_gmail_message(_parsed("promo.com", "Newsletter"),
                            _raw("news@promo.com", "Newsletter", b"List-Unsubscribe: <u@promo.com>\r\n"),
                            s, scan_id="gx")
    held = storage.buffer_list_for_recipient("user@corp.com")
    assert held and all(h["tier"] in ("noise", "uncertain") for h in held)


def test_pubsub_path_calls_shared_pipeline_when_enabled(tmp_path, monkeypatch):
    _tmp(tmp_path, monkeypatch)
    s = _Settings(enabled=True)
    monkeypatch.setattr(pw, "fetch_new_message_ids", lambda settings, hid: ["m1"])
    monkeypatch.setattr(pw, "fetch_raw_message",
                        lambda settings, mid: _raw("x@promo.com", "Confirm your email"))
    monkeypatch.setattr(pw, "apply_label", lambda *a, **k: True)
    captured = {}
    monkeypatch.setattr("app.security.bombing_pipeline.ingest_gmail_message",
                        lambda parsed, raw, settings, scan_id="": captured.update(called=True, scan_id=scan_id))

    async def fake_analyze(raw, settings):
        return {"verdict": "clean", "email_id": "e1",
                "parsed": _parsed("promo.com", "Confirm your email")}

    body = {"message": {"data": base64.b64encode(b'{"historyId":"123"}').decode()}}
    out = asyncio.run(pw.handle_push_notification(body, fake_analyze, s))
    assert out["status"] == "ok"
    assert captured.get("called") is True       # shared pipeline was invoked
    assert captured.get("scan_id") == "e1"
