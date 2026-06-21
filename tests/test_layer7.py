"""Phase 7 gate tests: Google Workspace integration."""
from unittest.mock import MagicMock, patch

import pytest


class FakeSettings:
    google_service_account_json = "credentials/sa.json"
    google_admin_impersonate_email = ""
    smtp_listen_host = "127.0.0.1"
    smtp_listen_port = 2525
    gmail_quarantine_label = "PhishGuard-Quarantine"
    gmail_scanned_label = "PhishGuard-Scanned"


def test_gmail_list_no_credentials():
    from app.layer7_gmail.gmail_client import list_messages
    result = list_messages(FakeSettings())
    assert result == []


def test_gmail_fetch_no_credentials():
    from app.layer7_gmail.gmail_client import fetch_raw_message
    result = fetch_raw_message(FakeSettings(), "fake-id")
    assert result is None


def test_gmail_apply_label_no_credentials():
    from app.layer7_gmail.gmail_client import apply_label
    result = apply_label(FakeSettings(), "fake-id", "Test")
    assert result is False


def test_find_label_id_helper():
    from app.layer7_gmail.gmail_client import _find_label_id
    labels = [{"id": "L1", "name": "Inbox"}, {"id": "L2", "name": "Spam"}]
    assert _find_label_id(labels, "Spam") == "L2"
    assert _find_label_id(labels, "Missing") is None


@pytest.mark.asyncio
async def test_smtp_handler_returns_ok():
    from app.layer7_gmail.smtp_receiver import PhishGuardSMTPHandler
    raw = b"From: test@example.com\r\nSubject: hi\r\n\r\nbody"
    async def fake_analyze(rb, cfg):
        return {"verdict": "clean"}
    hdlr = PhishGuardSMTPHandler(fake_analyze, FakeSettings())
    envelope = MagicMock()
    envelope.content = raw
    session = MagicMock()
    session.peer = ("127.0.0.1", 1234)
    resp = await hdlr.handle_DATA(None, session, envelope)
    assert resp == "250 OK"


@pytest.mark.asyncio
async def test_historical_scan_no_messages():
    from app.layer7_gmail.historical_scanner import scan_inbox
    async def fake_analyze(rb, cfg):
        return {"verdict": "clean"}
    with patch("app.layer7_gmail.historical_scanner.list_messages", return_value=[]):
        result = await scan_inbox(fake_analyze, FakeSettings())
    assert result["total"] == 0
    assert result["scanned"] == 0


@pytest.mark.asyncio
async def test_historical_scan_counts_phishing(tmp_path, monkeypatch):
    import app.layer7_gmail.historical_scanner as hs
    # Use a temp checkpoint DB so test runs are always clean
    monkeypatch.setattr(hs, "_CHECKPOINT_DB", str(tmp_path / "checkpoint.db"))

    from app.layer7_gmail.historical_scanner import scan_inbox
    stubs = [{"id": f"msg-unique-{i}"} for i in range(4)]
    raw_msg = b"From: x@evil.com\r\n\r\nbody"

    async def fake_analyze(rb, cfg):
        return {"verdict": "phishing"}

    with patch("app.layer7_gmail.historical_scanner.list_messages", return_value=stubs), \
         patch("app.layer7_gmail.historical_scanner.fetch_raw_message", return_value=raw_msg), \
         patch("app.layer7_gmail.historical_scanner.apply_label", return_value=True), \
         patch("app.storage.save_scan", return_value=None):
        result = await scan_inbox(fake_analyze, FakeSettings())

    assert result["phishing"] == 4
    assert result["scanned"] == 4
    assert result["skipped"] == 0


@pytest.mark.asyncio
async def test_historical_scan_skips_already_scanned(tmp_path, monkeypatch):
    """Re-running the scanner must skip messages already in the checkpoint table."""
    import app.layer7_gmail.historical_scanner as hs
    monkeypatch.setattr(hs, "_CHECKPOINT_DB", str(tmp_path / "checkpoint.db"))

    from app.layer7_gmail.historical_scanner import scan_inbox
    stubs = [{"id": "already-scanned-msg-unique"}]
    raw_msg = b"From: x@evil.com\r\n\r\nbody"

    async def fake_analyze(rb, cfg):
        return {"verdict": "phishing"}

    # First run — scans it
    with patch("app.layer7_gmail.historical_scanner.list_messages", return_value=stubs), \
         patch("app.layer7_gmail.historical_scanner.fetch_raw_message", return_value=raw_msg), \
         patch("app.layer7_gmail.historical_scanner.apply_label", return_value=True), \
         patch("app.storage.save_scan", return_value=None):
        r1 = await scan_inbox(fake_analyze, FakeSettings())

    # Second run — must skip it
    with patch("app.layer7_gmail.historical_scanner.list_messages", return_value=stubs), \
         patch("app.layer7_gmail.historical_scanner.fetch_raw_message", return_value=raw_msg), \
         patch("app.layer7_gmail.historical_scanner.apply_label", return_value=True), \
         patch("app.storage.save_scan", return_value=None):
        r2 = await scan_inbox(fake_analyze, FakeSettings())

    assert r1["scanned"] == 1
    assert r2["scanned"] == 0
    assert r2["skipped"] == 1


def test_build_service_no_auth_returns_none():
    from app.layer7_gmail.gmail_client import _build_service
    class S:
        google_service_account_json = ""
        google_admin_impersonate_email = ""
        gmail_oauth_token_file = ""
    assert _build_service(S) is None


def test_build_service_oauth_path_used(tmp_path):
    from app.layer7_gmail.gmail_client import _build_service
    fake_token = tmp_path / "tok.json"
    fake_token.write_text('{"refresh_token": "x", "client_id": "c", "client_secret": "s"}')

    class S:
        google_service_account_json = ""
        google_admin_impersonate_email = ""
        gmail_oauth_token_file = str(fake_token)

    fake_creds = MagicMock()
    fake_creds.valid = True
    fake_creds.expired = False
    fake_creds.refresh_token = "x"

    fake_uc_mod = MagicMock()
    fake_uc_mod.Credentials.from_authorized_user_file.return_value = fake_creds

    fake_build = MagicMock(return_value="GMAIL_SVC")
    fake_build_mod = MagicMock(build=fake_build)

    fake_req_mod = MagicMock()

    real_import = __import__

    def stub_import(name, *args, **kw):
        if name == "googleapiclient.discovery":
            return fake_build_mod
        if name == "google.oauth2.credentials":
            return fake_uc_mod
        if name == "google.auth.transport.requests":
            return fake_req_mod
        return real_import(name, *args, **kw)

    import builtins, importlib
    real_il = importlib.import_module

    def stub_il(name, *a, **k):
        if name == "googleapiclient.discovery":
            return fake_build_mod
        if name == "google.oauth2.credentials":
            return fake_uc_mod
        if name == "google.auth.transport.requests":
            return fake_req_mod
        return real_il(name, *a, **k)

    with patch.object(importlib, "import_module", side_effect=stub_il):
        svc = _build_service(S)

    assert svc is not None
    fake_uc_mod.Credentials.from_authorized_user_file.assert_called_once()


def test_oauth_setup_script_has_main():
    import importlib.util as _u
    spec = _u.spec_from_file_location("gos", "scripts/gmail_oauth_setup.py")
    m = _u.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert callable(m.main)
    assert callable(m.run_consent_flow)
    assert callable(m.verify_token)
