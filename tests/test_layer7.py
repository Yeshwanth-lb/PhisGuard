"""Phase 7 gate tests: Google Workspace integration."""
import pytest
from unittest.mock import MagicMock, patch, AsyncMock


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
async def test_historical_scan_counts_phishing():
    from app.layer7_gmail.historical_scanner import scan_inbox
    stubs = [{"id": f"msg{i}"} for i in range(4)]
    raw_msg = b"From: x@evil.com\r\n\r\nbody"
    async def fake_analyze(rb, cfg):
        return {"verdict": "phishing"}
    with patch("app.layer7_gmail.historical_scanner.list_messages", return_value=stubs), \
         patch("app.layer7_gmail.historical_scanner.fetch_raw_message", return_value=raw_msg), \
         patch("app.layer7_gmail.historical_scanner.apply_label", return_value=True):
        result = await scan_inbox(fake_analyze, FakeSettings())
    assert result["phishing"] == 4
    assert result["scanned"] == 4
