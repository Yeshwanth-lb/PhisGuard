"""Layer 4 SMTP escalation live integration test.

Runs only when the alert SMTP relay is configured and reachable with the
configured login. Sends a single clearly-labeled smoke-test alert via
app.layer4_soar.email_alerter.send_alert_email and asserts the exporter
returned True (relay accepted the message).

Skipped automatically in CI (which excludes *_live.py files) and skipped
on any developer machine where the configured SMTP relay is not
answering on the alert host:port with the configured login.
"""
import smtplib
import ssl

import certifi
import pytest

from app.config import settings


def _smtp_reachable() -> bool:
    """Best-effort liveness probe against the configured SMTP relay."""
    host = (settings.alert_smtp_host or "").strip()
    if not (host and settings.alert_email_from and settings.alert_email_to):
        return False
    user = (settings.alert_smtp_user or "").strip()
    pwd = settings.alert_smtp_password or ""
    port = int(settings.alert_smtp_port or 587)
    try:
        if settings.alert_smtp_use_tls:
            ctx = ssl.create_default_context(cafile=certifi.where())
            with smtplib.SMTP(host, port, timeout=10) as s:
                s.starttls(context=ctx)
                if user:
                    s.login(user, pwd)
                s.noop()
        else:
            with smtplib.SMTP(host, port, timeout=10) as s:
                if user:
                    s.login(user, pwd)
                s.noop()
    except Exception:
        return False
    return True


pytestmark = pytest.mark.skipif(
    not _smtp_reachable(),
    reason="SMTP relay not reachable with configured login; live SMTP tests skipped",
)


SMOKE_VERDICT = {
    "verdict": "phishing",
    "confidence": 0.95,
    "blocked_at": "layer2",
    "parsed": {
        "from_header": "smoke-test@phishguard.local",
        "subject": "[PhishGuard live test] verifying SMTP escalation -- ignore",
        "urls": ["https://example.test/smoke"],
    },
    "l2": {
        "verdict": "phishing",
        "confidence": 0.95,
        "engine_scores": {"claude": 0.95},
    },
}


def test_smtp_settings_loaded():
    """Cheap sanity check on configured fields."""
    assert settings.alert_smtp_host
    assert settings.alert_smtp_port
    assert settings.alert_email_from
    assert settings.alert_email_to


async def test_smtp_live_send_alert():
    """End-to-end: real SMTP send to the configured relay."""
    from app.layer4_soar.email_alerter import send_alert_email

    result = await send_alert_email(SMOKE_VERDICT, settings)
    assert result is True


async def test_smtp_skips_clean_verdict():
    """Sanity: relay live, but a clean verdict must NOT trigger a send."""
    from app.layer4_soar.email_alerter import send_alert_email

    clean = {**SMOKE_VERDICT, "verdict": "clean"}
    result = await send_alert_email(clean, settings)
    assert result is False


async def test_smtp_short_circuits_when_host_missing(monkeypatch):
    """Sanity: an unset host forces the exporter to return False."""
    from app.layer4_soar.email_alerter import send_alert_email

    monkeypatch.setattr(settings, "alert_smtp_host", "", raising=False)
    result = await send_alert_email(SMOKE_VERDICT, settings)
    assert result is False
