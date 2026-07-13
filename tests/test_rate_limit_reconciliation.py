"""Phase 3 hardening: rate-limiter ↔ bombing-window reconciliation + demo mode.

- Once an inbox is under active bombing triage, the per-recipient limit must NOT
  pre-empt it (otherwise it could 421 the OTP the bomb is burying).
- BOMBING_DEMO_MODE disables rate-limit blocking so a demo bomb reaches the detector.
"""
import pytest

import app.security.smtp_rate_limiter as rl


@pytest.fixture(autouse=True)
def _pin_limits(monkeypatch):
    """Deterministic limits regardless of ambient env (.env SMTP_RATE_* leakage)."""
    monkeypatch.setattr(rl, "PER_IP_LIMIT", 10)
    monkeypatch.setattr(rl, "PER_DOMAIN_LIMIT", 20)
    monkeypatch.setattr(rl, "PER_RCPT_LIMIT", 30)
    monkeypatch.setattr(rl, "GLOBAL_LIMIT", 60)
    monkeypatch.setattr(rl, "DEMO_MODE", False)


def _reset():
    rl._ip_windows.clear(); rl._dom_windows.clear(); rl._rcpt_windows.clear()
    rl._global_window.clear(); rl._burst_windows.clear(); rl._alerted_at.clear()
    rl._drop_windows.clear()


def test_skip_recipient_limit_bypasses_rcpt_block():
    _reset()
    # Fill the recipient bucket using distinct IPs/domains so ONLY the rcpt limit trips.
    for i in range(rl.PER_RCPT_LIMIT):
        rl.check(f"10.0.0.{i}", f"x@d{i}.com", "victim@co.com")
    # Normal path → blocked by the per-recipient limit.
    allowed, reason, _ = rl.check("99.0.0.1", "x@fresh.com", "victim@co.com")
    assert not allowed and "victim@co.com" in reason
    # Under-attack reconciliation → the same over-limit inbox is allowed through to triage.
    allowed2, _, _ = rl.check("99.0.0.2", "x@fresh2.com", "victim@co.com",
                              skip_recipient_limit=True)
    assert allowed2 is True


def test_skip_recipient_limit_still_enforces_other_limits():
    _reset()
    # Per-IP limit must still apply even when the recipient limit is skipped.
    for _ in range(rl.PER_IP_LIMIT):
        rl.check("5.5.5.5", "x@evil.com", "victim@co.com")
    allowed, reason, _ = rl.check("5.5.5.5", "x@evil.com", "victim@co.com",
                                  skip_recipient_limit=True)
    assert not allowed and "5.5.5.5" in reason   # per-IP still guards the gateway


def test_demo_mode_disables_blocking(monkeypatch):
    monkeypatch.setattr(rl, "DEMO_MODE", True)
    _reset()
    results = [rl.check("7.7.7.7", "x@evil.com", "v@co.com")[0]
               for _ in range(rl.PER_IP_LIMIT + 5)]
    assert all(results)   # nothing is ever blocked in demo mode


def test_demo_mode_off_still_blocks(monkeypatch):
    monkeypatch.setattr(rl, "DEMO_MODE", False)
    _reset()
    for _ in range(rl.PER_IP_LIMIT):
        rl.check("6.6.6.6", "x@evil.com", "v@co.com")
    allowed, _, _ = rl.check("6.6.6.6", "x@evil.com", "v@co.com")
    assert allowed is False
