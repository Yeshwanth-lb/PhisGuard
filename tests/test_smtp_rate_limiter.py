"""Tests for SMTP rate limiter — email bombing protection."""
import time
from unittest.mock import patch

import pytest

import app.security.smtp_rate_limiter as rl


def _reset():
    """Clear all in-memory state between tests."""
    rl._ip_windows.clear()
    rl._dom_windows.clear()
    rl._rcpt_windows.clear()
    rl._global_window.clear()
    rl._burst_windows.clear()
    rl._alerted_at.clear()


class TestPerIPLimit:
    def setup_method(self): _reset()

    def test_accepts_up_to_limit(self):
        for i in range(rl.PER_IP_LIMIT):
            allowed, _, _ = rl.check("1.2.3.4", f"x{i}@evil.com")
            assert allowed

    def test_blocks_over_limit(self):
        for _ in range(rl.PER_IP_LIMIT):
            rl.check("1.2.3.4", "x@evil.com")
        allowed, reason, tarpit = rl.check("1.2.3.4", "x@evil.com")
        assert not allowed
        assert "421" in reason
        assert "1.2.3.4" in reason
        assert tarpit == rl.TARPIT_SECS

    def test_different_ips_independent(self):
        for _ in range(rl.PER_IP_LIMIT):
            rl.check("1.1.1.1", "x@evil.com")
        allowed, _, _ = rl.check("2.2.2.2", "x@evil.com")
        assert allowed


class TestPerDomainLimit:
    def setup_method(self): _reset()

    def test_blocks_domain_over_hourly_limit(self):
        for i in range(rl.PER_DOMAIN_LIMIT):
            rl.check(f"10.0.0.{i}", f"x@spam-domain.com")
        allowed, reason, _ = rl.check("10.0.1.0", "x@spam-domain.com")
        assert not allowed
        assert "spam-domain.com" in reason

    def test_different_domains_independent(self):
        for i in range(rl.PER_DOMAIN_LIMIT):
            rl.check(f"10.0.0.{i}", "x@blocked.com")
        allowed, _, _ = rl.check("10.0.0.99", "x@other-domain.com")
        assert allowed


class TestPerRecipientLimit:
    def setup_method(self): _reset()

    def test_blocks_recipient_over_limit(self):
        """Distributed bombing: many IPs/domains all targeting the same inbox."""
        for i in range(rl.PER_RCPT_LIMIT):
            rl.check(f"10.0.0.{i}", f"x@domain-{i}.com", "victim@company.com")
        # Next email from a FRESH IP and domain should still be blocked (rcpt limit)
        allowed, reason, tarpit = rl.check("99.99.99.99", "x@brand-new.com", "victim@company.com")
        assert not allowed
        assert "victim@company.com" in reason
        assert tarpit == rl.TARPIT_SECS

    def test_different_recipients_independent(self):
        """Bombing one inbox should not affect other inboxes."""
        for i in range(rl.PER_RCPT_LIMIT):
            rl.check(f"10.0.0.{i}", f"x@d{i}.com", "victim@company.com")
        # Different recipient should still pass
        allowed, _, _ = rl.check("10.0.1.0", "x@other.com", "other@company.com")
        assert allowed

    def test_no_rcpt_no_per_rcpt_block(self):
        """If rcpt is empty, per-recipient limit does not block."""
        for i in range(rl.PER_RCPT_LIMIT + 5):
            allowed, _, _ = rl.check(f"10.0.0.{i}", f"x@d{i}.com", "")
            assert allowed  # no rcpt → no per-rcpt limit applies


class TestGlobalLimit:
    def setup_method(self): _reset()

    def test_blocks_global_overflow(self):
        for i in range(rl.GLOBAL_LIMIT):
            rl.check(f"10.{i//256}.{i%256}.1", f"x@domain-{i}.com")
        allowed, reason, _ = rl.check("99.99.99.99", "x@new-domain.com")
        assert not allowed
        assert "global" in reason.lower() or "busy" in reason.lower()


class TestTarpit:
    def setup_method(self): _reset()

    def test_allowed_has_zero_tarpit(self):
        allowed, _, tarpit = rl.check("1.2.3.4", "x@evil.com", "v@co.com")
        assert allowed and tarpit == 0

    def test_blocked_has_tarpit_delay(self):
        for _ in range(rl.PER_IP_LIMIT):
            rl.check("1.2.3.4", "x@evil.com")
        allowed, _, tarpit = rl.check("1.2.3.4", "x@evil.com")
        assert not allowed and tarpit == rl.TARPIT_SECS


class TestBurstDetection:
    def setup_method(self): _reset()

    def test_burst_fires_slack_alert(self):
        with patch.object(rl, '_alert_bombing_async') as mock_alert:
            for i in range(rl.BURST_THRESHOLD):
                rl.check("1.2.3.4", "x@evil.com")
            # Fires once for IP source and once for domain source
            assert mock_alert.call_count == 2
            sources = [call[0][0] for call in mock_alert.call_args_list]
            assert "1.2.3.4" in sources
            assert "evil.com" in sources

    def test_alert_suppressed_within_window(self):
        with patch.object(rl, '_alert_bombing_async') as mock_alert:
            # First burst — alerts for IP + domain = 2 calls
            for _ in range(rl.BURST_THRESHOLD):
                rl.check("1.2.3.4", "x@evil.com")
            assert mock_alert.call_count == 2
            # Second burst immediately — both sources suppressed, no new alerts
            for _ in range(rl.BURST_THRESHOLD):
                rl.check("1.2.3.4", "x@evil.com")
            assert mock_alert.call_count == 2  # still 2, no re-alert


class TestHelpers:
    def test_sender_domain_extraction(self):
        assert rl._sender_domain("attacker@evil.com") == "evil.com"
        assert rl._sender_domain("Name <attacker@evil.com>") == "evil.com"
        assert rl._sender_domain("") == "unknown"

    def test_stats_returns_correct_structure(self):
        _reset()
        stats = rl.stats()
        assert "global_emails_last_minute" in stats
        assert "limits" in stats
        assert stats["limits"]["per_ip_per_minute"] == rl.PER_IP_LIMIT
