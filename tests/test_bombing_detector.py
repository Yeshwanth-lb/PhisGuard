"""Tests for inbox bombing detector."""
import app.security.bombing_detector as bd


def _reset():
    bd._state.clear()


class TestSubjectPatternMatching:
    def test_confirm_email(self):
        assert bd._matches_subscription_pattern("Confirm your email address")

    def test_welcome_to(self):
        assert bd._matches_subscription_pattern("Welcome to Acme Corp!")

    def test_verify_account(self):
        assert bd._matches_subscription_pattern("Please verify your account")

    def test_thanks_signing_up(self):
        assert bd._matches_subscription_pattern("Thanks for signing up")

    def test_activate_subscription(self):
        assert bd._matches_subscription_pattern("Activate your subscription now")

    def test_one_more_step(self):
        assert bd._matches_subscription_pattern("One more step to complete setup")

    def test_legitimate_meeting(self):
        assert not bd._matches_subscription_pattern("Team sync Thursday 3pm")

    def test_legitimate_update(self):
        assert not bd._matches_subscription_pattern("Q3 roadmap update")

    def test_deployment_notice(self):
        assert not bd._matches_subscription_pattern("v2.4.1 deployed successfully")


class TestBombingDetection:
    def setup_method(self): _reset()

    def test_no_attack_below_volume_without_pattern(self):
        """High volume but no subscription pattern → no detection."""
        for i in range(bd.VOLUME_THRESHOLD - 1):
            under, new = bd.record("victim@co.com", f"x@d{i}.com", "Team meeting update")
            assert not under and not new

    def test_no_attack_low_diversity(self):
        """High volume but all from SAME domain → not bombing."""
        for i in range(bd.VOLUME_THRESHOLD + 5):
            under, new = bd.record("victim@co.com", "noreply@mailchimp.com",
                                    "Confirm your email")
        # Sender diversity is 0% (all same domain) → no bombing
        assert not new

    def test_no_attack_low_pattern(self):
        """High volume + diverse but subjects are normal business emails."""
        for i in range(bd.VOLUME_THRESHOLD + 5):
            under, new = bd.record("victim@co.com", f"x@domain-{i}.com",
                                    "Q3 planning update from the team")
        assert not new

    def test_attack_detected_all_three_signals(self):
        """Volume + pattern + diversity → bombing detected."""
        _reset()
        # First prime the seen_domains with some old domains
        # Then send a burst of subscription emails from new domains
        for i in range(bd.VOLUME_THRESHOLD + 2):
            under, new = bd.record(
                "victim@co.com",
                f"noreply@brand-new-domain-{i}.com",
                "Confirm your email address",
            )
        assert new or under  # should detect

    def test_newly_detected_only_fires_once(self):
        """Once attack is detected, newly_detected=True only on first trigger."""
        _reset()
        newly_count = 0
        for i in range(bd.VOLUME_THRESHOLD + 10):
            _, new = bd.record("victim@co.com", f"x@newdomain{i}.com",
                                "Welcome to the service")
            if new:
                newly_count += 1
        assert newly_count == 1  # fires exactly once

    def test_under_attack_persists(self):
        """After detection, subsequent emails show under_attack=True."""
        _reset()
        for i in range(bd.VOLUME_THRESHOLD + 5):
            bd.record("victim@co.com", f"x@d{i}.com", "Confirm your email")
        # One more email after detection
        under, _ = bd.record("victim@co.com", "x@another.com", "hello")
        assert under

    def test_different_recipients_independent(self):
        """Attack on one inbox does not affect another."""
        _reset()
        for i in range(bd.VOLUME_THRESHOLD + 5):
            bd.record("victim@co.com", f"x@d{i}.com", "Confirm your email")
        under, _ = bd.record("safe@co.com", "x@safe.com", "Team meeting tomorrow")
        assert not under

    def test_clear_attack(self):
        """SOC clearing the hold stops the under_attack flag."""
        _reset()
        for i in range(bd.VOLUME_THRESHOLD + 5):
            bd.record("victim@co.com", f"x@d{i}.com", "Confirm your email")
        assert bd.is_under_attack("victim@co.com")
        bd.clear_attack("victim@co.com")
        assert not bd.is_under_attack("victim@co.com")

    def test_active_attacks_list(self):
        """active_attacks() returns attacked recipients."""
        _reset()
        for i in range(bd.VOLUME_THRESHOLD + 5):
            bd.record("victim@co.com", f"x@d{i}.com", "Confirm your email")
        attacks = bd.active_attacks()
        assert any(a["rcpt"] == "victim@co.com" for a in attacks)

    def test_stats_structure(self):
        _reset()
        s = bd.stats()
        assert "active_attacks" in s
        assert "thresholds" in s
        assert s["thresholds"]["volume_threshold"] == bd.VOLUME_THRESHOLD


class TestVelocityDetection:
    def setup_method(self): _reset()

    def test_fires_before_volume_threshold(self):
        """VELOCITY_THRESHOLD subscription emails in 30s fires before VOLUME_THRESHOLD."""
        results = []
        for i in range(bd.VELOCITY_THRESHOLD):
            under, new = bd.record(
                "victim@co.com",
                f"x@domain-{i}.com",
                "Confirm your email address",
            )
            results.append((under, new))
        # Should have fired by VELOCITY_THRESHOLD, well before VOLUME_THRESHOLD
        assert bd.VELOCITY_THRESHOLD < bd.VOLUME_THRESHOLD
        assert any(new for _, new in results)

    def test_velocity_requires_pattern(self):
        """Velocity check requires subscription pattern — burst of normal emails should not fire."""
        for i in range(bd.VELOCITY_THRESHOLD + 2):
            under, new = bd.record(
                "victim@co.com",
                f"x@domain-{i}.com",
                "Team meeting tomorrow at 3pm",   # not a subscription pattern
            )
        # No velocity trigger — subject doesn't match pattern
        assert not any([bd.is_under_attack("victim@co.com")])
