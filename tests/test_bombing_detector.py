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


class TestSlowDripWindow:
    """Cascading window #3 — low-and-slow flood under the 5-min volume gate."""

    def setup_method(self): _reset()

    def test_slow_drip_triggers_over_hour(self, monkeypatch):
        """100 non-pattern emails spread 30s apart over ~50 min → hourly window fires,
        even though no 5-min slice ever reaches VOLUME_THRESHOLD and velocity never trips."""
        clock = {"t": 10_000.0}
        monkeypatch.setattr(bd, "_now", lambda: clock["t"])
        detected = False
        for i in range(bd.SLOWDRIP_THRESHOLD):
            _, new = bd.record("victim@co.com", f"x@d{i}.com", "Daily news digest")
            detected = detected or new
            clock["t"] += 30   # 100×30s = 3000s < 1h retained; ~10 per 5-min slice (<20)
        assert detected
        assert bd.is_under_attack("victim@co.com")

    def test_slow_drip_below_threshold_does_not_fire(self, monkeypatch):
        """One under the hourly threshold, spaced out → no detection by any window."""
        clock = {"t": 5_000.0}
        monkeypatch.setattr(bd, "_now", lambda: clock["t"])
        for i in range(bd.SLOWDRIP_THRESHOLD - 1):
            _, new = bd.record("v2@co.com", f"x@d{i}.com", "Weekly summary")
            assert not new
            clock["t"] += 30
        assert not bd.is_under_attack("v2@co.com")

    def test_stats_exposes_slowdrip_window(self):
        s = bd.stats()
        assert s["thresholds"]["slowdrip_window_secs"] == bd.SLOWDRIP_WINDOW_SECS
        assert s["thresholds"]["slowdrip_threshold"] == bd.SLOWDRIP_THRESHOLD


class TestSlidingCooldownAndFirstContact:
    def setup_method(self): _reset()

    def test_first_contact_true_then_false(self):
        assert bd.is_first_contact("v@co.com", "a@new.com") is True
        bd.record("v@co.com", "a@new.com", "hi")
        assert bd.is_first_contact("v@co.com", "a@new.com") is False

    def _trigger_bomb(self, rcpt):
        for i in range(bd.VELOCITY_THRESHOLD):
            bd.record(rcpt, f"x@d{i}.com", "Confirm your email")

    def test_cooldown_refreshes_on_noise(self, monkeypatch):
        clock = {"t": 1000.0}
        monkeypatch.setattr(bd, "_now", lambda: clock["t"])
        self._trigger_bomb("v@co.com")
        assert bd.is_under_attack("v@co.com")
        clock["t"] += bd.COOLDOWN_SECS - 10
        bd.record("v@co.com", "x@late.com", "Confirm your email")   # noise → refreshes
        clock["t"] += bd.COOLDOWN_SECS - 10                          # would expire w/o refresh
        assert bd.is_under_attack("v@co.com")

    def test_cooldown_expires_when_quiet(self, monkeypatch):
        clock = {"t": 2000.0}
        monkeypatch.setattr(bd, "_now", lambda: clock["t"])
        self._trigger_bomb("v2@co.com")
        assert bd.is_under_attack("v2@co.com")
        clock["t"] += bd.COOLDOWN_SECS + 1
        assert not bd.is_under_attack("v2@co.com")

    def test_high_signal_does_not_refresh_cooldown(self, monkeypatch):
        """A lone OTP (the buried alert) must not keep bombing mode alive on its own."""
        clock = {"t": 3000.0}
        monkeypatch.setattr(bd, "_now", lambda: clock["t"])
        self._trigger_bomb("v3@co.com")
        assert bd.is_under_attack("v3@co.com")
        clock["t"] += bd.COOLDOWN_SECS - 5
        bd.record("v3@co.com", "alerts@bank.com", "Your one-time password is 1234")
        clock["t"] += 10                                            # past original cooldown
        assert not bd.is_under_attack("v3@co.com")

    def test_stats_exposes_cooldown(self):
        assert bd.stats()["thresholds"]["mode_cooldown_secs"] == bd.COOLDOWN_SECS

    def test_seen_domains_lru_evicts(self, monkeypatch):
        _reset()
        monkeypatch.setattr(bd, "MAX_SEEN_DOMAINS", 3)
        for i in range(5):
            bd.record("v@co.com", f"x@d{i}.com", "hello there")
        st = bd._state["v@co.com"]
        assert len(st.seen_domains) <= 3
        assert bd.is_first_contact("v@co.com", "x@d0.com") is True   # evicted (LRU)
        assert bd.is_first_contact("v@co.com", "x@d4.com") is False  # still known

    def test_attack_backstop_caps_mode_duration(self, monkeypatch):
        _reset()
        clock = {"t": 1000.0}
        monkeypatch.setattr(bd, "_now", lambda: clock["t"])
        monkeypatch.setattr(bd, "ATTACK_MAX_SECS", 100)
        for i in range(bd.VELOCITY_THRESHOLD):
            bd.record("v@co.com", f"x@d{i}.com", "Confirm your email")
        assert bd.is_under_attack("v@co.com")
        started = bd._state["v@co.com"].attack_started_at
        clock["t"] = started + bd.ATTACK_MAX_SECS + 1     # past the backstop
        bd.record("v@co.com", "x@late.com", "Confirm your email")   # must NOT refresh now
        clock["t"] += bd.COOLDOWN_SECS + 1
        assert not bd.is_under_attack("v@co.com")          # mode lapsed despite ongoing noise
