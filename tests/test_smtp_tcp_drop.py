"""Tests for the TCP hard-drop escalation (Phase 1B).

A repeat 421-offender IP gets its socket dropped after the threshold; a single
legitimate email resets the streak. The 421/tarpit path itself is unchanged.
"""
import app.security.smtp_rate_limiter as rl


def test_note_rejection_drops_after_threshold():
    rl._drop_windows.clear()
    ip = "203.0.113.9"
    drops = [rl.note_rejection(ip) for _ in range(rl.TCP_DROP_THRESHOLD + 1)]
    # Up to and including the threshold-th rejection: no drop.
    assert drops[:rl.TCP_DROP_THRESHOLD] == [False] * rl.TCP_DROP_THRESHOLD
    # The one past the threshold triggers the drop.
    assert drops[rl.TCP_DROP_THRESHOLD] is True


def test_allowed_email_resets_streak():
    rl._drop_windows.clear()
    ip = "203.0.113.10"
    for _ in range(rl.TCP_DROP_THRESHOLD):
        rl.note_rejection(ip)
    assert ip in rl._drop_windows
    # A legitimate, allowed email clears the IP's drop streak.
    allowed, _, _ = rl.check(ip, "ok@legit.com", "user@co.com")
    assert allowed is True
    assert ip not in rl._drop_windows


def test_empty_ip_never_drops():
    assert rl.note_rejection("") is False
