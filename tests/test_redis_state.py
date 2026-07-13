"""Redis coordination: leader-lock + sliding window. Uses fakeredis so it runs
offline; falls back to real Redis if fakeredis isn't present (skips if neither)."""
import importlib
import os

import pytest


def _with_fake_redis(monkeypatch):
    fakeredis = pytest.importorskip("fakeredis")
    import redis
    server = fakeredis.FakeServer()
    monkeypatch.setattr(redis, "from_url",
                        lambda *a, **k: fakeredis.FakeStrictRedis(server=server, decode_responses=True))
    os.environ["REDIS_URL"] = "redis://fake"
    from app import redis_state
    importlib.reload(redis_state)
    return redis_state


def test_leader_lock_single_winner(monkeypatch):
    rs = _with_fake_redis(monkeypatch)
    wins = 0
    for _ in range(4):
        rs._held_leaders.clear()          # simulate a fresh process each time
        if rs.acquire_leader("sched", ttl_secs=30):
            wins += 1
    assert wins == 1                       # exactly one leader across 4 workers


def test_leader_fails_open_without_redis(monkeypatch):
    os.environ.pop("REDIS_URL", None)
    from app import redis_state
    importlib.reload(redis_state)
    # no Redis configured => single-node => everything runs (True)
    assert redis_state.acquire_leader("x") is True


def test_sliding_window_counts(monkeypatch):
    rs = _with_fake_redis(monkeypatch)
    assert rs.sliding_window_incr("k", 60, now=1000.0) == 1
    assert rs.sliding_window_incr("k", 60, now=1001.0) == 2
    # an event outside the window is pruned
    assert rs.sliding_window_incr("k", 60, now=1200.0) == 1


def teardown_module(_):
    os.environ.pop("REDIS_URL", None)
