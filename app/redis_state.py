"""Redis-backed coordination for running PhishGuard with more than one worker.

Two multi-worker hazards this solves (both additive — no Redis / single worker =
unchanged behavior):

1. Schedulers double-running. The daemon schedulers (ThreatLens, digest, watch
   renewal, ML retrain) would each fire in EVERY worker. `leader_lock()` is a
   Redis lock with a TTL + background renewal so exactly one process runs them.

2. Per-process rate-limit counters. With workers behind a load balancer, an
   in-memory sliding window under-counts (each worker sees only its share).
   `sliding_window_incr()` keeps the count in a Redis sorted set shared across
   workers. Opt-in via STATE_BACKEND=redis; default 'memory' is unchanged.

Everything fails OPEN and degrades to local behavior if Redis is unreachable —
availability of mail scanning must never depend on the coordination layer.
"""
from __future__ import annotations

import os
import threading
import time

import structlog

logger = structlog.get_logger()

_client = None
_client_lock = threading.Lock()


def _redis_url() -> str:
    url = os.environ.get("REDIS_URL", "")
    if not url:
        try:
            from app.config import settings
            url = getattr(settings, "redis_url", "") or ""
        except Exception:
            url = ""
    return url


def state_backend() -> str:
    """'redis' or 'memory' (default). Controls whether shared counters use Redis."""
    val = os.environ.get("STATE_BACKEND", "")
    if not val:
        try:
            from app.config import settings
            val = getattr(settings, "state_backend", "") or ""
        except Exception:
            val = ""
    return (val or "memory").strip().lower()


def _get_client():
    """Lazily create a shared sync Redis client, or None if unavailable."""
    global _client
    if _client is not None:
        return _client
    with _client_lock:
        if _client is not None:
            return _client
        url = _redis_url()
        if not url:
            return None
        try:
            import redis
            c = redis.from_url(url, decode_responses=True, socket_timeout=2,
                               socket_connect_timeout=2)
            c.ping()
            _client = c
        except Exception as exc:
            logger.warning("redis_state_unavailable", error=str(exc)[:120])
            return None
    return _client


def sliding_window_incr(key: str, window_secs: int, now: float | None = None) -> int | None:
    """Record an event in a Redis sorted-set sliding window and return the count
    within `window_secs`. Returns None if Redis is unavailable (caller falls back
    to its in-memory window). Prunes old entries each call; sets a safety TTL."""
    c = _get_client()
    if c is None:
        return None
    now = now if now is not None else time.time()
    rkey = f"rl:{key}"
    try:
        pipe = c.pipeline()
        pipe.zremrangebyscore(rkey, 0, now - window_secs)
        pipe.zadd(rkey, {f"{now}:{os.getpid()}": now})
        pipe.zcard(rkey)
        pipe.expire(rkey, window_secs + 5)
        return int(pipe.execute()[2])
    except Exception as exc:
        logger.warning("redis_sliding_window_err", error=str(exc)[:120])
        return None


_held_leaders: dict[str, bool] = {}


def acquire_leader(name: str, ttl_secs: int = 60) -> bool:
    """Try to become the singleton leader for `name`, held for the process
    lifetime with background renewal. Returns True if THIS process should run
    the guarded work (e.g. the daemon schedulers). Fails OPEN: with no Redis or
    an error, returns True so a single-node dev/demo runs everything as before.
    Idempotent per name (cached)."""
    if name in _held_leaders:
        return _held_leaders[name]
    c = _get_client()
    if c is None:
        _held_leaders[name] = True   # no Redis => single node => run locally
        return True
    token = f"{os.getpid()}:{time.time()}"
    key = f"leader:{name}"
    try:
        got = bool(c.set(key, token, nx=True, ex=ttl_secs))
    except Exception as exc:
        logger.warning("leader_acquire_err", error=str(exc)[:120])
        _held_leaders[name] = True   # fail open
        return True
    _held_leaders[name] = got
    if got:
        def _renew():
            while True:
                time.sleep(ttl_secs / 2)
                try:
                    if c.get(key) == token:
                        c.expire(key, ttl_secs)
                    else:
                        return
                except Exception:
                    return
        threading.Thread(target=_renew, daemon=True, name=f"leader-{name}").start()
        logger.info("scheduler_leader_acquired", name=name, pid=os.getpid())
    else:
        logger.info("scheduler_leader_deferred", name=name, pid=os.getpid())
    return got
