"""Phase 6 - In-memory per-IP rate limiter using sliding window."""
import threading
import time
from collections import deque

import structlog
from fastapi import HTTPException, Request

logger = structlog.get_logger()
_lock = threading.Lock()
_windows: dict = {}


def check_rate_limit(request: Request, limit: int = 60, window: int = 60) -> None:
    """Raise 429 if the caller exceeds `limit` requests per `window` seconds."""
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _lock:
        if ip not in _windows:
            _windows[ip] = deque()
        dq_ref = _windows[ip]
        while dq_ref and dq_ref[0] < now - window:
            dq_ref.popleft()
        if len(dq_ref) >= limit:
            logger.warning("rate_limited", ip=ip, count=len(dq_ref))
            raise HTTPException(status_code=429, detail="Too many requests")
        dq_ref.append(now)


def get_rate_limiter(limit: int = 60, window: int = 60):
    """Returns a FastAPI dependency that enforces the given rate limit."""
    def _dep(request: Request) -> None:
        check_rate_limit(request, limit=limit, window=window)
    return _dep
