"""Layer 6 - Audit logging middleware."""
import json
import os
import time
import uuid
from datetime import UTC, datetime

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = structlog.get_logger()
_AUDIT_FILE = os.environ.get("AUDIT_LOG_FILE", "data/audit.jsonl")

# Paths that do not need audit entries
_SKIP_PATHS = {"/health", "/", "/openapi.json", "/api/docs"}


def _write_audit(entry: dict) -> None:
    try:
        os.makedirs(os.path.dirname(_AUDIT_FILE) or ".", exist_ok=True)
        with open(_AUDIT_FILE, "a") as fh:
            fh.write(json.dumps(entry) + chr(10))
    except Exception as exc:
        logger.warning("audit_write_err", error=str(exc))


class AuditMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        req_id = str(uuid.uuid4())[:8]
        request.state.request_id = req_id
        start = time.monotonic()
        response = await call_next(request)
        duration_ms = round((time.monotonic() - start) * 1000, 1)
        path = request.url.path
        if path not in _SKIP_PATHS:
            entry = {
                "ts": datetime.now(UTC).isoformat(),
                "req_id": req_id,
                "method": request.method,
                "path": path,
                "status": response.status_code,
                "ip": request.client.host if request.client else "unknown",
                "duration_ms": duration_ms,
                "user_agent": request.headers.get("user-agent", ""),
            }
            _write_audit(entry)
            logger.info("audit", **entry)
        response.headers["X-Request-ID"] = req_id
        return response


def read_audit_log(limit: int = 100, path: str = "") -> list:
    """Read last N entries from the audit log."""
    fpath = path or _AUDIT_FILE
    if not os.path.exists(fpath):
        return []
    try:
        lines = open(fpath).readlines()
        entries = []
        for line in lines[-limit:]:
            try:
                entries.append(json.loads(line))
            except Exception:
                pass
        return list(reversed(entries))
    except Exception as exc:
        logger.warning("audit_read_err", error=str(exc))
        return []
