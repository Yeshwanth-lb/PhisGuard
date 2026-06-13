"""Phase 6 - JWT authentication middleware for FastAPI."""
import os
import hmac
import hashlib
import base64
import json
import time
import structlog
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logger = structlog.get_logger()
_bearer = HTTPBearer(auto_error=False)


def _get_secret() -> bytes:
    raw = os.environ.get("JWT_SECRET", "change-me-in-production")
    return raw.encode()


def create_token(payload: dict, ttl_seconds: int = 3600) -> str:
    """Create a minimal HS256 JWT."""
    hdr = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = {**payload, "exp": int(time.time()) + ttl_seconds}
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig_input = f"{hdr}.{body}".encode()
    sig = base64.urlsafe_b64encode(hmac.new(_get_secret(), sig_input, hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{hdr}.{body}.{sig}"


def verify_token(token: str) -> dict:
    """Verify HS256 JWT and return payload. Raises HTTPException on failure."""
    try:
        hdr, body, sig = token.split(".")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token format")
    sig_input = f"{hdr}.{body}".encode()
    expected = base64.urlsafe_b64encode(hmac.new(_get_secret(), sig_input, hashlib.sha256).digest()).rstrip(b"=").decode()
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(status_code=401, detail="Invalid signature")
    pad = 4 - len(body) % 4
    payload = json.loads(base64.urlsafe_b64decode(body + "=" * pad))
    if payload.get("exp", 0) < int(time.time()):
        raise HTTPException(status_code=401, detail="Token expired")
    return payload


def require_auth(credentials: HTTPAuthorizationCredentials = Security(_bearer)) -> dict:
    """FastAPI dependency — inject into protected routes."""
    if not credentials:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    return verify_token(credentials.credentials)
