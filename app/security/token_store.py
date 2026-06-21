"""Layer 6 - Refresh token store (in-memory, thread-safe)."""
import secrets
import threading
import time
from dataclasses import dataclass, field

_lock = threading.Lock()
_store: dict[str, "_TokenEntry"] = {}

REFRESH_TTL = 60 * 60 * 24 * 7   # 7 days in seconds
ACCESS_TTL  = 60 * 60              # 1 hour


@dataclass
class _TokenEntry:
    sub: str
    role: str
    issued_at: float = field(default_factory=time.time)
    expires_at: float = 0.0

    def __post_init__(self):
        if self.expires_at == 0.0:
            self.expires_at = self.issued_at + REFRESH_TTL

    def is_valid(self) -> bool:
        return time.time() < self.expires_at


def issue_refresh_token(sub: str, role: str) -> str:
    """Create and store a refresh token. Returns the opaque token string."""
    token = secrets.token_hex(32)
    with _lock:
        _store[token] = _TokenEntry(sub=sub, role=role)
    return token


def consume_refresh_token(token: str) -> dict | None:
    """Validate and consume a refresh token. Returns payload dict or None."""
    with _lock:
        entry = _store.pop(token, None)
    if entry is None or not entry.is_valid():
        return None
    return {"sub": entry.sub, "role": entry.role}


def revoke_all_for_user(sub: str) -> int:
    """Revoke all refresh tokens for a given subject. Returns count revoked."""
    with _lock:
        keys = [k for k, v in _store.items() if v.sub == sub]
        for k in keys:
            del _store[k]
    return len(keys)


def list_active_tokens() -> list:
    """Return summary of active tokens (for admin audit)."""
    now = time.time()
    with _lock:
        return [
            {"sub": e.sub, "role": e.role, "expires_at": e.expires_at, "valid": e.is_valid()}
            for e in _store.values()
            if e.expires_at > now
        ]
