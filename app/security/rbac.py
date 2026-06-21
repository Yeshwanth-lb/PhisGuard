"""Layer 6 - Role-Based Access Control."""
from enum import Enum

from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer

from .auth import require_auth

_bearer = HTTPBearer(auto_error=False)


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    READONLY = "readonly"


# Role hierarchy: what each role can access
ROLE_PERMISSIONS = {
    Role.ADMIN:    {"scan", "quarantine", "release", "denylist_write", "soar", "ml_retrain", "audit", "settings", "gmail_write"},
    Role.ANALYST:  {"scan", "quarantine", "denylist_write", "soar", "ml_retrain", "audit"},
    Role.READONLY: {"scan"},
}


def get_role(payload: dict) -> Role:
    """Extract role from JWT payload, default to readonly."""
    raw = payload.get("role", "readonly")
    try:
        return Role(raw)
    except ValueError:
        return Role.READONLY


def require_permission(permission: str):
    """FastAPI dependency factory: require a specific permission."""
    def _dep(payload: dict = Security(require_auth)) -> dict:
        role = get_role(payload)
        if permission not in ROLE_PERMISSIONS.get(role, set()):
            raise HTTPException(status_code=403, detail=f"Role {role} lacks permission: {permission}")
        return payload
    return _dep


def require_admin():
    """Shortcut dependency: admin role only."""
    def _dep(payload: dict = Security(require_auth)) -> dict:
        if get_role(payload) != Role.ADMIN:
            raise HTTPException(status_code=403, detail="Admin role required")
        return payload
    return _dep
