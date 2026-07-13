"""Phase 6 gate tests: security hardening."""
import time
from unittest.mock import MagicMock

import pytest

# --- JWT auth tests ---

def test_create_and_verify_token():
    from app.security.auth import create_token, verify_token
    tok = create_token({"sub": "tester"}, ttl_seconds=60)
    payload = verify_token(tok)
    assert payload["sub"] == "tester"


def test_expired_token_rejected():
    from fastapi import HTTPException

    from app.security.auth import create_token, verify_token
    tok = create_token({"sub": "x"}, ttl_seconds=0)
    time.sleep(1)
    with pytest.raises(HTTPException) as exc_info:
        verify_token(tok)
    assert exc_info.value.status_code == 401


def test_tampered_token_rejected():
    from fastapi import HTTPException

    from app.security.auth import create_token, verify_token
    tok = create_token({"sub": "x"}) + "tamper"
    with pytest.raises(HTTPException) as exc_info:
        verify_token(tok)
    assert exc_info.value.status_code == 401


# --- Rate limiter tests ---

def test_rate_limit_allows_under_threshold():
    from app.security.rate_limiter import check_rate_limit
    req = MagicMock()
    req.client.host = "10.0.0.1"
    for _ in range(5):
        check_rate_limit(req, limit=10, window=60)


def test_rate_limit_blocks_over_threshold():
    from fastapi import HTTPException

    from app.security.rate_limiter import _windows, check_rate_limit
    req = MagicMock()
    req.client.host = "10.0.0.99"
    _windows.pop("10.0.0.99", None)
    for _ in range(3):
        check_rate_limit(req, limit=3, window=60)
    with pytest.raises(HTTPException) as exc_info:
        check_rate_limit(req, limit=3, window=60)
    assert exc_info.value.status_code == 429


# --- Sanitizer tests ---

def test_validate_email_payload_ok():
    from app.security.sanitizer import validate_email_payload
    result = validate_email_payload({"raw_email": "From: x@y.com"})
    assert "raw_email" in result


def test_validate_email_payload_missing():
    from fastapi import HTTPException

    from app.security.sanitizer import validate_email_payload
    with pytest.raises(HTTPException) as exc_info:
        validate_email_payload({})
    assert exc_info.value.status_code == 422


def test_validate_url_list_filters_non_http():
    from app.security.sanitizer import validate_url_list
    urls = ["http://good.com", "ftp://bad.com", "javascript:alert(1)", "https://also.good.com"]
    clean = validate_url_list(urls)
    assert len(clean) == 2
    assert all(u.startswith("http") for u in clean)


def test_sanitize_strips_null_bytes():
    from app.security.sanitizer import sanitize_string
    result = sanitize_string("hello" + chr(0) + "world")
    assert chr(0) not in result
    assert result == "helloworld"

# --- Token store / refresh rotation tests ---

def test_refresh_token_single_use():
    from app.security.token_store import consume_refresh_token, issue_refresh_token
    rt = issue_refresh_token("alice", "analyst")
    payload = consume_refresh_token(rt)
    assert payload == {"sub": "alice", "role": "analyst"}
    assert consume_refresh_token(rt) is None


def test_revoke_all_for_user():
    from app.security.token_store import consume_refresh_token, issue_refresh_token, revoke_all_for_user
    rt1 = issue_refresh_token("bob", "admin")
    rt2 = issue_refresh_token("bob", "admin")
    n = revoke_all_for_user("bob")
    assert n >= 2
    assert consume_refresh_token(rt1) is None
    assert consume_refresh_token(rt2) is None


def test_create_token_pair_shape():
    from app.security.auth import create_token_pair, verify_token
    pair = create_token_pair("carol", "admin")
    assert set(pair.keys()) == {"access_token", "refresh_token", "token_type", "expires_in"}
    decoded = verify_token(pair["access_token"])
    assert decoded["sub"] == "carol" and decoded["role"] == "admin"


# --- RBAC tests ---

def test_rbac_admin_has_everything():
    from app.security.rbac import ROLE_PERMISSIONS, Role
    perms = ROLE_PERMISSIONS[Role.ADMIN]
    for p in ("scan", "ml_retrain", "audit", "settings", "quarantine"):
        assert p in perms


def test_rbac_readonly_blocked_from_writes():
    from app.security.rbac import ROLE_PERMISSIONS, Role
    perms = ROLE_PERMISSIONS[Role.READONLY]
    for p in ("ml_retrain", "audit", "settings", "soar"):
        assert p not in perms


def test_rbac_get_role_default():
    from app.security.rbac import Role, get_role
    assert get_role({}) == Role.READONLY
    assert get_role({"role": "analyst"}) == Role.ANALYST
    assert get_role({"role": "garbage"}) == Role.READONLY


# --- Audit log tests ---

def test_audit_log_write_and_read(tmp_path, monkeypatch):
    import importlib
    monkeypatch.setenv("AUDIT_LOG_FILE", str(tmp_path / "audit.jsonl"))
    from app.security import audit as audit_mod
    importlib.reload(audit_mod)
    audit_mod._write_audit({"req_id": "abc", "path": "/x", "status": 200})
    entries = audit_mod.read_audit_log(limit=10, path=str(tmp_path / "audit.jsonl"))
    assert len(entries) == 1
    assert entries[0]["req_id"] == "abc"


# --- HTTP-level integration tests via FastAPI TestClient ---

def _client():
    from fastapi.testclient import TestClient

    from app.main import app
    return TestClient(app)


def test_http_token_endpoint_returns_pair():
    c = _client()
    r = c.post("/token", json={"api_key": "dev-key", "sub": "u1", "role": "analyst"})
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data and "refresh_token" in data


def test_http_token_bad_api_key_rejected():
    c = _client()
    r = c.post("/token", json={"api_key": "wrong"})
    assert r.status_code == 401


def test_http_whoami_round_trip():
    c = _client()
    tok = c.post("/token", json={"api_key": "dev-key", "sub": "alice", "role": "analyst"}).json()
    r = c.get("/api/auth/whoami", headers={"Authorization": "Bearer " + tok["access_token"]})
    assert r.status_code == 200
    me = r.json()
    assert me["sub"] == "alice" and me["role"] == "analyst"


def test_http_whoami_unauthenticated():
    c = _client()
    r = c.get("/api/auth/whoami")
    assert r.status_code == 401


def test_http_refresh_rotation_and_replay():
    c = _client()
    tok = c.post("/token", json={"api_key": "dev-key", "sub": "bob", "role": "analyst"}).json()
    rt = tok["refresh_token"]
    r = c.post("/api/auth/refresh", json={"refresh_token": rt})
    assert r.status_code == 200
    new_tok = r.json()
    assert new_tok["access_token"] != tok["access_token"]
    r2 = c.post("/api/auth/refresh", json={"refresh_token": rt})
    assert r2.status_code == 401


def test_http_rbac_readonly_blocked_from_retrain():
    from app.security.auth import create_token
    c = _client()
    access = create_token({"sub": "ro", "role": "readonly"})   # role minted directly
    r = c.post("/api/ml/retrain", headers={"Authorization": "Bearer " + access})
    assert r.status_code in (401, 403)


def test_http_audit_logs_endpoint_for_analyst():
    c = _client()
    tok = c.post("/token", json={"api_key": "dev-key", "sub": "an", "role": "analyst"}).json()
    r = c.get("/api/audit/logs", headers={"Authorization": "Bearer " + tok["access_token"]})
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data.get("entries"), list)


def test_http_request_id_header_present():
    c = _client()
    tok = c.post("/token", json={"api_key": "dev-key", "sub": "h", "role": "analyst"}).json()
    r = c.get("/api/auth/whoami", headers={"Authorization": "Bearer " + tok["access_token"]})
    rid = r.headers.get("x-request-id")
    assert rid and len(rid) >= 4


# ---------------------------------------------------------------------------
# RBAC permission matrix: analyst vs admin vs readonly (live HTTP tests)
# ---------------------------------------------------------------------------

def _token(client, role):
    # Mint a role-specific token directly. /token no longer honors a client-supplied
    # role (server decides it), so tests use the low-level factory to exercise each role.
    from app.security.auth import create_token
    return create_token({"sub": f"test-{role}", "role": role})


def _auth(token):
    return {"Authorization": "Bearer " + token}


class TestRbacPermissionMatrix:
    """Verify that each role can only reach what ROLE_PERMISSIONS allows."""

    # --- ml_retrain permission ---

    def test_admin_can_access_ml_retrain(self):
        c = _client()
        r = c.post("/api/ml/retrain", headers=_auth(_token(c, "admin")))
        assert r.status_code != 403

    def test_analyst_can_access_ml_retrain(self):
        c = _client()
        r = c.post("/api/ml/retrain", headers=_auth(_token(c, "analyst")))
        assert r.status_code != 403

    def test_readonly_blocked_from_ml_retrain(self):
        c = _client()
        r = c.post("/api/ml/retrain", headers=_auth(_token(c, "readonly")))
        assert r.status_code == 403

    # --- audit permission ---

    def test_admin_can_access_audit_logs(self):
        c = _client()
        r = c.get("/api/audit/logs", headers=_auth(_token(c, "admin")))
        assert r.status_code == 200
        assert isinstance(r.json().get("entries"), list)

    def test_analyst_can_access_audit_logs(self):
        c = _client()
        r = c.get("/api/audit/logs", headers=_auth(_token(c, "analyst")))
        assert r.status_code == 200
        assert isinstance(r.json().get("entries"), list)

    def test_readonly_blocked_from_audit_logs(self):
        c = _client()
        r = c.get("/api/audit/logs", headers=_auth(_token(c, "readonly")))
        assert r.status_code == 403

    # --- gmail_write permission ---

    def test_analyst_blocked_from_gmail_write(self):
        c = _client()
        r = c.post("/api/gmail/watch", headers=_auth(_token(c, "analyst")))
        assert r.status_code == 403

    def test_readonly_blocked_from_gmail_write(self):
        c = _client()
        r = c.post("/api/gmail/watch", headers=_auth(_token(c, "readonly")))
        assert r.status_code == 403

    def test_admin_passes_gmail_permission_check(self):
        c = _client()
        r = c.post("/api/gmail/watch", headers=_auth(_token(c, "admin")))
        # Admin passes the permission check; the actual 5xx/200 depends on
        # whether Gmail credentials are configured, not on RBAC.
        assert r.status_code != 403

    # --- unauthenticated access ---

    def test_unauthenticated_ml_retrain_rejected(self):
        c = _client()
        r = c.post("/api/ml/retrain")
        assert r.status_code == 401

    def test_unauthenticated_audit_logs_rejected(self):
        c = _client()
        r = c.get("/api/audit/logs")
        assert r.status_code == 401

    # --- scan permission: all roles ---

    def test_all_roles_blocked_without_auth_on_analyze(self):
        c = _client()
        r = c.post("/analyze", json={"raw_email": "From: a@b.com\n\nbody"})
        assert r.status_code == 401

    def test_readonly_can_access_scan_after_auth(self):
        """readonly has 'scan' permission so /analyze must not 403."""
        c = _client()
        tok = _token(c, "readonly")
        r = c.post(
            "/analyze",
            headers=_auth(tok),
            json={"raw_email": "From: a@b.com\nTo: x@y.com\nSubject: hi\n\nbody"},
        )
        # 200 (clean verdict) or 5xx from unconfigured external services — not 403
        assert r.status_code != 403
