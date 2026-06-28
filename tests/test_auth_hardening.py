"""JWT hardening tests: alg validation, tamper/decode safety, secret guard, and that
the /token role is decided server-side (not by the client)."""
import base64
import json
import time

import pytest
from fastapi import HTTPException

import app.config as cfg
import app.security.auth as auth


def _seg(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def test_valid_token_roundtrip(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "testsecret-123")
    p = auth.verify_token(auth.create_token({"sub": "u", "role": "analyst"}))
    assert p["sub"] == "u" and p["role"] == "analyst"


def test_alg_none_rejected(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "testsecret-123")
    hdr = _seg({"alg": "none", "typ": "JWT"})
    body = _seg({"sub": "x", "role": "admin", "exp": int(time.time()) + 999})
    with pytest.raises(HTTPException):
        auth.verify_token(f"{hdr}.{body}.")


def test_tampered_signature_rejected(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "testsecret-123")
    hdr, body, sig = auth.create_token({"sub": "u", "role": "analyst"}).split(".")
    with pytest.raises(HTTPException):
        auth.verify_token(f"{hdr}.{body}.{sig}x")


def test_malformed_body_rejected(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "testsecret-123")
    # valid header + signature path but garbage body — must 401, not 500
    hdr = _seg({"alg": "HS256", "typ": "JWT"})
    import hashlib, hmac
    body = "!!!notbase64!!!"
    sig = base64.urlsafe_b64encode(
        hmac.new(b"testsecret-123", f"{hdr}.{body}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    with pytest.raises(HTTPException):
        auth.verify_token(f"{hdr}.{body}.{sig}")


def test_assert_secure_secret_raises_on_default(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.delenv("ALLOW_INSECURE_JWT_SECRET", raising=False)
    monkeypatch.setattr(cfg.settings, "jwt_secret", "change-me-in-production")
    with pytest.raises(RuntimeError):
        auth.assert_secure_secret()


def test_assert_secure_secret_allows_override(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.setattr(cfg.settings, "jwt_secret", "change-me-in-production")
    monkeypatch.setenv("ALLOW_INSECURE_JWT_SECRET", "true")
    auth.assert_secure_secret()   # must not raise


def test_token_role_is_server_side(monkeypatch):
    """A client cannot escalate by passing role=admin to /token."""
    from fastapi.testclient import TestClient
    import app.main as main
    monkeypatch.setattr(cfg.settings, "api_key", "dev-key")
    monkeypatch.setattr(cfg.settings, "api_key_role", "analyst")
    monkeypatch.setattr(cfg.settings, "api_key_roles", "")
    monkeypatch.setenv("JWT_SECRET", "testsecret-123")
    client = TestClient(main.app)
    r = client.post("/token", json={"api_key": "dev-key", "role": "admin"})
    assert r.status_code == 200
    payload = auth.verify_token(r.json()["access_token"])
    assert payload["role"] == "analyst"   # requested 'admin' ignored

    # unknown key rejected
    assert client.post("/token", json={"api_key": "wrong", "role": "admin"}).status_code == 401
