"""Phase 6 gate tests: security hardening."""
import time
import pytest
from unittest.mock import MagicMock


# --- JWT auth tests ---

def test_create_and_verify_token():
    from app.security.auth import create_token, verify_token
    tok = create_token({"sub": "tester"}, ttl_seconds=60)
    payload = verify_token(tok)
    assert payload["sub"] == "tester"


def test_expired_token_rejected():
    from app.security.auth import create_token, verify_token
    from fastapi import HTTPException
    tok = create_token({"sub": "x"}, ttl_seconds=0)
    time.sleep(1)
    with pytest.raises(HTTPException) as exc_info:
        verify_token(tok)
    assert exc_info.value.status_code == 401


def test_tampered_token_rejected():
    from app.security.auth import create_token, verify_token
    from fastapi import HTTPException
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
    from app.security.rate_limiter import check_rate_limit, _windows
    from fastapi import HTTPException
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
    from app.security.sanitizer import validate_email_payload
    from fastapi import HTTPException
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
