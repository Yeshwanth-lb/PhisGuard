"""Phase 6 - Input sanitization and validation for email payloads."""
import re
import structlog
from fastapi import HTTPException

logger = structlog.get_logger()

MAX_SUBJECT_LEN = 998
MAX_BODY_LEN = 10 * 1024 * 1024
MAX_URL_LEN = 2048
MAX_URL_COUNT = 500


def sanitize_string(value: str, max_len: int = 1000) -> str:
    """Strip null bytes and truncate to max_len."""
    return value.replace(chr(0), "")[:max_len]


def validate_email_payload(payload: dict) -> dict:
    """Validates and sanitizes the incoming email payload. Raises 422 on bad input."""
    raw = payload.get("raw_email", "")
    if not raw or not isinstance(raw, str):
        raise HTTPException(status_code=422, detail="raw_email field is required")
    if len(raw) > MAX_BODY_LEN:
        raise HTTPException(status_code=413, detail="Payload too large")
    raw = sanitize_string(raw, MAX_BODY_LEN)
    return {**payload, "raw_email": raw}


def validate_url_list(urls: list) -> list:
    """Filter and sanitize a list of URLs."""
    if len(urls) > MAX_URL_COUNT:
        logger.warning("url_list_truncated", original_count=len(urls))
        urls = urls[:MAX_URL_COUNT]
    clean = []
    for u in urls:
        if not isinstance(u, str):
            continue
        u = u.strip()[:MAX_URL_LEN]
        if re.match(r"^https?://", u):
            clean.append(u)
    return clean


def validate_headers(headers: dict) -> dict:
    """Remove oversized or non-string header values."""
    return {
        k[:200]: str(v)[:2000]
        for k, v in headers.items()
        if isinstance(k, str) and isinstance(v, str)
    }
