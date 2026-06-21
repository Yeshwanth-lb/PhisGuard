import codecs
import email
import email.policy
import hashlib
import re
from email import message_from_bytes
from email.header import decode_header, make_header
from typing import Any

import structlog

logger = structlog.get_logger()

_BOGUS_CHARSET_ALIASES = {
    "default": "utf-8",
    "default_charset": "utf-8",
    "unknown": "utf-8",
    "unknown-8bit": "latin-1",
    "x-unknown": "utf-8",
    "x-user-defined": "utf-8",
    "chinesebig5": "big5",
    "x-mac-roman": "mac-roman",
    "x-mac-cyrillic": "mac-cyrillic",
    "ks_c_5601-1987": "cp949",
    "iso-8859-8-i": "iso-8859-8",
    "windows-874": "cp874",
}


def _safe_decode(payload: bytes, charset: str | None) -> str:
    """Decode bytes using the declared charset, falling back to latin-1 for unknown codecs.

    `bytes.decode(charset, errors='replace')` raises LookupError when the codec itself
    is unknown (e.g. "default", "unknown-8bit") regardless of the errors= value, so we
    explicitly normalise + look up the codec first and fall through to latin-1 on miss.
    """
    raw_charset = (charset or "").strip().lower().strip("\"'")
    if not raw_charset:
        raw_charset = "utf-8"
    raw_charset = _BOGUS_CHARSET_ALIASES.get(raw_charset, raw_charset)
    try:
        codecs.lookup(raw_charset)
    except LookupError:
        raw_charset = "latin-1"
    try:
        return payload.decode(raw_charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("latin-1", errors="replace")


def _decode_header_value(value: Any) -> str:
    """Decode an RFC 2047 header value into a plain string. Always returns a str."""
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        try:
            return str(value)
        except Exception:
            return ""


def _extract_sender_ip(received_headers: list[Any]) -> str | None:
    """Extract sender IP from the last untrusted Received header."""
    ipv4_pattern = re.compile(r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?")
    for raw in reversed(received_headers):
        header = str(raw) if raw is not None else ""
        if not header:
            continue
        for ip in ipv4_pattern.findall(header):
            parts = ip.split(".")
            if parts[0] == "10":
                continue
            if parts[0] == "172" and 16 <= int(parts[1]) <= 31:
                continue
            if parts[0] == "192" and parts[1] == "168":
                continue
            if ip.startswith("127."):
                continue
            return ip
    return None


def _extract_body(msg: email.message.Message) -> tuple[str | None, str | None]:
    """Return (text_plain, text_html) decoded bodies. Tolerates bogus / unknown charsets."""
    text_plain = None
    text_html = None
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            try:
                payload = part.get_payload(decode=True)
            except Exception as exc:
                logger.warning("body_payload_decode_failed", ct=ct, error=str(exc))
                continue
            if payload is None:
                continue
            charset = None
            try:
                charset = part.get_content_charset()
            except Exception:
                charset = None
            decoded = _safe_decode(payload, charset)
            if ct == "text/plain" and text_plain is None:
                text_plain = decoded
            elif ct == "text/html" and text_html is None:
                text_html = decoded
    else:
        ct = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
        except Exception as exc:
            logger.warning("body_payload_decode_failed", ct=ct, error=str(exc))
            payload = None
        if payload:
            charset = None
            try:
                charset = msg.get_content_charset()
            except Exception:
                charset = None
            decoded = _safe_decode(payload, charset)
            if ct == "text/plain":
                text_plain = decoded
            elif ct == "text/html":
                text_html = decoded
    return text_plain, text_html


def _extract_attachments(msg: email.message.Message) -> list[dict[str, str]]:
    """Return list of attachment dicts with filename, sha256, content_type, size."""
    attachments = []
    for part in msg.walk():
        try:
            disposition = part.get_content_disposition()
        except Exception:
            disposition = None
        if disposition not in ("attachment", "inline"):
            continue
        filename = part.get_filename() or "unknown"
        try:
            filename = str(make_header(decode_header(str(filename))))
        except Exception:
            filename = str(filename)
        try:
            payload = part.get_payload(decode=True)
        except Exception as exc:
            logger.warning("attachment_decode_failed", filename=filename, error=str(exc))
            continue
        if payload is None:
            continue
        if not isinstance(payload, (bytes, bytearray)):
            logger.warning("attachment_payload_not_bytes", filename=filename, type=type(payload).__name__)
            continue
        try:
            ct = part.get_content_type()
        except Exception:
            ct = "application/octet-stream"
        attachments.append({
            "filename": filename,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "content_type": ct,
            "size": len(payload),
        })
    return attachments


def _check_auth(msg: email.message.Message) -> tuple[str, str, str]:
    """Extract SPF, DKIM, DMARC results from Authentication-Results header."""
    auth_results = msg.get("Authentication-Results", "")
    spf = "unknown"
    dkim = "unknown"
    dmarc = "unknown"
    spf_m = re.search(r"spf=(\w+)", auth_results, re.IGNORECASE)
    if spf_m:
        spf = spf_m.group(1).lower()
    dkim_m = re.search(r"dkim=(\w+)", auth_results, re.IGNORECASE)
    if dkim_m:
        dkim = dkim_m.group(1).lower()
    dmarc_m = re.search(r"dmarc=(\w+)", auth_results, re.IGNORECASE)
    if dmarc_m:
        dmarc = dmarc_m.group(1).lower()
    return spf, dkim, dmarc


def parse_email(raw: bytes) -> dict[str, Any]:
    """Parse raw email bytes into structured metadata dict."""
    try:
        msg = message_from_bytes(raw, policy=email.policy.compat32)
    except Exception as e:
        logger.error("email_parse_failed", error=str(e))
        return {}
    try:
        return _parse_email_inner(msg)
    except Exception as exc:
        logger.error("email_parse_inner_failed", error=str(exc))
        return {}


def _parse_email_inner(msg: email.message.Message) -> dict[str, Any]:
    received_headers = msg.get_all("Received", [])
    sender_ip = _extract_sender_ip(received_headers)
    from_header = _decode_header_value(msg.get("From", ""))
    reply_to = _decode_header_value(msg.get("Reply-To", ""))
    return_path = _decode_header_value(msg.get("Return-Path", ""))
    x_orig_ip = msg.get("X-Originating-IP", "")

    sender_domain = None
    sender_email_addr = None
    domain_m = re.search(r"@([\w.-]+)", from_header)
    if domain_m:
        sender_domain = domain_m.group(1).lower()
        email_m = re.search(r"[\w.+-]+@[\w.-]+", from_header)
        if email_m:
            sender_email_addr = email_m.group(0).lower()

    subject = _decode_header_value(msg.get("Subject", ""))
    text_plain, text_html = _extract_body(msg)
    attachments = _extract_attachments(msg)
    spf, dkim, dmarc = _check_auth(msg)

    return {
        "sender_ip": sender_ip or x_orig_ip or None,
        "sender_domain": sender_domain,
        "sender_email": sender_email_addr,
        "from_header": from_header,
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": subject,
        "body_text": text_plain,
        "body_html": text_html,
        "attachments": attachments,
        "attachment_hashes": [a["sha256"] for a in attachments],
        "headers": {
            "From": from_header,
            "Reply-To": reply_to,
            "Return-Path": return_path,
            "Subject": subject,
            "Received": received_headers,
        },
        "spf_result": spf,
        "dkim_result": dkim,
        "dmarc_result": dmarc,
    }
