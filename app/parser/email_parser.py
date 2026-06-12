import email
import email.policy
import hashlib
import re
from email import message_from_bytes
from email.header import decode_header, make_header
from typing import Optional, List, Dict, Any, Tuple
import structlog

logger = structlog.get_logger()


def _decode_header_value(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value or ""


def _extract_sender_ip(received_headers: List[str]) -> Optional[str]:
    """Extract sender IP from the last untrusted Received header."""
    ipv4_pattern = re.compile(r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?")
    for header in reversed(received_headers):
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


def _extract_body(msg: email.message.Message) -> Tuple[Optional[str], Optional[str]]:
    """Return (text_plain, text_html) decoded bodies."""
    text_plain = None
    text_html = None
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace")
            if ct == "text/plain" and text_plain is None:
                text_plain = decoded
            elif ct == "text/html" and text_html is None:
                text_html = decoded
    else:
        ct = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace")
            if ct == "text/plain":
                text_plain = decoded
            elif ct == "text/html":
                text_html = decoded
    return text_plain, text_html


def _extract_attachments(msg: email.message.Message) -> List[Dict[str, str]]:
    """Return list of attachment dicts with filename, sha256, content_type, size."""
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() not in ("attachment", "inline"):
            continue
        filename = part.get_filename() or "unknown"
        try:
            filename = str(make_header(decode_header(filename)))
        except Exception:
            pass
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        attachments.append({
            "filename": filename,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "content_type": part.get_content_type(),
            "size": len(payload),
        })
    return attachments


def _check_auth(msg: email.message.Message) -> Tuple[str, str, str]:
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


def parse_email(raw: bytes) -> Dict[str, Any]:
    """Parse raw email bytes into structured metadata dict."""
    try:
        msg = message_from_bytes(raw, policy=email.policy.compat32)
    except Exception as e:
        logger.error("email_parse_failed", error=str(e))
        return {}

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
