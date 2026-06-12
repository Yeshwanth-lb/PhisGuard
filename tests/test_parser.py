import pytest
from app.parser.email_parser import parse_email
from app.parser.url_extractor import extract_urls

BENIGN_EML = b'From: Alice <alice@example.com>\nTo: Bob <bob@company.com>\nSubject: Meeting tomorrow\nMessage-ID: <123@example.com>\nReceived: from mail.example.com (mail.example.com [203.0.113.10])\n  by mx.company.com with SMTP\nAuthentication-Results: mx.company.com; spf=pass dkim=pass dmarc=pass\nContent-Type: text/plain\n\nHi Bob, let us meet tomorrow at 10am.\nCheck the agenda at https://docs.example.com/agenda\n'

def test_p0_01_parse_returns_data():
    r = parse_email(BENIGN_EML)
    assert r is not None
    assert r.get("sender_domain") == "example.com"

def test_p0_02_header_extraction():
    r = parse_email(BENIGN_EML)
    assert r["subject"] == "Meeting tomorrow"
    assert r["spf_result"] == "pass"
    assert r["dkim_result"] == "pass"
    assert r["dmarc_result"] == "pass"

def test_p0_03_url_extraction():
    r = parse_email(BENIGN_EML)
    body = r.get("body_text", "") or ""
    extracted = extract_urls(body_text=body)
    assert any("docs.example.com" in u for u in extracted)

def test_p0_05_sender_ip():
    r = parse_email(BENIGN_EML)
    assert r.get("sender_ip") == "203.0.113.10"
