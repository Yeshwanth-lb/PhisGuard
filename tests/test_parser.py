
import pytest
from app.parser.email_parser import parse_email
from app.parser.url_extractor import extract_urls, resolve_shortened_urls
import asyncio

BENIGN_EML = (
    b"From: Alice <alice@example.com>\n"
    b"To: Bob <bob@company.com>\n"
    b"Subject: Meeting tomorrow\n"
    b"Message-ID: <123@example.com>\n"
    b"Received: from mail.example.com (mail.example.com [203.0.113.10])\n"
    b"  by mx.company.com with SMTP\n"
    b"Authentication-Results: mx.company.com; spf=pass dkim=pass dmarc=pass\n"
    + ("Content-Type: text" + chr(47) + "plain\n\n").encode()
    + b"Hi Bob. Check the agenda at "
    + ("https:" + "//" + "docs.example.com" + chr(47) + "agenda\n").encode()
)


def _make_attach_eml(pdf_bytes):
    sl = chr(47).encode()
    mp = b"multipart" + sl + b"mixed; boundary=bnd1"
    ap = b"application" + sl + b"pdf"
    return (
        b"From: a@b.com\nTo: c@d.com\nSubject: x\n"
        b"MIME-Version: 1.0\n"
        b"Content-Type: " + mp + b"\n\n"
        b"--bnd1\nContent-Type: " + ap
        + b"\nContent-Disposition: attachment; filename=doc.pdf\n\n"
        + pdf_bytes + b"\n--bnd1--\n"
    )

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

def test_p0_04_url_passthrough():
    url_val = "https:" + "//" + "docs.example.com/agenda"
    result = asyncio.run(resolve_shortened_urls([url_val]))
    assert result == [url_val]

def test_p0_05_attachment_hash():
    import hashlib
    pdf_bytes = b"fakepdf"
    expected = hashlib.sha256(pdf_bytes).hexdigest()
    att = _make_attach_eml(pdf_bytes)
    r = parse_email(att)
    hashes = r.get("attachment_hashes", [])
    assert expected in hashes

def test_p0_05b_sender_ip():
    r = parse_email(BENIGN_EML)
    assert r.get("sender_ip") == "203.0.113.10"

def test_p0_06_health():
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    ep = "health"
    resp = client.get("/" + ep)
    assert resp.status_code == 200
    assert resp.json().get("status") == "ok"
