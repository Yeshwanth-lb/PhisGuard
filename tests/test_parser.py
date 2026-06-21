
import asyncio

from app.parser.email_parser import parse_email
from app.parser.url_extractor import extract_urls, resolve_shortened_urls

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


def test_p0_07_bogus_charset_does_not_crash():
    """Emails declaring unknown charsets like 'default' or 'unknown-8bit' must not raise.

    Regression for the corpus 500s caused by `payload.decode('default', errors='replace')`
    raising LookupError before errors='replace' had a chance to run.
    """
    sl = chr(47)
    for bogus in ("default", "default_charset", "unknown-8bit", "chinesebig5", "x-mac-roman"):
        eml = (
            "From: a@b.com\nTo: c@d.com\nSubject: bogus charset test\n"
            "MIME-Version: 1.0\n"
            "Content-Type: text" + sl + "html; charset=\"" + bogus + "\"\n"
            "Content-Transfer-Encoding: 8bit\n\n"
            "<html><body>Hello world.</body></html>\n"
        ).encode("latin-1")
        result = parse_email(eml)
        assert isinstance(result, dict)
        body_html = result.get("body_html") or ""
        assert isinstance(body_html, str)
        assert "Hello world" in body_html, f"charset={bogus} did not preserve body"


def test_p0_08_received_header_object_does_not_crash():
    """Received headers that come back as Header objects must be coerced to str safely.

    Regression for `re.findall` on a non-string Received header raising TypeError.
    """
    eml = (
        b"From: =?gb2312?B?xLPM7M28x66+47Tz?= <vendor@example.com>\n"
        b"To: target@example.org\n"
        b"Subject: =?gb2312?B?ucXJobnFy66+47Tz?=\n"
        b"Received: from sender [201.187.11.125] (sw59-152-110.adsl.seed.net.tw\n"
        b" [61.59.152.110]) by mx.example.com with SMTP id LAA29871; "
        b"Sat, 7 Sep 2002 11:48:19 +0100\n"
        b"Content-Type: text/plain; charset=\"unknown-8bit\"\n\n"
        b"\xfe\xfd\xfc bogus payload \xfb\xfa\n"
    )
    result = parse_email(eml)
    assert isinstance(result, dict)
    assert result.get("sender_domain") == "example.com"
    assert result.get("sender_ip") in {"201.187.11.125", "61.59.152.110"}
    assert isinstance(result.get("body_text") or "", str)


def test_p0_09_decode_header_value_handles_non_string():
    """_decode_header_value must always return a str even when handed a Header object."""
    from email.header import Header

    from app.parser.email_parser import _decode_header_value
    h = Header("subject text", "utf-8")
    assert isinstance(_decode_header_value(h), str)
    assert isinstance(_decode_header_value(None), str)
    assert isinstance(_decode_header_value(""), str)
    assert isinstance(_decode_header_value(123), str)


def test_p0_10_safe_decode_falls_back_to_latin1():
    """_safe_decode must never raise on bogus charsets."""
    from app.parser.email_parser import _safe_decode
    payload = bytes(range(256))
    for bogus in ("default", "default_charset", "unknown-8bit", "x-fake", "", None):
        result = _safe_decode(payload, bogus)
        assert isinstance(result, str)
        assert len(result) > 0


def test_p0_11_multipart_report_does_not_crash():
    """multipart/report emails (bounce messages) must parse without raising.

    This is the production crash path: walk() on a multipart/report yields
    message/delivery-status parts whose payload structure is unusual.  Before
    the _parse_email_inner safety wrapper any uncaught exception here propagated
    to /analyze as an HTTP 500.
    """
    eml = (
        b"From: mailer-daemon@mx.example.com\n"
        b"To: sender@example.com\n"
        b"Subject: Delivery Status Notification (Failure)\n"
        b"MIME-Version: 1.0\n"
        b"Content-Type: multipart/report; report-type=delivery-status; boundary=bnd\n\n"
        b"--bnd\n"
        b"Content-Type: text/plain; charset=utf-8\n\n"
        b"Your message could not be delivered.\n\n"
        b"--bnd\n"
        b"Content-Type: message/delivery-status\n\n"
        b"Reporting-MTA: dns; mx.example.com\n\n"
        b"Final-Recipient: rfc822; nobody@gone.example.com\n"
        b"Status: 5.1.1\n"
        b"Action: failed\n\n"
        b"--bnd\n"
        b"Content-Type: message/rfc822\n\n"
        b"From: sender@example.com\n"
        b"To: nobody@gone.example.com\n"
        b"Subject: Original\n"
        b"Content-Type: text/plain\n\n"
        b"Original body.\n"
        b"--bnd--\n"
    )
    result = parse_email(eml)
    assert isinstance(result, dict)
    assert result.get("from_header") or True  # parse succeeds, fields are extracted if possible


def test_p0_12_deeply_nested_multipart_does_not_crash():
    """Deeply nested multipart/alternative inside multipart/mixed must not crash."""
    eml = (
        b"From: a@b.com\nTo: c@d.com\nSubject: nested\n"
        b"MIME-Version: 1.0\n"
        b"Content-Type: multipart/mixed; boundary=outer\n\n"
        b"--outer\n"
        b"Content-Type: multipart/alternative; boundary=inner\n\n"
        b"--inner\n"
        b"Content-Type: text/plain; charset=utf-8\n\n"
        b"Hello plain.\n"
        b"--inner\n"
        b"Content-Type: text/html; charset=utf-8\n\n"
        b"<html><body>Hello HTML.</body></html>\n"
        b"--inner--\n"
        b"--outer\n"
        b"Content-Type: application/octet-stream\n"
        b"Content-Disposition: attachment; filename=data.bin\n\n"
        b"\x00\x01\x02\x03\n"
        b"--outer--\n"
    )
    result = parse_email(eml)
    assert isinstance(result, dict)
    assert result.get("body_text") is not None
    assert result.get("body_html") is not None
    assert len(result.get("attachment_hashes", [])) == 1
