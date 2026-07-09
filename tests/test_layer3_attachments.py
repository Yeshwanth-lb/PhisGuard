"""Layer 3 attachment static analysis + multi-URL detonation tests."""
import asyncio
import io
import zipfile
from email.message import EmailMessage
from unittest.mock import MagicMock, patch

from app.layer3_sandbox.attachment_analyzer import analyze_attachments
from app.layer3_sandbox.verdicts import run_layer3


# ── helpers ─────────────────────────────────────────────────────────────────
def _email_with_attachment(filename: str, data: bytes,
                           ctype: str = "application/octet-stream") -> bytes:
    msg = EmailMessage()
    msg["From"] = "sender@test.com"
    msg["To"] = "victim@test.com"
    msg["Subject"] = "please see attached"
    msg.set_content("Hi, the document is attached.")
    maintype, _, subtype = ctype.partition("/")
    msg.add_attachment(data, maintype=maintype, subtype=subtype or "octet-stream",
                       filename=filename)
    return msg.as_bytes()


class _FakeSettings:
    max_attachment_scan_bytes = 25 * 1024 * 1024
    l3_max_detonations = 5


def _analyze(raw: bytes) -> dict:
    return asyncio.run(analyze_attachments(raw, _FakeSettings()))


# ── attachment: dangerous file types ─────────────────────────────────────────
class TestDangerousExtensions:
    def test_bare_executable_is_phishing(self):
        raw = _email_with_attachment("invoice.exe", b"MZ\x90\x00fake")
        r = _analyze(raw)
        assert r["verdict"] == "phishing"
        assert r["score"] >= 0.95
        assert any("dangerous_ext:exe" in f for f in r["findings"])

    def test_double_extension_is_phishing_and_flagged(self):
        raw = _email_with_attachment("invoice.pdf.exe", b"MZ\x90\x00fake")
        r = _analyze(raw)
        assert r["verdict"] == "phishing"
        assert r["score"] >= 0.97
        assert any("double_ext:pdf.exe" in f for f in r["findings"])

    def test_script_attachment_is_phishing(self):
        raw = _email_with_attachment("update.js", b"var x = 1;")
        r = _analyze(raw)
        assert r["verdict"] == "phishing"

    def test_lnk_is_phishing(self):
        raw = _email_with_attachment("photo.jpg.lnk", b"\x4c\x00\x00\x00")
        r = _analyze(raw)
        assert r["verdict"] == "phishing"

    def test_benign_pdf_is_clean(self):
        raw = _email_with_attachment("report.pdf", b"%PDF-1.4 harmless",
                                     ctype="application/pdf")
        r = _analyze(raw)
        assert r["verdict"] == "clean"
        assert r["score"] == 0.0

    def test_benign_text_is_clean(self):
        raw = _email_with_attachment("notes.txt", b"just some notes", ctype="text/plain")
        r = _analyze(raw)
        assert r["verdict"] == "clean"


# ── attachment: no attachments ───────────────────────────────────────────────
class TestNoAttachments:
    def test_plain_email_skipped(self):
        msg = EmailMessage()
        msg["From"] = "a@test.com"; msg["To"] = "b@test.com"; msg["Subject"] = "hi"
        msg.set_content("no attachments here")
        r = _analyze(msg.as_bytes())
        assert r["verdict"] == "skipped"

    def test_empty_raw_skipped(self):
        r = _analyze(b"")
        assert r["verdict"] == "skipped"


# ── attachment: Office macros (olevba mocked) ────────────────────────────────
class _FakeVBAParser:
    def __init__(self, has_macros, results):
        self._has = has_macros
        self._results = results
    def detect_vba_macros(self):
        return self._has
    def analyze_macros(self):
        return self._results
    def close(self):
        pass


class TestMacros:
    # olevba (oletools) is a hard dependency of the macro path and is installed
    # in the app image + requirements.txt. Skip these where it isn't present
    # (e.g. a bare dev host) rather than fail — the non-macro tests above still
    # fully exercise the module's control flow.
    def setup_method(self, _m):
        import pytest
        pytest.importorskip("oletools")

    def test_autoexec_macro_is_phishing(self):
        raw = _email_with_attachment(
            "invoice.xlsm", b"PK\x03\x04fake-ooxml",
            ctype="application/vnd.ms-excel.sheet.macroEnabled.12")
        fake = _FakeVBAParser(True, [("AutoExec", "Auto_Open", "Runs on open"),
                                     ("Suspicious", "Shell", "May run an executable")])
        with patch("oletools.olevba.VBA_Parser", return_value=fake):
            r = _analyze(raw)
        assert r["verdict"] == "phishing"
        assert r["score"] >= 0.9
        assert any("autoexec" in f.lower() for f in r["findings"])

    def test_benign_macro_is_suspicious_not_phishing(self):
        raw = _email_with_attachment(
            "budget.xlsm", b"PK\x03\x04fake-ooxml",
            ctype="application/vnd.ms-excel.sheet.macroEnabled.12")
        fake = _FakeVBAParser(True, [])  # macros present, nothing suspicious
        with patch("oletools.olevba.VBA_Parser", return_value=fake):
            r = _analyze(raw)
        assert r["verdict"] == "suspicious"
        assert 0.40 <= r["score"] < 0.65
        assert any("vba_macros_present" in f for f in r["findings"])

    def test_macro_capable_doc_without_macros_is_clean(self):
        raw = _email_with_attachment("report.doc", b"\xd0\xcf\x11\xe0fake-ole",
                                     ctype="application/msword")
        fake = _FakeVBAParser(False, [])
        with patch("oletools.olevba.VBA_Parser", return_value=fake):
            r = _analyze(raw)
        assert r["verdict"] == "clean"


# ── attachment: archives ─────────────────────────────────────────────────────
class TestArchives:
    def test_zip_with_executable_is_phishing(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", "hello")
            zf.writestr("payload.exe", b"MZ\x90\x00")
        raw = _email_with_attachment("archive.zip", buf.getvalue(),
                                     ctype="application/zip")
        r = _analyze(raw)
        assert r["verdict"] == "phishing"
        assert any("archive_contains:payload.exe" in f for f in r["findings"])

    def test_clean_zip_is_clean(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("doc1.txt", "a")
            zf.writestr("doc2.csv", "b,c")
        raw = _email_with_attachment("files.zip", buf.getvalue(),
                                     ctype="application/zip")
        r = _analyze(raw)
        assert r["verdict"] == "clean"


# ── attachment: multiple, worst wins ─────────────────────────────────────────
def test_worst_attachment_wins():
    # Build an email with two attachments: one benign, one malicious.
    msg = EmailMessage()
    msg["From"] = "s@test.com"; msg["To"] = "v@test.com"; msg["Subject"] = "docs"
    msg.set_content("attached")
    msg.add_attachment(b"harmless", maintype="text", subtype="plain", filename="ok.txt")
    msg.add_attachment(b"MZ\x90\x00", maintype="application", subtype="octet-stream",
                       filename="setup.exe")
    r = _analyze(msg.as_bytes())
    assert r["verdict"] == "phishing"
    assert r["worst_attachment"] == "setup.exe"
    assert len(r["attachments"]) == 2


# ── multi-URL detonation (detonate_url mocked) ───────────────────────────────
def _phishing_crawl():
    return {"crawl_result": {
        "url": "http://evil.test", "final_url": "http://evil.test", "title": "Login",
        "dom_html": "", "scripts": [], "redirects": [],
        "form_data": [{"fields": [{"name": "password", "type": "password"}]}],
    }}


def _clean_crawl():
    return {"crawl_result": {
        "url": "http://ok.test", "final_url": "http://ok.test", "title": "News",
        "dom_html": "", "scripts": [], "redirects": [], "form_data": [],
    }}


class TestMultiUrlDetonation:
    def test_second_url_phishing_is_caught(self):
        """The payload behind the SECOND link must be found (old code only did urls[0])."""
        async def fake_detonate(url, img):
            return _clean_crawl() if "ok.test" in url else _phishing_crawl()

        with patch("app.layer3_sandbox.verdicts.detonate_url", side_effect=fake_detonate):
            r = asyncio.run(run_layer3(["http://ok.test/a", "http://evil.test/login"],
                                       _FakeSettings()))
        assert r["verdict"] == "phishing"
        assert r["detonated_url"] == "http://evil.test/login"
        assert r["urls_detonated"] == 2
        assert r["urls_available"] == 2

    def test_stops_early_on_first_phishing(self):
        calls = []
        async def fake_detonate(url, img):
            calls.append(url)
            return _phishing_crawl()

        with patch("app.layer3_sandbox.verdicts.detonate_url", side_effect=fake_detonate):
            r = asyncio.run(run_layer3(["http://evil1.test", "http://evil2.test",
                                        "http://evil3.test"], _FakeSettings()))
        assert r["verdict"] == "phishing"
        assert len(calls) == 1  # stopped after the first phishing hit

    def test_detonation_cap_respected(self):
        calls = []
        async def fake_detonate(url, img):
            calls.append(url)
            return _clean_crawl()

        many = [f"http://ok{i}.test" for i in range(10)]
        with patch("app.layer3_sandbox.verdicts.detonate_url", side_effect=fake_detonate):
            r = asyncio.run(run_layer3(many, _FakeSettings(), max_detonations=3))
        assert len(calls) == 3
        assert r["verdict"] == "clean"
        assert r["urls_available"] == 10

    def test_all_detonations_error_returns_error(self):
        async def fake_detonate(url, img):
            return {"error": "timeout", "crawl_result": {}}

        with patch("app.layer3_sandbox.verdicts.detonate_url", side_effect=fake_detonate):
            r = asyncio.run(run_layer3(["http://a.test", "http://b.test"], _FakeSettings()))
        assert r["verdict"] == "error"

    def test_empty_urls_skipped(self):
        r = asyncio.run(run_layer3([], _FakeSettings()))
        assert r["verdict"] == "skipped"
