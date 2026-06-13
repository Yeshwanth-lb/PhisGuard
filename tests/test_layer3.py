"""Phase 3 gate tests - Page Analyzer and OCR Engine (sandbox runner mocked)."""
import pytest
from unittest.mock import AsyncMock, patch
from app.layer3_sandbox.page_analyzer import analyze_page
from app.layer3_sandbox.ocr_engine import ocr_screenshot
from app.layer3_sandbox.verdicts import run_layer3



# TC-P3-01: Credential field in crawl result raises high score
def test_page_analyzer_cred_field():
    crawl = {
        "url": "http://evil.test",
        "final_url": "http://evil.test",
        "title": "login page",
        "dom_html": "",
        "scripts": [],
        "form_data": [{
            "fields": [
                {"name": "password", "type": "password"},
                {"name": "username", "type": "text"},
            ]
        }],
        "redirects": [],
    }
    result = analyze_page(crawl)
    assert result["score"] >= 0.7, f"Expected high score, got {result}"
    assert result["cred_fields"] >= 1


# TC-P3-02: Long redirect chain raises score
def test_page_analyzer_redirect_chain():
    crawl = {
        "url": "http://start.test",
        "final_url": "http://end.test",
        "title": "", "dom_html": "",
        "scripts": [], "form_data": [],
        "redirects": ["r1", "r2", "r3", "r4"],
    }
    result = analyze_page(crawl)
    assert result["score"] >= 0.4
    assert result["redirects"] == 4


# TC-P3-03: OCR gracefully degrades when tesseract absent
def test_ocr_no_screenshot():
    result = ocr_screenshot(None)
    assert result["score"] == 0.0
    assert result["text"] == ""


# TC-P3-04: Layer 3 skips when URL list is empty
import asyncio
def test_layer3_empty_urls():
    class FakeSettings: pass
    result = asyncio.run(run_layer3([], FakeSettings()))
    assert result["verdict"] == "skipped"
