"""Layer 3 - OCR Engine: extract text from screenshot using Tesseract."""
import base64
import io

import structlog

logger = structlog.get_logger()

URGENCY_WORDS = [
    "verify", "suspended", "expire", "urgent",
    "confirm", "click here", "act now", "limited",
    "immediately", "unusual activity", "validate",
]


def ocr_screenshot(screenshot_b64: str | None) -> dict:
    """Run Tesseract OCR on a base64-encoded PNG screenshot."""
    if not screenshot_b64:
        return {"text": "", "score": 0.0, "findings": []}
    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        logger.warning("ocr_dependencies_missing")
        return {"text": "", "score": 0.0, "findings": ["ocr_unavailable"]}
    try:
        img_bytes = base64.b64decode(screenshot_b64)
        img = Image.open(io.BytesIO(img_bytes))
        text = pytesseract.image_to_string(img).lower()
    except Exception as exc:
        logger.warning("ocr_error", error=str(exc))
        return {"text": "", "score": 0.0, "findings": ["ocr_error"]}
    score = 0.0
    findings = []
    hit_count = sum(1 for w in URGENCY_WORDS if w in text)
    if hit_count > 0:
        findings.append(f"urgency_words:{hit_count}")
        score = min(0.3 + hit_count * 0.1, 0.7)
    from app.layer2_ai.structural import HIGH_VALUE_BRANDS
    for brand in HIGH_VALUE_BRANDS:
        if brand in text:
            findings.append(f"ocr_brand:{brand}")
            score = max(score, 0.5)
    logger.info("ocr_done", score=round(score,3), chars=len(text))
    return {"text": text[:2000], "score": round(score, 3), "findings": findings}
