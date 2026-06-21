"""Layer 3 - Sandbox verdict aggregator."""
import structlog

from app.layer3_sandbox.ocr_engine import ocr_screenshot
from app.layer3_sandbox.page_analyzer import analyze_page
from app.layer3_sandbox.sandbox_runner import detonate_url

logger = structlog.get_logger()
SANDBOX_THRESHOLD = 0.55


async def run_layer3(urls: list, settings) -> dict:
    """Detonate top suspicious URL and return Layer 3 verdict."""
    if not urls:
        return {"verdict": "skipped", "reason": "no_urls"}
    target_url = urls[0]
    docker_img = getattr(settings, "sandbox_docker_image", None)
    sandbox_resp = await detonate_url(target_url, docker_img)
    if "error" in sandbox_resp:
        return {"verdict": "error", "error": sandbox_resp["error"]}
    crawl = sandbox_resp.get("crawl_result", {})
    page = analyze_page(crawl)
    ocr = ocr_screenshot(crawl.get("screenshot_b64"))
    combined = max(page["score"], ocr["score"])
    verdict = "phishing" if combined >= SANDBOX_THRESHOLD else "clean"
    logger.info("l3_verdict", verdict=verdict, score=combined)
    return {
        "verdict": verdict,
        "score": combined,
        "page_findings": page["findings"],
        "ocr_findings": ocr["findings"],
        "screenshot_b64": crawl.get("screenshot_b64"),
        "final_url": crawl.get("final_url"),
        "title": crawl.get("title"),
        "redirects": crawl.get("redirects", []),
        "detonated_url": target_url,
    }
