"""Layer 3 - Sandbox verdict aggregator."""
import structlog

from app.layer3_sandbox.ocr_engine import ocr_screenshot
from app.layer3_sandbox.page_analyzer import analyze_page
from app.layer3_sandbox.sandbox_runner import detonate_url

logger = structlog.get_logger()
SANDBOX_THRESHOLD = 0.55
# Cap how many URLs we detonate per email — detonation spins a Docker container
# each, so an email stuffed with links can't be used to exhaust the host. The
# first benign link is a classic decoy, so we must not stop at urls[0].
DEFAULT_MAX_DETONATIONS = 5


def _score_one(crawl: dict, target_url: str) -> dict:
    page = analyze_page(crawl)
    ocr = ocr_screenshot(crawl.get("screenshot_b64"))
    combined = max(page["score"], ocr["score"])
    return {
        "detonated_url": target_url,
        "score": combined,
        "verdict": "phishing" if combined >= SANDBOX_THRESHOLD else "clean",
        "page_findings": page["findings"],
        "ocr_findings": ocr["findings"],
        "screenshot_b64": crawl.get("screenshot_b64"),
        "final_url": crawl.get("final_url"),
        "title": crawl.get("title"),
        "redirects": crawl.get("redirects", []),
    }


async def run_layer3(urls: list, settings, max_detonations: int | None = None) -> dict:
    """Detonate suspicious URLs (up to a cap) and return the worst verdict.

    Unlike the old behavior of only detonating urls[0], this walks every URL up
    to `max_detonations` and keeps the highest-scoring result — attackers put a
    clean link first and the credential-harvest page second. Stops early as soon
    as one URL scores phishing (no point detonating the rest).
    """
    if not urls:
        return {"verdict": "skipped", "reason": "no_urls"}
    docker_img = getattr(settings, "sandbox_docker_image", None)
    cap = max_detonations if max_detonations is not None else getattr(
        settings, "l3_max_detonations", DEFAULT_MAX_DETONATIONS)

    targets = urls[: max(1, cap)]
    best: dict | None = None
    all_results: list[dict] = []
    last_error: str | None = None

    for target_url in targets:
        sandbox_resp = await detonate_url(target_url, docker_img)
        if "error" in sandbox_resp:
            last_error = sandbox_resp["error"]
            logger.info("l3_detonation_error", url=target_url[:80], error=last_error)
            continue
        scored = _score_one(sandbox_resp.get("crawl_result", {}), target_url)
        all_results.append(scored)
        if best is None or scored["score"] > best["score"]:
            best = scored
        if scored["verdict"] == "phishing":
            break  # worst-case found; don't burn more containers

    if best is None:
        return {"verdict": "error", "error": last_error or "all_detonations_failed",
                "urls_attempted": len(targets)}

    verdict = best["verdict"]
    logger.info("l3_verdict", verdict=verdict, score=best["score"],
                urls_detonated=len(all_results), urls_available=len(urls))
    # Flat shape kept backward-compatible with the previous single-URL return;
    # `all_detonations` adds the per-URL breakdown for the dashboard.
    return {
        "verdict": verdict,
        "score": best["score"],
        "page_findings": best["page_findings"],
        "ocr_findings": best["ocr_findings"],
        "screenshot_b64": best["screenshot_b64"],
        "final_url": best["final_url"],
        "title": best["title"],
        "redirects": best["redirects"],
        "detonated_url": best["detonated_url"],
        "urls_detonated": len(all_results),
        "urls_available": len(urls),
        "all_detonations": all_results,
    }
