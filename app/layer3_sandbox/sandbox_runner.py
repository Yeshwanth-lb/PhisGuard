"""Layer 3 - Sandbox Runner."""
import asyncio
import json
import os
import structlog
from typing import Optional
logger = structlog.get_logger()
SANDBOX_TIMEOUT_SECS = 30
CRAWLER_JS = os.path.join(os.path.dirname(__file__),
    "..", "..", "docker", "sandbox", "crawler.js")


async def detonate_url(url: str, docker_image: Optional[str] = None) -> dict:
    if not url:
        return {"error": "no_url", "crawl_result": {}}
    try:
        return await _run_crawler(url, docker_image)
    except Exception as exc:
        logger.warning("sandbox_error", url=url, error=str(exc))
        return {"error": str(exc), "crawl_result": {}}


async def _run_crawler(url: str, docker_image: Optional[str]) -> dict:
    if docker_image:
        cmd = ["docker", "run", "--rm",
            "--network", "none", docker_image,
            "node", "/app/crawler.js", url]
    else:
        cmd = ["node", CRAWLER_JS, url]
    kw = {"stdout": asyncio.subprocess.PIPE, "stderr": asyncio.subprocess.PIPE}
    proc = await asyncio.create_subprocess_exec(*cmd, **kw)
    try:
        out_b, err_b = await asyncio.wait_for(proc.communicate(), SANDBOX_TIMEOUT_SECS)
    except asyncio.TimeoutError:
        proc.kill()
        return {"error": "timeout", "crawl_result": {}}
    if proc.returncode != 0:
        logger.warning("crawler_failed")
        return {"error": "crawler_failed", "crawl_result": {}}
    try:
        return json.loads(out_b.decode())
    except json.JSONDecodeError as exc:
        return {"error": str(exc), "crawl_result": {}}
