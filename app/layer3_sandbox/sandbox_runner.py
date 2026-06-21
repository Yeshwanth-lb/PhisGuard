"""Layer 3 - Sandbox Runner.

Uses the Python docker SDK (via the mounted Docker socket) instead of the
docker CLI binary — the CLI is not present in the app container but the socket
is mounted at /var/run/docker.sock, so the SDK works fine.
"""
import asyncio
import json
import os

import structlog

logger = structlog.get_logger()
SANDBOX_TIMEOUT_SECS = 30
CRAWLER_JS = os.path.join(os.path.dirname(__file__),
    "..", "..", "docker", "sandbox", "crawler.js")


async def detonate_url(url: str, docker_image: str | None = None) -> dict:
    if not url:
        return {"error": "no_url", "crawl_result": {}}
    try:
        return await _run_crawler(url, docker_image)
    except Exception as exc:
        logger.warning("sandbox_error", url=url, error=str(exc))
        return {"error": str(exc), "crawl_result": {}}


async def _run_with_sdk(url: str, docker_image: str) -> dict:
    """Run the sandbox container via Python docker SDK (works without docker CLI)."""
    loop = asyncio.get_event_loop()

    def _sync_run():
        import docker as _docker
        client = _docker.DockerClient(base_url="unix://var/run/docker.sock")
        try:
            output = client.containers.run(
                docker_image,
                command=url,
                remove=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges"],
                read_only=True,
                tmpfs={"/tmp": "rw,exec,size=512M"},
                mem_limit="1g",
                nano_cpus=int(1.0 * 1e9),
                pids_limit=256,
                network_mode="bridge",
            )
            return output.decode("utf-8", errors="replace") if isinstance(output, bytes) else str(output)
        except _docker.errors.ContainerError as exc:
            raise RuntimeError(f"container_error: {exc}") from exc
        except _docker.errors.ImageNotFound:
            raise RuntimeError(f"image_not_found: {docker_image}")
        finally:
            try:
                client.close()
            except Exception:
                pass

    try:
        raw = await asyncio.wait_for(
            loop.run_in_executor(None, _sync_run),
            timeout=SANDBOX_TIMEOUT_SECS + 5,
        )
        parsed = json.loads(raw)
        return {"crawl_result": parsed}
    except asyncio.TimeoutError:
        return {"error": "timeout", "crawl_result": {}}
    except json.JSONDecodeError as exc:
        return {"error": f"json_parse: {exc}", "crawl_result": {}}


async def _run_crawler(url: str, docker_image: str | None) -> dict:
    if docker_image:
        # Try Python SDK first (works inside Docker via socket mount)
        try:
            import docker  # type: ignore  # noqa: F401 — just checking availability
            logger.info("sandbox_using_sdk", image=docker_image, url=url[:60])
            return await _run_with_sdk(url, docker_image)
        except ImportError:
            pass  # fall through to CLI
        except Exception as exc:
            logger.warning("sandbox_sdk_failed", error=str(exc))
            # Fall through to CLI attempt

        # CLI fallback (works on host / CI where docker binary is available)
        cmd = [
            "docker", "run", "--rm",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--read-only",
            "--tmpfs", "/tmp:rw,exec,size=512M",
            "--memory", "1g",
            "--cpus", "1.0",
            "--pids-limit", "256",
            docker_image,
            url,
        ]
    else:
        cmd = ["node", CRAWLER_JS, url]

    env = dict(os.environ)
    cand = os.path.join(os.path.dirname(__file__), "..", "..", "docker", "sandbox", ".puppeteer-cache")
    cand = os.path.abspath(cand)
    if os.path.exists(cand):
        env["PUPPETEER_CACHE_DIR"] = cand

    kw = {"stdout": asyncio.subprocess.PIPE, "stderr": asyncio.subprocess.PIPE, "env": env}
    proc = await asyncio.create_subprocess_exec(*cmd, **kw)
    try:
        out_b, err_b = await asyncio.wait_for(proc.communicate(), SANDBOX_TIMEOUT_SECS)
    except TimeoutError:
        proc.kill()
        return {"error": "timeout", "crawl_result": {}}
    if proc.returncode != 0:
        logger.warning("crawler_failed", stderr=err_b.decode()[:200] if err_b else "")
        return {"error": "crawler_failed", "crawl_result": {}}
    try:
        parsed_json = json.loads(out_b.decode())
        return {"crawl_result": parsed_json}
    except json.JSONDecodeError as exc:
        return {"error": str(exc), "crawl_result": {}}
