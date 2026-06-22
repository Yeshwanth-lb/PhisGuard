"""Phase 3 gate tests - Page Analyzer, OCR Engine, and Sandbox Runner."""
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

from app.layer3_sandbox.ocr_engine import ocr_screenshot
from app.layer3_sandbox.page_analyzer import analyze_page
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
def test_layer3_empty_urls():
    class FakeSettings: pass
    result = asyncio.run(run_layer3([], FakeSettings()))
    assert result["verdict"] == "skipped"


# ---------------------------------------------------------------------------
# TC-P3-05: Sandbox runner - Docker SDK detonation
# The sandbox switched from CLI (create_subprocess_exec) to the Python
# Docker SDK. Tests now mock docker.DockerClient instead.
# ---------------------------------------------------------------------------

def test_sandbox_docker_command_flags():
    """detonate_url must call containers.run with the correct security flags."""
    crawl_payload = {
        "url": "http://evil.test/login",
        "final_url": "http://evil.test/login",
        "title": "Login",
        "dom_html": "",
        "scripts": [],
        "form_data": [{"fields": [{"name": "password", "type": "password"}]}],
        "redirects": [],
    }

    mock_client = MagicMock()
    mock_client.containers.run.return_value = json.dumps(crawl_payload).encode()

    from app.layer3_sandbox import sandbox_runner

    with patch("docker.DockerClient", return_value=mock_client):
        result = asyncio.run(
            sandbox_runner.detonate_url("http://evil.test/login", docker_image="phishguard-sandbox:latest")
        )

    assert result.get("crawl_result") == crawl_payload, f"unexpected result: {result}"
    call_kwargs = mock_client.containers.run.call_args
    assert call_kwargs is not None
    kwargs = call_kwargs.kwargs if call_kwargs.kwargs else call_kwargs[1]
    assert kwargs.get("remove") is True
    assert "ALL" in kwargs.get("cap_drop", [])
    assert "no-new-privileges" in kwargs.get("security_opt", [])
    assert kwargs.get("read_only") is True


def test_sandbox_docker_nonzero_exit_returns_error():
    """ContainerError from Docker SDK must return an error dict, not raise.

    The runner falls back to CLI when SDK raises, so we mock both paths to
    ensure the error propagates all the way through to the return value.
    """
    import docker as _docker

    mock_client = MagicMock()
    mock_client.containers.run.side_effect = _docker.errors.ContainerError(
        "phishguard-sandbox:latest", 1, "node", "phishguard-sandbox:latest", b""
    )

    # CLI fallback proc with non-zero exit
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.communicate = AsyncMock(return_value=(b"", b""))
    mock_proc.kill = MagicMock()

    from app.layer3_sandbox import sandbox_runner

    with patch("docker.DockerClient", return_value=mock_client), \
         patch("asyncio.create_subprocess_exec", AsyncMock(return_value=mock_proc)):
        result = asyncio.run(
            sandbox_runner.detonate_url("http://evil.test", docker_image="phishguard-sandbox:latest")
        )

    assert "error" in result
    assert result.get("crawl_result") == {}


def test_sandbox_docker_timeout_kills_container():
    """A hung SDK run_in_executor must return a timeout error dict."""
    import asyncio as _aio

    mock_client = MagicMock()

    def slow_run(*args, **kwargs):
        import time; time.sleep(9999)

    mock_client.containers.run.side_effect = slow_run

    from app.layer3_sandbox import sandbox_runner

    original_timeout = sandbox_runner.SANDBOX_TIMEOUT_SECS
    sandbox_runner.SANDBOX_TIMEOUT_SECS = 0.05
    try:
        with patch("docker.DockerClient", return_value=mock_client):
            result = asyncio.run(
                sandbox_runner.detonate_url("http://evil.test", docker_image="phishguard-sandbox:latest")
            )
    finally:
        sandbox_runner.SANDBOX_TIMEOUT_SECS = original_timeout

    assert result.get("error") == "timeout"


def test_sandbox_no_docker_image_uses_node():
    """Without a docker_image, the runner must fall back to the local node crawler."""
    crawl_payload = {"url": "http://x.test", "final_url": "http://x.test",
                     "title": "", "dom_html": "", "scripts": [], "form_data": [], "redirects": []}
    mock_proc = _make_mock_proc(json.dumps(crawl_payload).encode())
    captured_cmd = []

    async def fake_exec(*cmd, **kwargs):
        captured_cmd.extend(cmd)
        return mock_proc

    from app.layer3_sandbox import sandbox_runner

    with patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
        result = asyncio.run(sandbox_runner.detonate_url("http://x.test"))

    assert "docker" not in captured_cmd
    assert "node" in captured_cmd
    assert result.get("crawl_result") == crawl_payload
