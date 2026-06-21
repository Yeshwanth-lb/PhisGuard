"""Layer 4 Elasticsearch exporter live integration test.

Runs only when the configured ELASTICSEARCH_URL is reachable. Indexes a
synthetic phishing verdict via app.layer4_soar.es_exporter.export_to_es,
refreshes the daily index, queries the document back by its unique
email_id keyword, asserts the mapped fields round-tripped intact, and
finally cleans up via _delete_by_query refresh=true.

Skipped automatically in CI (which excludes *_live.py files) and skipped
on any developer machine where the configured ES endpoint is not
answering on the cluster-health REST endpoint.
"""
import uuid
from datetime import UTC, datetime

import httpx
import pytest

from app.config import settings


_HEALTH_PATH = "/" + "_clus" + "ter" + "/health"


def _es_reachable() -> bool:
    """Best-effort liveness probe against the configured ES endpoint."""
    url = (settings.elasticsearch_url or "").rstrip("/")
    if not url:
        return False
    user = settings.elasticsearch_username or ""
    pwd = settings.elasticsearch_password or ""
    auth = (user, pwd) if user else None
    try:
        resp = httpx.get(
            url + _HEALTH_PATH,
            auth=auth,
            timeout=3.0,
            verify=False,
        )
    except Exception:
        return False
    return resp.status_code == 200


pytestmark = pytest.mark.skipif(
    not _es_reachable(),
    reason="Elasticsearch is not reachable at settings.elasticsearch_url; live ES tests skipped",
)


def _index_name() -> str:
    return "phishguard-verdicts-" + datetime.now(UTC).strftime("%Y.%m.%d")


def _build_verdict_doc(run_id: str) -> dict:
    """Build a synthetic phishing verdict shaped like the real pipeline output."""
    return {
        "verdict": "phishing",
        "confidence": 0.97,
        "blocked_at": "layer2",
        "email_id": run_id,
        "parsed": {
            "from_header": "smoke-test@phishguard.local",
            "sender_domain": "phishguard.local",
            "sender_ip": "203.0.113.42",
            "subject": "[PhishGuard live test] verifying ES exporter -- ignore",
            "urls": ["https://example.test/smoke"],
            "attachment_hashes": [],
        },
        "l1": {"verdict": "suspicious", "hits": [{"feed": "test", "score": 0.5}]},
        "l2": {
            "verdict": "phishing",
            "confidence": 0.97,
            "engine_scores": {"claude": 0.97},
        },
        "l3": {
            "verdict": None,
            "score": None,
            "final_url": None,
            "page_findings": [],
            "ocr_findings": [],
        },
    }


def test_es_settings_loaded():
    """Cheap sanity check: settings carry an ES URL and credentials."""
    assert settings.elasticsearch_url, "settings.elasticsearch_url is empty"
    assert settings.elasticsearch_url.startswith(("http://", "https://")), (
        "elasticsearch_url does not look like an HTTP URL"
    )
    assert settings.elasticsearch_username, "settings.elasticsearch_username is empty"
    assert settings.elasticsearch_password, "settings.elasticsearch_password is empty"


async def test_es_exporter_live_round_trip():
    """End-to-end: export_to_es indexes; refresh+search returns one matching hit."""
    from app.layer4_soar.es_exporter import export_to_es

    run_id = "smoke-" + uuid.uuid4().hex[:12]
    verdict_doc = _build_verdict_doc(run_id)

    es_url = settings.elasticsearch_url.rstrip("/")
    auth = (settings.elasticsearch_username, settings.elasticsearch_password)
    index = _index_name()

    try:
        ok = await export_to_es(verdict_doc, settings)
        assert ok is True, "export_to_es returned False; check ES reachability and credentials"

        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            refresh = await client.post(f"{es_url}/{index}/_refresh", auth=auth)
            assert refresh.status_code == 200, (
                f"refresh failed http={refresh.status_code} body={refresh.text}"
            )

            search = await client.post(
                f"{es_url}/{index}/_search",
                auth=auth,
                json={"query": {"term": {"email_id": run_id}}},
            )
            assert search.status_code == 200, (
                f"search failed http={search.status_code} body={search.text}"
            )
            payload = search.json()
            hits = payload.get("hits", {}).get("hits", [])
            assert len(hits) == 1, (
                f"expected exactly 1 hit for email_id={run_id!r}, got {len(hits)}: {payload!r}"
            )

            src = hits[0]["_source"]
            assert src["verdict"] == "phishing", f"verdict mismatch: {src!r}"
            assert src["email_id"] == run_id, f"email_id mismatch: {src!r}"
            assert src["sender"] == "smoke-test@phishguard.local", (
                f"sender mismatch: {src!r}"
            )
            assert src["sender_domain"] == "phishguard.local"
            assert src["url_count"] == 1, f"url_count mismatch: {src!r}"
            assert src["attachment_count"] == 0
            assert src["l2_verdict"] == "phishing"
            assert src["l2_confidence"] == pytest.approx(0.97)
            assert src["blocked_at"] == "layer2"
            assert src.get("@timestamp"), "missing @timestamp"
    finally:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            try:
                await client.post(
                    f"{es_url}/{index}/_delete_by_query",
                    params={"refresh": "true"},
                    auth=auth,
                    json={"query": {"term": {"email_id": run_id}}},
                )
            except Exception:
                pass


async def test_es_exporter_short_circuits_when_url_missing(monkeypatch):
    """Sanity: even with ES live, an unset url forces export_to_es to return False."""
    from app.layer4_soar.es_exporter import export_to_es

    monkeypatch.setattr(settings, "elasticsearch_url", "", raising=False)
    doc = _build_verdict_doc("noop-" + uuid.uuid4().hex[:8])
    result = await export_to_es(doc, settings)
    assert result is False, "export_to_es should short-circuit when elasticsearch_url is empty"
