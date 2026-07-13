"""Section 2 — reliability & observability: engine-failure alerting, degraded
verdicts, and fleet watch-health rollup."""
import asyncio
import time
from unittest.mock import patch

from app.layer2_ai import orchestrator
from app.layer7_gmail import watch_state


# ── Engine-failure surfacing (degraded_engines) ──────────────────────────────
class TestEngineFailureSurfacing:
    def _run(self, structural_exc=False):
        async def fake_structural(parsed):
            if structural_exc:
                raise RuntimeError("boom: structural crashed")
            return {"engine": "structural", "score": 0.0, "social_engineering_score": 0.0,
                    "social_engineering_categories": []}
        async def fake_nlp(parsed, **kw):
            return {"engine": "nlp", "score": 0.1}
        async def fake_behavioral(parsed, **kw):
            return {"engine": "behavioral", "score": 0.1}
        with patch.object(orchestrator, "run_structural", fake_structural), \
             patch.object(orchestrator, "run_nlp", fake_nlp), \
             patch.object(orchestrator, "run_behavioral", fake_behavioral), \
             patch.object(orchestrator, "LLMClient", lambda s: type("C", (), {"provider": "x"})()), \
             patch.object(orchestrator, "_alert_engine_failure", lambda *a, **k: _noop()):
            return asyncio.run(orchestrator.run_layer2({"sender_domain": "x.com"}, object()))

    def test_healthy_run_reports_no_degraded_engines(self):
        r = self._run(structural_exc=False)
        assert r["degraded_engines"] == []

    def test_engine_crash_is_surfaced_not_silent(self):
        r = self._run(structural_exc=True)
        assert "structural" in r["degraded_engines"]
        assert r["engines"]["structural"]["status"] == "error"
        # verdict still produced (degraded, not crashed)
        assert r["verdict"] in ("clean", "suspicious", "phishing")


async def _noop():
    return None


class TestEngineAlertThrottle:
    def test_alert_throttled_per_engine(self):
        orchestrator._engine_alert_last.clear()

        class S:
            slack_webhook_url = "https://hooks.slack.test/x"
        posts = []

        class _FakeResp:
            def raise_for_status(self): pass

        class _FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def post(self, url, **kw): posts.append(url); return _FakeResp()

        with patch("httpx.AsyncClient", _FakeClient):
            # two rapid failures for the same engine → only one alert
            asyncio.run(orchestrator._alert_engine_failure("nlp", "err1", S()))
            asyncio.run(orchestrator._alert_engine_failure("nlp", "err2", S()))
        assert len(posts) == 1


# ── Fleet watch-health rollup ────────────────────────────────────────────────
class TestWatchHealthSummary:
    def _seed(self, tmp_db, rows):
        watch_state._STATE_DB = tmp_db
        for email, expiry_ms in rows:
            watch_state.save_watch(email, "h", expiry_ms)

    def test_empty_is_all_zero_and_healthy(self, tmp_path):
        watch_state._STATE_DB = str(tmp_path / "w.db")
        s = watch_state.health_summary()
        assert s["total_mailboxes"] == 0 and s["protected"] == 0 and s["healthy"] is True

    def test_classifies_protected_expiring_stale(self, tmp_path):
        now_ms = time.time() * 1000
        self._seed(str(tmp_path / "w.db"), [
            ("ok@x.com", now_ms + 6 * 86400 * 1000),      # 6 days out → protected
            ("soon@x.com", now_ms + 3600 * 1000),          # 1h out → expiring (within 24h)
            ("expired@x.com", now_ms - 1000),              # already expired → stale
            ("never@x.com", None),                          # never registered → stale
        ])
        s = watch_state.health_summary(expiring_hours=24)
        assert s["total_mailboxes"] == 4
        assert s["protected"] == 1
        assert s["expiring_soon"] == 1
        assert s["stale_or_expired"] == 2
        assert s["healthy"] is False   # stale present
