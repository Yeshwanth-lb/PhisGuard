"""Layer 4 Slack live integration test.

Runs only when SLACK_WEBHOOK_URL is set in the environment. Posts a single
clearly-labeled smoke-test card to the configured channel and asserts the
Slack API accepted the payload.

Skipped automatically in CI (which excludes *_live.py files) and skipped on
any developer machine without a webhook configured.
"""
import os

import pytest

pytestmark = pytest.mark.skipif(
    not os.getenv("SLACK_WEBHOOK_URL"),
    reason="SLACK_WEBHOOK_URL not set in environment; live Slack tests skipped",
)


SMOKE_VERDICT = {
    "verdict": "phishing",
    "confidence": 0.95,
    "blocked_at": "layer2",
    "parsed": {
        "from_header": "smoke-test@phishguard.local",
        "subject": "[PhishGuard live test] verifying Slack alerting -- ignore",
        "urls": ["https://example.test/smoke"],
    },
}


def test_slack_webhook_url_shape():
    """Cheap sanity check: webhook URL points at hooks.slack.com."""
    url = os.environ["SLACK_WEBHOOK_URL"].strip()
    assert url.startswith("https://hooks.slack.com/services/"), (
        "SLACK_WEBHOOK_URL does not look like a Slack incoming webhook"
    )
    parts = url.rstrip("/").split("/")
    assert len(parts) >= 7, "webhook URL missing expected path segments"
    team_id, bot_id, secret = parts[4], parts[5], parts[6]
    assert team_id and bot_id and secret, "webhook URL has empty path components"


async def test_slack_live_smoke():
    """End-to-end: real HTTPS POST to Slack with a labeled smoke-test card."""
    from app.config import settings
    from app.layer4_soar.slack_notifier import notify_slack

    assert settings.slack_webhook_url, "settings did not load SLACK_WEBHOOK_URL from env"

    result = await notify_slack(SMOKE_VERDICT, settings)
    assert result is True, "notify_slack returned False; check webhook validity and channel access"


async def test_slack_live_skips_clean_verdict():
    """Sanity: live webhook present, but clean verdict must NOT trigger a post."""
    from app.config import settings
    from app.layer4_soar.slack_notifier import notify_slack

    clean = {**SMOKE_VERDICT, "verdict": "clean"}
    result = await notify_slack(clean, settings)
    assert result is False, "notify_slack posted on a clean verdict; verdict-routing is broken"
