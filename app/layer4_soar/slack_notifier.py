"""Layer 4 - Slack notifier: post real-time alerts to a Slack channel."""
import structlog
logger = structlog.get_logger()


def _build_message(verdict_doc: dict) -> dict:
    verdict = verdict_doc.get("verdict", "unknown")
    conf = verdict_doc.get("confidence", 0.0)
    blocked_at = verdict_doc.get("blocked_at", "none")
    parsed = verdict_doc.get("parsed") or {}
    sender = parsed.get("from_header", "unknown")
    subject = parsed.get("subject", "unknown")
    emoji = ":rotating_light:" if verdict == "phishing" else ":warning:"
    color = "danger" if verdict == "phishing" else "warning"
    return {
        "attachments": [{
            "color": color,
            "title": f"{emoji} PhishGuard: {verdict.upper()} (confidence {conf:.0%})",
            "fields": [
                {"title": "From", "value": sender, "short": True},
                {"title": "Subject", "value": subject, "short": True},
                {"title": "Blocked at", "value": blocked_at, "short": True},
            ],
        }]
    }


async def notify_slack(verdict_doc: dict, settings) -> bool:
    webhook = getattr(settings, "slack_webhook_url", None)
    if not webhook:
        return False
    verdict = verdict_doc.get("verdict", "")
    if verdict not in ("phishing", "suspicious"):
        return False
    try:
        import httpx
        payload = _build_message(verdict_doc)
        async with httpx.AsyncClient() as client:
            resp = await client.post(webhook, json=payload, timeout=10)
            resp.raise_for_status()
            logger.info("slack_notified", verdict=verdict)
            return True
    except Exception as exc:
        logger.warning("slack_error", error=str(exc))
        return False
