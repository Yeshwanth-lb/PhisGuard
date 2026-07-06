"""Layer 7 - Fleet watch orchestrator: register and renew Gmail push watches
across every mailbox in the domain, not just one pinned account.

Two entry points:
  setup_fleet_watches()    — register a watch for each discovered mailbox
  renew_expiring_watches() — renew whichever mailboxes are close to expiry

Both fail closed per-mailbox (one broken mailbox doesn't stop the rest) and
alert Slack on failure, because a watch silently expiring means that mailbox
just stops being protected with no error anywhere else to catch it.
"""
import asyncio

import structlog

from .directory_client import list_domain_users
from .gmail_setup import setup_gmail_watch, renew_gmail_watch
from . import watch_state

logger = structlog.get_logger()


async def _alert_slack(settings, text: str) -> None:
    webhook = getattr(settings, "slack_webhook_url", None)
    if not webhook:
        return
    try:
        import httpx
        async with httpx.AsyncClient() as client:
            await client.post(webhook, json={"text": text}, timeout=10)
    except Exception as exc:
        logger.warning("fleet_watch_slack_alert_failed", error=str(exc))


def _resolve_users(settings, only_users: list[str] | None) -> list[str]:
    directory_users = list_domain_users(settings)
    if not only_users:
        return directory_users
    directory_set = set(directory_users)
    users = [u for u in only_users if u in directory_set]
    skipped = set(only_users) - directory_set
    if skipped:
        logger.warning("fleet_watch_pilot_users_not_in_directory", skipped=sorted(skipped))
    return users


async def setup_fleet_watches(settings, only_users: list[str] | None = None,
                               concurrency: int = 3) -> dict:
    """Register a Gmail watch for each discovered (or pilot-listed) mailbox
    and persist its expiry to watch_state. Returns per-mailbox results."""
    users = _resolve_users(settings, only_users)
    if not users:
        logger.warning("fleet_watch_no_users")
        return {"mailboxes": 0, "results": {}}

    sem = asyncio.Semaphore(concurrency)
    results: dict[str, dict] = {}
    failures: list[str] = []

    async def _one(user_email: str) -> None:
        async with sem:
            try:
                r = await asyncio.to_thread(setup_gmail_watch, settings, user_email)
                results[user_email] = r
                if r.get("ok"):
                    watch_state.save_watch(user_email, r.get("history_id"), r.get("watch_expiry"))
                else:
                    failures.append(user_email)
            except Exception as exc:
                logger.warning("fleet_watch_setup_err", user_email=user_email, error=str(exc))
                results[user_email] = {"ok": False, "error": str(exc)}
                failures.append(user_email)

    await asyncio.gather(*[_one(u) for u in users])

    if failures:
        await _alert_slack(
            settings,
            f":warning: PhishGuard fleet watch setup failed for {len(failures)}/{len(users)} "
            f"mailbox(es): {', '.join(failures[:10])}{'...' if len(failures) > 10 else ''}",
        )

    logger.info("fleet_watch_setup_complete", mailboxes=len(users), failures=len(failures))
    return {"mailboxes": len(users), "results": results}


async def renew_expiring_watches(settings, within_hours: int = 24,
                                  concurrency: int = 3) -> dict:
    """Renew every mailbox whose watch expires within `within_hours` (or has
    no recorded state at all). Intended to be called on a schedule, well
    inside the 7-day expiry window, not exactly at the deadline."""
    expiring = watch_state.list_expiring_within(within_hours)
    if not expiring:
        return {"checked": 0, "renewed": 0, "failed": 0}

    sem = asyncio.Semaphore(concurrency)
    renewed = 0
    failed: list[str] = []

    async def _one(user_email: str) -> None:
        nonlocal renewed
        async with sem:
            try:
                r = await asyncio.to_thread(renew_gmail_watch, settings, user_email)
                if r.get("ok"):
                    watch_state.save_watch(user_email, None, r.get("watch_expiry"))
                    renewed += 1
                else:
                    failed.append(user_email)
            except Exception as exc:
                logger.warning("fleet_watch_renew_err", user_email=user_email, error=str(exc))
                failed.append(user_email)

    await asyncio.gather(*[_one(u) for u in expiring])

    if failed:
        await _alert_slack(
            settings,
            f":rotating_light: PhishGuard watch renewal FAILED for {len(failed)} mailbox(es) — "
            f"these will stop receiving live phishing detection once their watch expires: "
            f"{', '.join(failed[:10])}{'...' if len(failed) > 10 else ''}",
        )

    logger.info("fleet_watch_renewal_complete", checked=len(expiring), renewed=renewed, failed=len(failed))
    return {"checked": len(expiring), "renewed": renewed, "failed": len(failed)}
