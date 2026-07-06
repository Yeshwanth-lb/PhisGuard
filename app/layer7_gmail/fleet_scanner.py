"""Layer 7 - Fleet scanner: run the historical scanner across every mailbox
in the Workspace domain, not just the one pinned test account.

This is the actual "detect everything once given access" entry point: it
turns discover-the-domain (directory_client) + scan-one-mailbox
(historical_scanner) into scan-the-whole-domain. Mailboxes are scanned with
bounded concurrency so a large domain doesn't fire hundreds of simultaneous
Gmail API calls and hit per-project quota.
"""
import asyncio
from collections.abc import Callable

import structlog

from .directory_client import list_domain_users
from .historical_scanner import scan_inbox

logger = structlog.get_logger()


async def scan_all_mailboxes(
    analyze_fn: Callable,
    settings,
    query: str = "",
    max_messages_per_user: int = 200,
    mailbox_concurrency: int = 3,
    per_mailbox_concurrency: int = 5,
) -> dict:
    """Discover every mailbox in the domain and scan each one's inbox.

    Returns a summary with per-mailbox results plus aggregate totals. A
    mailbox whose scan raises is recorded as an error entry, not a fatal
    failure for the rest of the fleet — one broken mailbox must not stop the
    domain-wide sweep.
    """
    users = list_domain_users(settings)
    if not users:
        logger.warning("fleet_no_users_discovered")
        return {"domain": getattr(settings, "google_workspace_domain", ""),
                "mailboxes": 0, "results": {}, "totals": _empty_totals()}

    sem = asyncio.Semaphore(mailbox_concurrency)
    results: dict[str, dict] = {}

    async def _scan_one(user_email: str) -> None:
        async with sem:
            try:
                results[user_email] = await scan_inbox(
                    analyze_fn, settings, query=query,
                    max_messages=max_messages_per_user,
                    concurrency=per_mailbox_concurrency,
                    user_email=user_email,
                )
            except Exception as exc:
                logger.warning("fleet_mailbox_scan_err", user_email=user_email, error=str(exc))
                results[user_email] = {"error": str(exc)}

    await asyncio.gather(*[_scan_one(u) for u in users])

    totals = _empty_totals()
    for r in results.values():
        for k in totals:
            totals[k] += r.get(k, 0)

    logger.info("fleet_scan_complete", domain=getattr(settings, "google_workspace_domain", ""),
                mailboxes=len(users), **totals)
    return {
        "domain": getattr(settings, "google_workspace_domain", ""),
        "mailboxes": len(users),
        "results": results,
        "totals": totals,
    }


def _empty_totals() -> dict:
    return {"total": 0, "scanned": 0, "skipped": 0,
            "phishing": 0, "suspicious": 0, "clean": 0, "errors": 0}
