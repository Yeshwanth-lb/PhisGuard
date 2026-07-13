"""Gmail fleet watch renewal scheduler — daemon thread that renews expiring
Gmail watches on a cadence, mirroring app/threatlens/scheduler.py's pattern.

Without this, watches expire after 7 days with zero warning delivered
anywhere by Gmail itself — a mailbox just silently stops receiving push
notifications. Checking every 6h against a 24h-out expiry window gives
several retry opportunities before anything actually goes dark.
"""
import threading
import time

import structlog

logger = structlog.get_logger()

_CHECK_INTERVAL_SECS = 6 * 3600
_RENEW_WITHIN_HOURS = 24

_run_lock = threading.Lock()
_scheduler_thread: threading.Thread | None = None


def _fleet_configured(settings) -> bool:
    import os
    sa_path = getattr(settings, "google_service_account_json", "") or ""
    domain = getattr(settings, "google_workspace_domain", "") or ""
    return bool(sa_path and os.path.exists(sa_path) and domain)


def _run_one_tick(settings) -> None:
    """Execute one renewal check. Callable directly in tests without a thread."""
    if not _fleet_configured(settings):
        logger.debug("watch_scheduler_tick_skip_unconfigured")
        return
    if not _run_lock.acquire(blocking=False):
        logger.info("watch_scheduler_skip_overlap")
        return
    try:
        import asyncio
        from app.layer7_gmail.fleet_watch import renew_expiring_watches
        result = asyncio.run(renew_expiring_watches(settings, within_hours=_RENEW_WITHIN_HOURS))
        logger.info("watch_scheduler_tick_complete", **result)
    except Exception as exc:
        logger.warning("watch_scheduler_tick_error", error=str(exc)[:200])
    finally:
        _run_lock.release()


def _run_loop(settings) -> None:
    while True:
        time.sleep(_CHECK_INTERVAL_SECS)
        _run_one_tick(settings)


def start_watch_scheduler(settings) -> None:
    """Start the daemon renewal thread. No-op (logged, not silent) when the
    fleet isn't configured yet — safe to call unconditionally at startup."""
    global _scheduler_thread

    if not _fleet_configured(settings):
        logger.info("watch_scheduler_disabled_not_configured")
        return

    if _scheduler_thread and _scheduler_thread.is_alive():
        logger.debug("watch_scheduler_already_running")
        return

    _scheduler_thread = threading.Thread(
        target=_run_loop, args=(settings,), daemon=True, name="gmail-watch-scheduler",
    )
    _scheduler_thread.start()
    logger.info("watch_scheduler_started", interval_secs=_CHECK_INTERVAL_SECS,
                renew_within_hours=_RENEW_WITHIN_HOURS)
