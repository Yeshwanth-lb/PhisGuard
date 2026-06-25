"""ThreatLens scheduler — daemon thread that fires profiling cycles on cadence.

Follows the same pattern as app/layer4_soar/digest.py.
Exposes _run_one_tick() for direct testing (no thread, no sleep).
"""
from __future__ import annotations

import asyncio
import threading
import time

import structlog

from app.threatlens.config import threatlens_settings

logger = structlog.get_logger()

_run_lock = threading.Lock()
_scheduler_thread: threading.Thread | None = None


def _cadence_secs() -> int:
    c = threatlens_settings.intel_run_cadence
    if c == "hourly":
        return 3600
    if c == "on_campaign":
        return 3600  # poll every hour; campaign triggers are handled in orchestrator
    return 86400    # daily default


def _run_one_tick() -> None:
    """Execute one scheduler tick: check enabled flag, check for overlap, run cycle.

    Callable directly in tests without spinning up a thread.
    """
    if not threatlens_settings.intel_enabled:
        logger.debug("threatlens_scheduler_tick_disabled")
        return

    if not _run_lock.acquire(blocking=False):
        logger.info("threatlens_scheduler_skip_overlap")
        return

    try:
        asyncio.run(_do_run())
    except Exception as exc:
        logger.warning("threatlens_scheduler_error", error=str(exc)[:200])
    finally:
        _run_lock.release()


async def _do_run() -> None:
    from app.threatlens.orchestrator import run_cycle
    from app.threatlens.org_assessor import assess
    await run_cycle()
    await assess()


def _run_loop() -> None:
    """Background loop — sleeps between ticks."""
    while True:
        time.sleep(_cadence_secs())
        _run_one_tick()


def start_scheduler() -> None:
    """Start the daemon scheduler thread. No-op when INTEL_ENABLED=false."""
    global _scheduler_thread

    if not threatlens_settings.intel_enabled:
        logger.info("threatlens_scheduler_disabled_skip")
        return

    if _scheduler_thread and _scheduler_thread.is_alive():
        logger.debug("threatlens_scheduler_already_running")
        return

    _scheduler_thread = threading.Thread(
        target=_run_loop,
        daemon=True,
        name="threatlens-scheduler",
    )
    _scheduler_thread.start()
    logger.info(
        "threatlens_scheduler_started",
        cadence=threatlens_settings.intel_run_cadence,
        interval_secs=_cadence_secs(),
    )
