"""Layer 5 - Automated retrain scheduler.

Daemon thread that fires a gated retrain on a cadence (default weekly),
mirroring app/threatlens/scheduler.py. Opt-in via ML_AUTO_RETRAIN_ENABLED —
off by default because retraining on live SOC feedback should be a deliberate
choice, and the promotion gate (auto_retrain.run_gated_retrain) only protects
against *worse* models, not against a deployer who isn't ready for the model to
move at all.
"""
import threading
import time

import structlog

logger = structlog.get_logger()

_run_lock = threading.Lock()
_scheduler_thread: threading.Thread | None = None


def _cadence_secs(settings) -> int:
    days = getattr(settings, "ml_retrain_cadence_days", 7)
    return max(1, int(days)) * 86400


def _run_one_tick(settings) -> None:
    """Execute one gated retrain. Callable directly in tests (no thread/sleep)."""
    if not getattr(settings, "ml_auto_retrain_enabled", False):
        logger.debug("retrain_scheduler_tick_disabled")
        return
    if not _run_lock.acquire(blocking=False):
        logger.info("retrain_scheduler_skip_overlap")
        return
    try:
        import asyncio
        from app.layer5_ml.auto_retrain import run_gated_retrain
        result = asyncio.run(run_gated_retrain(settings))
        logger.info("retrain_scheduler_tick_complete", **{
            k: v for k, v in result.items() if k != "metrics"
        })
    except Exception as exc:
        logger.warning("retrain_scheduler_tick_error", error=str(exc)[:200])
    finally:
        _run_lock.release()


def _run_loop(settings) -> None:
    while True:
        time.sleep(_cadence_secs(settings))
        _run_one_tick(settings)


def start_retrain_scheduler(settings) -> None:
    """Start the daemon retrain thread. No-op (logged) when disabled."""
    global _scheduler_thread
    if not getattr(settings, "ml_auto_retrain_enabled", False):
        logger.info("retrain_scheduler_disabled")
        return
    if _scheduler_thread and _scheduler_thread.is_alive():
        logger.debug("retrain_scheduler_already_running")
        return
    _scheduler_thread = threading.Thread(
        target=_run_loop, args=(settings,), daemon=True, name="ml-retrain-scheduler",
    )
    _scheduler_thread.start()
    logger.info("retrain_scheduler_started", cadence_days=getattr(settings, "ml_retrain_cadence_days", 7))
