"""Scheduler tests — cadence, disabled flag, overlap guard."""
import pytest

from app.threatlens.config import threatlens_settings
from app.threatlens.scheduler import _run_lock, _run_one_tick


@pytest.fixture(autouse=True)
def ensure_lock_released():
    """Ensure the lock is released after each test."""
    yield
    if _run_lock.locked():
        try:
            _run_lock.release()
        except RuntimeError:
            pass


def test_scheduler_fires_on_cadence(mocker):
    """When enabled, _run_one_tick() invokes _do_run once (sync test — no running event loop)."""
    call_count = 0

    async def fake_do_run():
        nonlocal call_count
        call_count += 1

    mocker.patch("app.threatlens.scheduler._do_run", fake_do_run)
    mocker.patch.object(threatlens_settings, "intel_enabled", True)

    _run_one_tick()

    assert call_count == 1


def test_scheduler_skips_when_disabled(mocker):
    """When INTEL_ENABLED=false, _run_one_tick() never calls _do_run."""
    mocker.patch.object(threatlens_settings, "intel_enabled", False)
    mock_do = mocker.patch("app.threatlens.scheduler._do_run")

    _run_one_tick()

    mock_do.assert_not_called()


def test_scheduler_run_overlap_guarded(mocker):
    """When _run_lock is already held, _run_one_tick() skips — no concurrent double-profiling."""
    mocker.patch.object(threatlens_settings, "intel_enabled", True)
    mock_do = mocker.patch("app.threatlens.scheduler._do_run")

    _run_lock.acquire()
    try:
        _run_one_tick()
        mock_do.assert_not_called()
    finally:
        _run_lock.release()
