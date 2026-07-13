"""Detection quality regression gate against the modern eval corpus.

Marked `live` because it drives the full pipeline (LLM + all layers) via the
running app on localhost:8000 — skipped automatically when the app isn't up, so
it never breaks the fast/unit suite. Run explicitly with:  make eval  (or
`pytest -m live tests/test_detection_eval.py`).

Thresholds are floors with margin below observed performance (88% recall / 0%
FP at time of writing), so normal LLM variance doesn't flake the gate but a real
regression (a whole attack family going dark, or benign mail getting flagged)
fails CI.
"""
import pytest

pytestmark = pytest.mark.live

RECALL_FLOOR = 0.75      # catch >=75% of modern phishing families
FP_CEILING = 0.10        # <=10% of benign wrongly flagged


def _app_up(api="http://localhost:8000"):
    try:
        import httpx
        return httpx.get(f"{api}/health", timeout=5).status_code == 200
    except Exception:
        return False


def test_detection_meets_floor():
    if not _app_up():
        pytest.skip("app not running on localhost:8000 — start the stack (make up) to run the eval gate")
    from scripts.eval_detection import run
    res = run()
    assert res["recall"] >= RECALL_FLOOR, (
        f"phishing recall {res['recall']:.0%} below floor {RECALL_FLOOR:.0%}; "
        f"missed: {res['misses']}")
    assert res["fp_rate"] <= FP_CEILING, (
        f"benign false-positive rate {res['fp_rate']:.0%} above ceiling {FP_CEILING:.0%}; "
        f"false positives: {res['false_positives']}")
