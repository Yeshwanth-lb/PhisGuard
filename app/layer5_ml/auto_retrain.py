"""Layer 5 - Gated automated retraining.

train_and_evaluate() writes the model unconditionally. That's fine for a manual
`make retrain` (a human reads the metrics), but dangerous on an automated
schedule: a bad batch of SOC feedback, or a data glitch, could silently
overwrite a good model with a worse one and quietly degrade detection with
nobody looking.

This module wraps it with a champion/challenger promotion gate:
  1. train the challenger to a TEMP path (never model_out directly)
  2. compare the challenger's held-out ROC-AUC to the stored champion's
  3. PROMOTE (atomically replace model_out) only if
     challenger_auc >= champion_auc - tolerance; otherwise KEEP the champion
  4. either way, alert Slack — a rejected retrain is a signal worth seeing

First run (no champion recorded) promotes unconditionally to bootstrap.
"""
import json
import os
import shutil

import structlog

logger = structlog.get_logger()


def _champion_path(model_out: str) -> str:
    return os.path.splitext(model_out)[0] + ".champion.json"


def _read_champion(model_out: str) -> dict | None:
    p = _champion_path(model_out)
    try:
        if os.path.exists(p):
            with open(p) as fh:
                return json.load(fh)
    except Exception as exc:
        logger.warning("champion_read_err", error=str(exc))
    return None


def _write_champion(model_out: str, metrics: dict) -> None:
    try:
        with open(_champion_path(model_out), "w") as fh:
            json.dump({
                "test_roc_auc": metrics.get("test_roc_auc"),
                "cv_f1_mean": metrics.get("cv_f1_mean"),
                "n_samples_total": metrics.get("n_samples_total"),
                "n_feedback_corrections": metrics.get("n_feedback_corrections"),
            }, fh, indent=2)
    except Exception as exc:
        logger.warning("champion_write_err", error=str(exc))


async def _alert(settings, text: str) -> None:
    webhook = getattr(settings, "slack_webhook_url", "") if settings else ""
    if not webhook:
        return
    try:
        import httpx
        async with httpx.AsyncClient() as client:
            await client.post(webhook, json={"text": text}, timeout=10)
    except Exception as exc:
        logger.warning("auto_retrain_alert_err", error=str(exc))


async def run_gated_retrain(settings) -> dict:
    """Train a challenger and promote it only if it doesn't regress the champion.
    Returns a summary dict with status in {promoted, rejected, skipped, error}."""
    from app.layer5_ml.training_pipeline import train_and_evaluate

    model_out = getattr(settings, "ml_model_path", "data/model.pkl")
    data_dir = getattr(settings, "ml_local_data_dir", "data/training")
    tolerance = getattr(settings, "ml_promote_auc_tolerance", 0.01)
    tmp_out = model_out + ".challenger"

    result = train_and_evaluate(
        data_dir=data_dir,
        db_path=os.environ.get("PHISHGUARD_DB_PATH", "data/phishguard.db"),
        model_out=tmp_out,
        mlflow_tracking_uri=getattr(settings, "mlflow_tracking_uri", None),
    )
    if result.get("status") != "ok":
        # insufficient data / imbalance / sklearn missing — nothing to promote
        logger.info("auto_retrain_no_candidate", status=result.get("status"),
                    reason=result.get("reason"))
        _cleanup(tmp_out)
        return {"status": "skipped", "reason": result.get("reason") or result.get("status")}

    metrics = result["metrics"]
    challenger_auc = metrics.get("test_roc_auc", 0.0)
    champion = _read_champion(model_out)
    champion_auc = champion.get("test_roc_auc") if champion else None

    # Promote if there's no champion yet, or the challenger doesn't regress it.
    if champion_auc is None or challenger_auc >= champion_auc - tolerance:
        try:
            shutil.move(tmp_out, model_out)
        except Exception as exc:
            logger.warning("promote_move_err", error=str(exc))
            _cleanup(tmp_out)
            return {"status": "error", "error": str(exc)}
        _write_champion(model_out, metrics)
        logger.info("auto_retrain_promoted", challenger_auc=round(challenger_auc, 4),
                    champion_auc=round(champion_auc, 4) if champion_auc else None,
                    n_feedback=metrics.get("n_feedback_corrections"))
        await _alert(settings,
                     f":white_check_mark: PhishGuard ML model retrained & promoted "
                     f"(AUC {challenger_auc:.3f}"
                     + (f" vs champion {champion_auc:.3f}" if champion_auc else ", first model")
                     + f", {metrics.get('n_feedback_corrections',0)} SOC corrections).")
        return {"status": "promoted", "challenger_auc": challenger_auc,
                "champion_auc": champion_auc, "metrics": metrics}

    # Challenger regressed — keep the champion, discard the challenger.
    _cleanup(tmp_out)
    logger.warning("auto_retrain_rejected", challenger_auc=round(challenger_auc, 4),
                   champion_auc=round(champion_auc, 4), tolerance=tolerance)
    await _alert(settings,
                 f":warning: PhishGuard ML retrain REJECTED — challenger AUC "
                 f"{challenger_auc:.3f} < champion {champion_auc:.3f} (tol {tolerance}). "
                 f"Keeping current model. Investigate recent SOC feedback / training data.")
    return {"status": "rejected", "challenger_auc": challenger_auc, "champion_auc": champion_auc}


def _cleanup(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass
