"""Layer 5 - MLflow tracker: log verdict metrics and model runs."""
import structlog
from .feature_extractor import extract_features, label_from_verdict

logger = structlog.get_logger()


def log_verdict_to_mlflow(verdict_doc: dict, settings) -> bool:
    tracking_uri = getattr(settings, "mlflow_tracking_uri", None)
    if not tracking_uri:
        return False
    try:
        import mlflow  # type: ignore
        mlflow.set_tracking_uri(tracking_uri)
        mlflow.set_experiment("phishguard-verdicts")
        feats = extract_features(verdict_doc)
        lbl = label_from_verdict(verdict_doc)
        with mlflow.start_run():
            mlflow.log_params({
                "verdict": verdict_doc.get("verdict"),
                "blocked_at": str(verdict_doc.get("blocked_at")),
            })
            mlflow.log_metrics({
                "confidence": float(verdict_doc.get("confidence", 0.0)),
                "label": float(lbl),
                "structural_score": feats["structural_score"],
                "nlp_score": feats["nlp_score"],
                "behavioral_score": feats["behavioral_score"],
            })
        logger.info("mlflow_logged", verdict=verdict_doc.get("verdict"))
        return True
    except Exception as exc:
        logger.warning("mlflow_err", error=str(exc))
        return False


def register_model(model_path: str, settings, metrics: dict) -> bool:
    tracking_uri = getattr(settings, "mlflow_tracking_uri", None)
    if not tracking_uri:
        return False
    try:
        import mlflow
        mlflow.set_tracking_uri(tracking_uri)
        with mlflow.start_run():
            mlflow.log_metrics(metrics)
            mlflow.sklearn.log_model(  # type: ignore
                sk_model=None,
                artifact_path="model",
                registered_model_name="phishguard-behavioral",
            )
        logger.info("model_registered", path=model_path)
        return True
    except Exception as exc:
        logger.warning("model_register_err", error=str(exc))
        return False
