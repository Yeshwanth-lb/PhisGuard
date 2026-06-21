"""Layer 5 - MLflow tracker: log verdict metrics and model runs."""
import hashlib
import pickle

import structlog

from .feature_extractor import extract_features, label_from_verdict

logger = structlog.get_logger()


def log_verdict_to_mlflow(verdict_doc: dict, settings) -> bool:
    tracking_uri = getattr(settings, "mlflow_tracking_uri", None)
    if not tracking_uri:
        return False
    try:
        import mlflow
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
    """Register the trained pickle as an MLflow sklearn model artifact.

    After logging the model artifact, the latest version is immediately
    transitioned to the 'Production' stage so the running app can be
    configured to load a specific production-pinned version instead of
    silently picking up whatever 'latest' is.  The SHA-256 of the pickle
    file is stored as a model tag to enable hash-based pinning in CI.
    """
    tracking_uri = getattr(settings, "mlflow_tracking_uri", None)
    if not tracking_uri:
        return False
    try:
        import mlflow
        import mlflow.sklearn
        from mlflow.tracking import MlflowClient

        with open(model_path, "rb") as fh:
            raw = fh.read()
            model = pickle.loads(raw)

        model_sha256 = hashlib.sha256(raw).hexdigest()

        mlflow.set_tracking_uri(tracking_uri)
        mlflow.set_experiment("phishguard-layer5")
        with mlflow.start_run() as run:
            scalar = {
                k: v for k, v in metrics.items()
                if isinstance(v, (int, float)) and not isinstance(v, bool)
            }
            mlflow.log_metrics(scalar)
            mlflow.set_tag("model_sha256", model_sha256)
            mlflow.sklearn.log_model(
                sk_model=model,
                artifact_path="model",
                registered_model_name="phishguard-layer5",
            )
            run_id = run.info.run_id

        # Pin the version we just registered to Production so production
        # always runs a known, hash-verified model version.
        client = MlflowClient(tracking_uri=tracking_uri)
        versions = client.search_model_versions(
            f"name='phishguard-layer5' and run_id='{run_id}'"
        )
        if versions:
            version_number = versions[0].version
            client.set_model_version_tag(
                name="phishguard-layer5",
                version=version_number,
                key="model_sha256",
                value=model_sha256,
            )
            client.transition_model_version_stage(
                name="phishguard-layer5",
                version=version_number,
                stage="Production",
                archive_existing_versions=True,
            )
            logger.info(
                "model_promoted_to_production",
                version=version_number,
                sha256=model_sha256[:16],
            )

        logger.info("model_registered", path=model_path, sha256=model_sha256[:16])
        return True
    except Exception as exc:
        logger.warning("model_register_err", error=str(exc))
        return False
