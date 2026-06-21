"""Layer 5 - Retrain entrypoint.

Thin wrapper around training_pipeline.train_and_evaluate so the long-standing
public API ("retrain") keeps working while the heavy lifting moves into the
upgraded pipeline module.
"""
import structlog

from .feature_extractor import FEATURE_KEYS
from .training_pipeline import train_and_evaluate

logger = structlog.get_logger()


def load_dataset(data_dir: str):
    """Backwards-compatible loader used by older callers and tests."""
    import glob
    import json
    import os

    X, y = [], []
    for path in glob.glob(os.path.join(data_dir, "*.jsonl")):
        with open(path) as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                feats = rec.get("features") or {}
                row = [float(feats.get(k, 0.0)) for k in FEATURE_KEYS]
                X.append(row)
                y.append(int(rec.get("label", 0)))
    return X, y


def retrain(
    data_dir: str = "data/training",
    model_out: str = "data/model.pkl",
    db_path: str = "data/phishguard.db",
    baselines_dir: str = "ml/baselines",
    mlflow_tracking_uri=None,
):
    """Train a fresh calibrated classifier and emit a full metric panel."""
    return train_and_evaluate(
        data_dir=data_dir,
        db_path=db_path,
        model_out=model_out,
        baselines_dir=baselines_dir,
        mlflow_tracking_uri=mlflow_tracking_uri,
    )
