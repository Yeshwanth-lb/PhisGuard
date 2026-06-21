"""Layer 5 - ML Classifier: loads trained model and runs inference."""
import os
import pickle

import structlog

from .feature_extractor import FEATURE_KEYS, extract_features

logger = structlog.get_logger()

_MODEL_CACHE: object | None = None
_MODEL_PATH_CACHE: str = ""


def _load_model(model_path: str):
    global _MODEL_CACHE, _MODEL_PATH_CACHE
    if _MODEL_CACHE is not None and _MODEL_PATH_CACHE == model_path:
        return _MODEL_CACHE
    if not os.path.exists(model_path):
        return None
    try:
        with open(model_path, "rb") as fh:
            _MODEL_CACHE = pickle.load(fh)
        _MODEL_PATH_CACHE = model_path
        logger.info("ml_model_loaded", path=model_path)
        return _MODEL_CACHE
    except Exception as exc:
        logger.warning("ml_model_load_err", error=str(exc))
        return None


def predict(verdict_doc: dict, model_path: str = "data/model.pkl") -> dict:
    """Run ML inference on a verdict doc. Returns score and prediction."""
    model = _load_model(model_path)
    if model is None:
        return {"ml_score": 0.0, "ml_label": 0, "ml_available": False}
    try:
        feats = extract_features(verdict_doc)
        row = [[float(feats.get(k, 0.0)) for k in FEATURE_KEYS]]
        proba = model.predict_proba(row)[0]
        score = float(proba[1]) if len(proba) > 1 else float(proba[0])
        label = int(model.predict(row)[0])
        return {"ml_score": round(score, 4), "ml_label": label, "ml_available": True}
    except Exception as exc:
        logger.warning("ml_predict_err", error=str(exc))
        return {"ml_score": 0.0, "ml_label": 0, "ml_available": False}


def model_info(model_path: str = "data/model.pkl") -> dict:
    """Return metadata about the current trained model."""
    exists = os.path.exists(model_path)
    size = os.path.getsize(model_path) if exists else 0
    mtime = os.path.getmtime(model_path) if exists else None
    model = _load_model(model_path) if exists else None
    model_type = type(model).__name__ if model else "none"
    n_estimators = getattr(model, "n_estimators", None)
    return {
        "model_path": model_path,
        "exists": exists,
        "size_bytes": size,
        "last_trained": mtime,
        "model_type": model_type,
        "n_estimators": n_estimators,
    }
