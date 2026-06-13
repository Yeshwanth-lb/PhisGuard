"""Layer 5 - Retrain script: loads stored JSONL records and retrains the behavioral model."""
import json
import os
import glob
import structlog
from .feature_extractor import extract_features, label_from_verdict

logger = structlog.get_logger()

FEATURE_KEYS = [
    "url_count", "has_http_url", "has_ip_url",
    "l1_hit_count", "structural_score", "nlp_score",
    "behavioral_score", "l2_confidence", "urgent_word_count",
    "brand_spoof_count", "subject_len", "spf_fail",
    "dkim_fail", "attachment_count",
]


def load_dataset(data_dir: str) -> tuple:
    X, y = [], []
    pattern = os.path.join(data_dir, "*.jsonl")
    for path in glob.glob(pattern):
        with open(path) as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                    feats = rec.get("features") or {}
                    row = [float(feats.get(k, 0.0)) for k in FEATURE_KEYS]
                    X.append(row)
                    y.append(int(rec.get("label", 0)))
                except Exception:
                    continue
    return X, y


def retrain(data_dir: str = "data/training", model_out: str = "data/model.pkl") -> dict:
    X, y = load_dataset(data_dir)
    if len(X) < 10:
        logger.warning("retrain_skipped", reason="insufficient_data", n=len(X))
        return {"status": "skipped", "n_samples": len(X)}
    try:
        from sklearn.ensemble import GradientBoostingClassifier  # type: ignore
        from sklearn.model_selection import cross_val_score  # type: ignore
        import pickle
        model = GradientBoostingClassifier(n_estimators=100, max_depth=4, random_state=42)
        model.fit(X, y)
        scores = cross_val_score(model, X, y, cv=min(5, len(X)), scoring="f1")
        metrics = {"cv_f1_mean": float(scores.mean()), "cv_f1_std": float(scores.std()), "n_samples": len(X)}
        os.makedirs(os.path.dirname(model_out) or ".", exist_ok=True)
        with open(model_out, "wb") as fout:
            pickle.dump(model, fout)
        logger.info("retrain_complete", **metrics)
        return {"status": "ok", **metrics}
    except Exception as exc:
        logger.warning("retrain_err", error=str(exc))
        return {"status": "error", "error": str(exc)}
