"""Layer 5 - Upgraded training pipeline.

Combines bootstrap, daily verdict records, and DB scans, then trains a
calibrated gradient-boosted classifier and emits a full metric panel.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import pickle
from app import db as _db
import time
from datetime import UTC, datetime

import structlog

from .feature_extractor import FEATURE_KEYS, extract_features

logger = structlog.get_logger()


def _load_jsonl_records(data_dir):
    rows = []
    for path in sorted(glob.glob(os.path.join(data_dir, "*.jsonl"))):
        with open(path) as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                feats = rec.get("features") or {}
                if not feats:
                    continue
                row = [float(feats.get(k, 0.0)) for k in FEATURE_KEYS]
                label = int(rec.get("label", 0))
                rows.append((row, label, os.path.basename(path)))
    return rows


def _load_feedback_records(db_path):
    """Load SOC-corrected verdicts from the feedback table.

    Returns (rows, corrected_scan_ids):
      rows              — feature vectors with the human-corrected label
      corrected_scan_ids — set of scan IDs whose original label must be
                          excluded from _load_db_records so the wrong label
                          doesn't compete with the human correction.

    When the same scan is corrected multiple times only the latest correction
    is used (most recent submitted_at wins).
    """
    # On the Postgres backend db_path is a SQLite path that won't exist — the
    # existence check only guards the SQLite case (no DB file yet = no data).
    if not _db.is_postgres() and not os.path.exists(db_path):
        return [], set()

    rows = []
    corrected_scan_ids = set()
    db = _db.connect(db_path)
    cur = db.cursor()
    try:
        # Latest correction per scan (subquery handles multiple edits)
        cur.execute("""
            SELECT f.scan_id, f.corrected_verdict, s.data_json
            FROM feedback f
            JOIN scans s ON s.id = f.scan_id
            WHERE s.data_json IS NOT NULL
              AND f.submitted_at = (
                  SELECT MAX(f2.submitted_at)
                  FROM feedback f2
                  WHERE f2.scan_id = f.scan_id
              )
        """)
        for scan_id, corrected_verdict, data_json in cur.fetchall():
            try:
                doc = json.loads(data_json) if isinstance(data_json, str) else None
            except json.JSONDecodeError:
                continue
            if not doc:
                continue
            feats = extract_features(doc)
            row = [float(feats.get(k, 0.0)) for k in FEATURE_KEYS]
            label = 1 if corrected_verdict == "phishing" else 0
            rows.append((row, label, f"feedback:{corrected_verdict}"))
            corrected_scan_ids.add(scan_id)
    finally:
        db.close()

    if rows:
        logger.info("feedback_records_loaded", count=len(rows))
    return rows, corrected_scan_ids


def _load_db_records(db_path, exclude_scan_ids=None):
    if not _db.is_postgres() and not os.path.exists(db_path):
        return []
    rows = []
    db = _db.connect(db_path)
    cur = db.cursor()
    try:
        cur.execute("SELECT id, verdict, data_json FROM scans WHERE data_json IS NOT NULL")
        for scan_id, verdict, data_json in cur.fetchall():
            # Skip scans that have a human feedback correction — the corrected
            # version is loaded separately by _load_feedback_records so the
            # original (potentially wrong) label doesn't pollute training.
            if exclude_scan_ids and scan_id in exclude_scan_ids:
                continue
            try:
                doc = json.loads(data_json) if isinstance(data_json, str) else None
            except json.JSONDecodeError:
                continue
            if not doc:
                continue
            feats = extract_features(doc)
            row = [float(feats.get(k, 0.0)) for k in FEATURE_KEYS]
            label = 1 if verdict == "phishing" else 0
            rows.append((row, label, "phishguard.db:scans"))
    finally:
        db.close()
    return rows


def _dedupe(rows):
    seen = {}
    for row in rows:
        feats, label, src = row
        key = hashlib.sha1((json.dumps(feats) + str(label)).encode()).hexdigest()
        if key not in seen:
            seen[key] = row
    return list(seen.values())


def _assemble_corpus(data_dir, db_path):
    # Feedback corrections come first so their scan IDs can be excluded from
    # the raw DB load — prevents the original (wrong) label from competing.
    feedback_rows, corrected_ids = _load_feedback_records(db_path)
    jsonl_rows = _load_jsonl_records(data_dir)
    db_rows = _load_db_records(db_path, exclude_scan_ids=corrected_ids)
    # Feedback rows are added last so deduplication keeps them over any
    # duplicate from jsonl (same features, same label would dedupe fine;
    # different label means feedback always wins because it's the authoritative
    # human correction).
    combined = _dedupe(jsonl_rows + db_rows + feedback_rows)
    by_source = {}
    for _, _, src in combined:
        by_source[src] = by_source.get(src, 0) + 1
    X = [r[0] for r in combined]
    y = [r[1] for r in combined]
    return X, y, by_source, len(feedback_rows)


def _format_confusion_matrix(cm):
    tn, fp, fn, tp = int(cm[0][0]), int(cm[0][1]), int(cm[1][0]), int(cm[1][1])
    return {"tn": tn, "fp": fp, "fn": fn, "tp": tp}


def _pick_optimal_threshold(y_true, proba):
    from sklearn.metrics import roc_curve
    fpr, tpr, thr = roc_curve(y_true, proba)
    j = tpr - fpr
    idx = int(j.argmax())
    return float(thr[idx]), float(j[idx])


def _baseline_record(metrics):
    run_id = metrics.get("run_id") or hashlib.md5(
        (str(time.time()) + json.dumps(metrics, default=str, sort_keys=True)).encode()
    ).hexdigest()
    return {
        "run_id": run_id,
        "trained_at": datetime.now(UTC).isoformat(),
        "metrics": metrics,
    }


def train_and_evaluate(
    data_dir: str = "data/training",
    db_path: str = "data/phishguard.db",
    model_out: str = "data/model.pkl",
    baselines_dir: str = "ml/baselines",
    test_size: float = 0.2,
    cv_folds: int = 5,
    random_state: int = 42,
    mlflow_tracking_uri: str | None = None,
):
    try:
        from sklearn.calibration import CalibratedClassifierCV
        from sklearn.ensemble import ExtraTreesClassifier
        from sklearn.metrics import (
            confusion_matrix,
            f1_score,
            precision_score,
            recall_score,
            roc_auc_score,
        )
        from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
    except ImportError as exc:
        logger.warning("sklearn_missing", error=str(exc))
        return {"status": "error", "error": "sklearn import failed: " + str(exc)}

    X, y, by_source, n_feedback = _assemble_corpus(data_dir, db_path)
    n_samples = len(X)
    n_pos = sum(y)
    n_neg = n_samples - n_pos

    if n_samples < 30:
        logger.warning("retrain_skipped_insufficient", n_samples=n_samples)
        return {"status": "skipped", "reason": "insufficient_data", "n_samples": n_samples}
    if n_pos < 5 or n_neg < 5:
        logger.warning("retrain_skipped_imbalance", n_pos=n_pos, n_neg=n_neg)
        return {"status": "skipped", "reason": "class_imbalance", "n_pos": n_pos, "n_neg": n_neg}

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=random_state
    )

    base = ExtraTreesClassifier(
        n_estimators=300,
        random_state=random_state,
        n_jobs=-1,
        class_weight='balanced',  # handles phishing/clean imbalance automatically
    )

    inner_cv = min(3, max(2, int(n_pos / 3), int(n_neg / 3)))
    calibrated = CalibratedClassifierCV(base, method="isotonic", cv=inner_cv)

    folds = min(cv_folds, n_pos, n_neg)
    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=random_state)
    cv_f1 = cross_val_score(calibrated, X_train, y_train, cv=skf, scoring="f1")
    cv_auc = cross_val_score(calibrated, X_train, y_train, cv=skf, scoring="roc_auc")

    calibrated.fit(X_train, y_train)
    proba_test = calibrated.predict_proba(X_test)[:, 1]
    pred_test = calibrated.predict(X_test)

    threshold, youden_j = _pick_optimal_threshold(y_test, proba_test)
    pred_optimal = [1 if p >= threshold else 0 for p in proba_test]


    metrics = {
        "n_samples_total": n_samples,
        "n_feedback_corrections": n_feedback,
        "n_pos": n_pos,
        "n_neg": n_neg,
        "n_train": len(X_train),
        "n_test": len(X_test),
        "by_source": by_source,
        "cv_folds": folds,
        "cv_f1_mean": float(cv_f1.mean()),
        "cv_f1_std": float(cv_f1.std()),
        "cv_roc_auc_mean": float(cv_auc.mean()),
        "cv_roc_auc_std": float(cv_auc.std()),
        "test_precision_at_default": float(precision_score(y_test, pred_test, zero_division=0)),
        "test_recall_at_default": float(recall_score(y_test, pred_test, zero_division=0)),
        "test_f1_at_default": float(f1_score(y_test, pred_test, zero_division=0)),
        "test_roc_auc": float(roc_auc_score(y_test, proba_test)),
        "test_confusion_at_default": _format_confusion_matrix(confusion_matrix(y_test, pred_test)),
        "optimal_threshold": threshold,
        "optimal_threshold_youden_j": youden_j,
        "test_precision_at_optimal": float(precision_score(y_test, pred_optimal, zero_division=0)),
        "test_recall_at_optimal": float(recall_score(y_test, pred_optimal, zero_division=0)),
        "test_f1_at_optimal": float(f1_score(y_test, pred_optimal, zero_division=0)),
        "test_confusion_at_optimal": _format_confusion_matrix(
            confusion_matrix(y_test, pred_optimal)
        ),
        "feature_keys": list(FEATURE_KEYS),
        "model_type": "CalibratedClassifierCV(ExtraTreesClassifier, isotonic)",
    }


    importances = None
    try:
        per_fold = []
        for cal_clf in calibrated.calibrated_classifiers_:
            est = getattr(cal_clf, "estimator", None) or getattr(cal_clf, "base_estimator", None)
            if est is not None and hasattr(est, "feature_importances_"):
                per_fold.append(list(est.feature_importances_))
        if per_fold:
            avg = [float(sum(col) / len(per_fold)) for col in zip(*per_fold)]
            importances = dict(zip(FEATURE_KEYS, avg))
            metrics["feature_importances"] = importances
    except Exception as exc:
        logger.warning("feature_importance_err", error=str(exc))

    os.makedirs(os.path.dirname(model_out) or ".", exist_ok=True)
    with open(model_out, "wb") as fh:
        pickle.dump(calibrated, fh)

    os.makedirs(baselines_dir, exist_ok=True)
    baseline = _baseline_record(metrics)
    baseline_path = os.path.join(baselines_dir, "run-" + baseline["run_id"] + ".json")
    with open(baseline_path, "w") as fh:
        json.dump(baseline, fh, indent=2, default=str)

    if mlflow_tracking_uri:
        _maybe_log_to_mlflow(mlflow_tracking_uri, metrics, model_out)

    logger.info(
        "retrain_complete",
        n_samples=n_samples,
        cv_f1_mean=metrics["cv_f1_mean"],
        test_roc_auc=metrics["test_roc_auc"],
        baseline_path=baseline_path,
    )
    return {
        "status": "ok",
        "model_path": model_out,
        "baseline_path": baseline_path,
        "metrics": metrics,
    }


def _maybe_log_to_mlflow(uri, metrics, model_path):
    try:
        import mlflow
        import mlflow.sklearn
        mlflow.set_tracking_uri(uri)
        mlflow.set_experiment("phishguard-layer5")
        with mlflow.start_run():
            scalar = {
                k: v for k, v in metrics.items()
                if isinstance(v, (int, float)) and not isinstance(v, bool)
            }
            mlflow.log_metrics(scalar)
            mlflow.log_params({
                "n_samples_total": metrics["n_samples_total"],
                "model_type": metrics["model_type"],
                "cv_folds": metrics["cv_folds"],
            })
            mlflow.log_artifact(model_path, artifact_path="model")
            cm = metrics.get("test_confusion_at_default")
            if cm:
                mlflow.log_dict(cm, "confusion_matrix_default.json")
            cm_opt = metrics.get("test_confusion_at_optimal")
            if cm_opt:
                mlflow.log_dict(cm_opt, "confusion_matrix_optimal.json")
            fi = metrics.get("feature_importances")
            if fi:
                mlflow.log_dict(fi, "feature_importances.json")
    except Exception as exc:
        logger.warning("mlflow_log_err", error=str(exc))
