"""Phase 5 gate tests: ML pipeline layer."""
import json
import os

import pytest

from app.layer5_ml import bootstrap, classifier, training_pipeline
from app.layer5_ml.feature_extractor import FEATURE_KEYS, extract_features, label_from_verdict


class FakeSettings:
    ml_s3_bucket = None
    ml_local_data_dir = None
    ml_verdict_log_dir = None
    mlflow_tracking_uri = None


PHISH_DOC = {
    "verdict": "phishing",
    "confidence": 0.92,
    "blocked_at": "layer2",
    "l1": {"hits": ["1.2.3.4"]},
    "l2": {
        "confidence": 0.92,
        "engine_scores": {"structural": 0.8, "nlp": 0.9, "behavioral": 0.7},
    },
    "parsed": {
        "subject": "Urgent: verify your account",
        "from_header": "attacker@evil.com",
        "urls": ["http://evil.com/steal"],
        "headers": {},
        "attachment_hashes": [],
    },
}


def test_extract_features_shape():
    feats = extract_features(PHISH_DOC)
    assert isinstance(feats, dict)
    assert len(feats) > 10
    assert feats["url_count"] == 1
    assert feats["urgent_word_count"] >= 1


def test_label_phishing():
    assert label_from_verdict(PHISH_DOC) == 1
    clean = {**PHISH_DOC, "verdict": "clean"}
    assert label_from_verdict(clean) == 0


@pytest.mark.asyncio
async def test_save_training_local(tmp_path):
    from app.layer5_ml.storage_exporter import save_training_record
    cfg = FakeSettings()
    cfg.ml_verdict_log_dir = str(tmp_path)
    ok = await save_training_record(PHISH_DOC, cfg)
    assert ok is True
    files = list(tmp_path.glob("*.jsonl"))
    assert len(files) == 1
    line = json.loads(files[0].read_text().strip())
    assert line["label"] == 1
    assert "features" in line


@pytest.mark.asyncio
async def test_save_training_does_not_pollute_training_dir(tmp_path):
    """Live verdict logs must not land in the training corpus.

    Regression for the ML feedback-loop bug where every model prediction was
    being saved as a 'training record', causing the model to drift toward
    always predicting 'clean'.
    """
    from app.layer5_ml.storage_exporter import save_training_record
    train_dir = tmp_path / "training"
    verdict_dir = tmp_path / "verdicts"
    train_dir.mkdir()
    cfg = FakeSettings()
    cfg.ml_local_data_dir = str(train_dir)
    cfg.ml_verdict_log_dir = str(verdict_dir)
    ok = await save_training_record(PHISH_DOC, cfg)
    assert ok is True
    assert list(train_dir.glob("*.jsonl")) == [], "live verdict leaked into training dir"
    assert len(list(verdict_dir.glob("*.jsonl"))) == 1


def test_mlflow_no_uri():
    from app.layer5_ml.mlflow_tracker import log_verdict_to_mlflow
    result = log_verdict_to_mlflow(PHISH_DOC, FakeSettings())
    assert result is False


def test_retrain_insufficient_data(tmp_path):
    from app.layer5_ml.retrain import retrain
    result = retrain(
        data_dir=str(tmp_path),
        model_out=str(tmp_path / "model.pkl"),
        db_path=str(tmp_path / "none.db"),
        baselines_dir=str(tmp_path / "bl"),
    )
    assert result["status"] == "skipped"


def test_bootstrap_generator_shapes(tmp_path):
    out_dir = tmp_path / "training"
    path = bootstrap.generate_bootstrap_data(
        out_dir=str(out_dir),
        n_phish=120,
        n_clean=120,
        overwrite=True,
        seed=7,
    )
    assert os.path.exists(path)
    rows = [json.loads(line) for line in open(path)]
    assert len(rows) == 240
    labels_present = set(r["label"] for r in rows)
    assert 0 in labels_present and 1 in labels_present
    sample = rows[0]
    assert set(sample["features"].keys()) == set(FEATURE_KEYS)


def test_train_and_evaluate_full_pipeline(tmp_path):
    data_dir = tmp_path / "training"
    bootstrap.generate_bootstrap_data(
        out_dir=str(data_dir),
        n_phish=150,
        n_clean=150,
        overwrite=True,
        seed=11,
    )
    model_out = tmp_path / "model.pkl"
    baselines_dir = tmp_path / "baselines"
    db_path = tmp_path / "missing.db"

    result = training_pipeline.train_and_evaluate(
        data_dir=str(data_dir),
        db_path=str(db_path),
        model_out=str(model_out),
        baselines_dir=str(baselines_dir),
        cv_folds=3,
        random_state=11,
    )
    assert result["status"] == "ok"
    metrics = result["metrics"]
    assert metrics["n_samples_total"] >= 280
    assert metrics["cv_f1_mean"] > 0.7
    assert metrics["test_roc_auc"] > 0.7
    assert "feature_importances" in metrics
    importances = metrics["feature_importances"]
    nontrivial = [k for k, v in importances.items() if v > 0.01]
    assert len(nontrivial) >= 3
    assert os.path.exists(str(model_out))
    baseline_files = list(baselines_dir.glob("run-*.json"))
    assert len(baseline_files) == 1


def test_predict_with_trained_model(tmp_path):
    data_dir = tmp_path / "training"
    bootstrap.generate_bootstrap_data(
        out_dir=str(data_dir),
        n_phish=120,
        n_clean=120,
        overwrite=True,
        seed=13,
    )
    model_out = tmp_path / "model.pkl"
    training_pipeline.train_and_evaluate(
        data_dir=str(data_dir),
        db_path=str(tmp_path / "none.db"),
        model_out=str(model_out),
        baselines_dir=str(tmp_path / "bl"),
        cv_folds=3,
        random_state=13,
    )

    phish_doc = {
        "parsed": {
            "subject": "URGENT verify your account immediately",
            "urls": ["http://1.2.3.4/login"],
            "headers": {"received-spf": "fail", "dkim-signature": "fail"},
            "attachment_hashes": ["a"],
        },
        "l1": {"hits": [{"x": 1}, {"y": 2}]},
        "l2": {"engine_scores": {"structural": 0.85, "nlp": 0.9, "behavioral": 0.8}, "confidence": 0.85},
    }
    clean_doc = {
        "parsed": {"subject": "Lunch tomorrow", "urls": [], "headers": {}, "attachment_hashes": []},
        "l1": {"hits": []},
        "l2": {"engine_scores": {"structural": 0.05, "nlp": 0.05, "behavioral": 0.05}, "confidence": 0.6},
    }
    classifier._MODEL_CACHE = None
    classifier._MODEL_PATH_CACHE = ""
    p = classifier.predict(phish_doc, model_path=str(model_out))
    c = classifier.predict(clean_doc, model_path=str(model_out))
    assert p["ml_available"]
    assert c["ml_available"]
    assert p["ml_score"] > c["ml_score"]
