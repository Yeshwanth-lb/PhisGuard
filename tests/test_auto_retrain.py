"""Gated automated retraining — champion/challenger promotion logic."""
import asyncio
import json
import os
import tempfile
from unittest.mock import patch

from app.layer5_ml import auto_retrain


class _Settings:
    def __init__(self, model_out):
        self.ml_model_path = model_out
        self.ml_local_data_dir = "data/training"
        self.ml_promote_auc_tolerance = 0.01
        self.mlflow_tracking_uri = None
        self.slack_webhook_url = ""


def _fake_train(model_out, auc):
    """Simulate train_and_evaluate: write a dummy model file + return metrics."""
    def _inner(*args, **kwargs):
        with open(kwargs["model_out"], "wb") as fh:
            fh.write(b"challenger-model-bytes")
        return {"status": "ok", "model_path": kwargs["model_out"],
                "metrics": {"test_roc_auc": auc, "cv_f1_mean": 0.9,
                            "n_samples_total": 100, "n_feedback_corrections": 10}}
    return _inner


def _run(settings):
    return asyncio.run(auto_retrain.run_gated_retrain(settings))


def test_first_run_promotes_unconditionally():
    with tempfile.TemporaryDirectory() as d:
        model_out = os.path.join(d, "model.pkl")
        s = _Settings(model_out)
        with patch("app.layer5_ml.training_pipeline.train_and_evaluate", _fake_train(model_out, 0.80)):
            r = _run(s)
        assert r["status"] == "promoted"
        assert os.path.exists(model_out)                       # model written
        assert os.path.exists(auto_retrain._champion_path(model_out))  # champion recorded
        champ = json.load(open(auto_retrain._champion_path(model_out)))
        assert champ["test_roc_auc"] == 0.80


def test_better_challenger_promotes():
    with tempfile.TemporaryDirectory() as d:
        model_out = os.path.join(d, "model.pkl")
        s = _Settings(model_out)
        with patch("app.layer5_ml.training_pipeline.train_and_evaluate", _fake_train(model_out, 0.80)):
            _run(s)
        with patch("app.layer5_ml.training_pipeline.train_and_evaluate", _fake_train(model_out, 0.88)):
            r = _run(s)
        assert r["status"] == "promoted"
        assert json.load(open(auto_retrain._champion_path(model_out)))["test_roc_auc"] == 0.88


def test_worse_challenger_rejected_keeps_champion():
    with tempfile.TemporaryDirectory() as d:
        model_out = os.path.join(d, "model.pkl")
        s = _Settings(model_out)
        with patch("app.layer5_ml.training_pipeline.train_and_evaluate", _fake_train(model_out, 0.90)):
            _run(s)
        # a clearly worse challenger (0.70 vs 0.90) must be rejected
        with patch("app.layer5_ml.training_pipeline.train_and_evaluate", _fake_train(model_out, 0.70)):
            r = _run(s)
        assert r["status"] == "rejected"
        # champion metric unchanged, no leftover challenger file
        assert json.load(open(auto_retrain._champion_path(model_out)))["test_roc_auc"] == 0.90
        assert not os.path.exists(model_out + ".challenger")


def test_tiny_regression_within_tolerance_promotes():
    with tempfile.TemporaryDirectory() as d:
        model_out = os.path.join(d, "model.pkl")
        s = _Settings(model_out)
        with patch("app.layer5_ml.training_pipeline.train_and_evaluate", _fake_train(model_out, 0.90)):
            _run(s)
        # 0.895 is within the 0.01 tolerance of 0.90 → still promoted (noise, not regression)
        with patch("app.layer5_ml.training_pipeline.train_and_evaluate", _fake_train(model_out, 0.895)):
            r = _run(s)
        assert r["status"] == "promoted"


def test_insufficient_data_skips_no_overwrite():
    with tempfile.TemporaryDirectory() as d:
        model_out = os.path.join(d, "model.pkl")
        with open(model_out, "wb") as fh:
            fh.write(b"existing-good-model")
        s = _Settings(model_out)

        def _skip(*a, **k):
            return {"status": "skipped", "reason": "insufficient_data"}
        with patch("app.layer5_ml.training_pipeline.train_and_evaluate", _skip):
            r = _run(s)
        assert r["status"] == "skipped"
        # existing model untouched
        assert open(model_out, "rb").read() == b"existing-good-model"
