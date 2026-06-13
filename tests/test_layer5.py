"""Phase 5 gate tests: ML pipeline layer."""
import os, json, tempfile
import pytest


class FakeSettings:
    ml_s3_bucket = None
    ml_local_data_dir = None
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
    from app.layer5_ml.feature_extractor import extract_features
    feats = extract_features(PHISH_DOC)
    assert isinstance(feats, dict)
    assert len(feats) > 10
    assert feats["url_count"] == 1
    assert feats["urgent_word_count"] >= 1


def test_label_phishing():
    from app.layer5_ml.feature_extractor import label_from_verdict
    assert label_from_verdict(PHISH_DOC) == 1
    clean = {**PHISH_DOC, "verdict": "clean"}
    assert label_from_verdict(clean) == 0


@pytest.mark.asyncio
async def test_save_training_local(tmp_path):
    from app.layer5_ml.storage_exporter import save_training_record
    cfg = FakeSettings()
    cfg.ml_local_data_dir = str(tmp_path)
    ok = await save_training_record(PHISH_DOC, cfg)
    assert ok is True
    files = list(tmp_path.glob("*.jsonl"))
    assert len(files) == 1
    line = json.loads(files[0].read_text().strip())
    assert line["label"] == 1
    assert "features" in line


def test_mlflow_no_uri():
    from app.layer5_ml.mlflow_tracker import log_verdict_to_mlflow
    result = log_verdict_to_mlflow(PHISH_DOC, FakeSettings())
    assert result is False


def test_retrain_insufficient_data(tmp_path):
    from app.layer5_ml.retrain import retrain
    result = retrain(data_dir=str(tmp_path), model_out=str(tmp_path / "model.pkl"))
    assert result["status"] == "skipped"


def test_retrain_with_data(tmp_path):
    from app.layer5_ml.storage_exporter import _build_record
    from app.layer5_ml.retrain import retrain
    jsonl_path = tmp_path / "test.jsonl"
    records = [_build_record(PHISH_DOC) for _ in range(20)]
    clean_doc = {**PHISH_DOC, "verdict": "clean"}
    records += [_build_record(clean_doc) for _ in range(20)]
    jsonl_path.write_text(chr(10).join(json.dumps(r) for r in records))
    result = retrain(data_dir=str(tmp_path), model_out=str(tmp_path / "model.pkl"))
    assert result["status"] == "ok"
    assert (tmp_path / "model.pkl").exists()
