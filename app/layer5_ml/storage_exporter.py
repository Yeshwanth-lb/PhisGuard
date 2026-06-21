"""Layer 5 - Storage exporter: saves verdict training records to S3 or local disk."""
import json
import os
from datetime import UTC, datetime

import structlog

from .feature_extractor import extract_features, label_from_verdict

logger = structlog.get_logger()


def _build_record(verdict_doc: dict) -> dict:
    return {
        "ts": datetime.now(UTC).isoformat(),
        "verdict": verdict_doc.get("verdict"),
        "confidence": verdict_doc.get("confidence", 0.0),
        "features": extract_features(verdict_doc),
        "label": label_from_verdict(verdict_doc),
    }


async def save_training_record(verdict_doc: dict, settings) -> bool:
    rec = _build_record(verdict_doc)
    bucket = getattr(settings, "ml_s3_bucket", None)
    if bucket:
        return await _save_s3(rec, bucket, settings)
    return _save_local(rec, settings)


def _save_local(rec: dict, settings) -> bool:
    # Live verdicts go to ml_verdict_log_dir, NOT ml_local_data_dir.
    # The training dir must only contain trusted, ground-truth labels.
    # Mixing the model's own predictions back into training causes a
    # feedback loop (every "clean" verdict reinforces "everything is clean").
    outdir = getattr(settings, "ml_verdict_log_dir", "data/verdicts")
    os.makedirs(outdir, exist_ok=True)
    date_str = datetime.now(UTC).strftime("%Y-%m-%d")
    path = os.path.join(outdir, f"verdicts-{date_str}.jsonl")
    try:
        with open(path, "a") as fout:
            fout.write(json.dumps(rec) + chr(10))
        logger.info("training_record_saved", path=path)
        return True
    except Exception as exc:
        logger.warning("local_save_err", error=str(exc))
        return False


async def _save_s3(rec: dict, bucket: str, settings) -> bool:
    try:
        import aioboto3  # type: ignore
        date_str = datetime.now(UTC).strftime("%Y/%m/%d")
        key = f"phishguard/training/{date_str}/{rec['ts']}.json"
        region = getattr(settings, "aws_region", "us-east-1")
        session = aioboto3.Session()
        async with session.client("s3", region_name=region) as s3:
            await s3.put_object(Bucket=bucket, Key=key, Body=json.dumps(rec).encode())
        logger.info("s3_record_saved", bucket=bucket, key=key)
        return True
    except Exception as exc:
        logger.warning("s3_save_err", error=str(exc))
        return _save_local(rec, settings)
