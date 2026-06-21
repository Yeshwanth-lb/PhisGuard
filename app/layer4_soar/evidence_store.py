"""Evidence store — saves raw malicious emails to MinIO for SOC investigation.

Every email that gets a phishing or suspicious verdict has its raw .eml bytes
stored in MinIO under a structured path:

  phishguard-evidence/
  └── 2026/06/17/
      └── <email_id>/
          ├── email.eml          ← original raw email bytes
          └── report.json        ← full pipeline verdict document

SOC team access:
  - MinIO web UI:  http://localhost:9001  (user: phishguard / changeme123)
  - Download API:  GET /api/evidence/<email_id>/download
  - Report API:    GET /api/evidence/<email_id>/report

Falls back to local filesystem (data/evidence/) when MinIO is unreachable.
"""
import json
import os
from datetime import UTC, datetime

import structlog

logger = structlog.get_logger()

_LOCAL_EVIDENCE_DIR = "data/evidence"


def _local_path(email_id: str, filename: str) -> str:
    today = datetime.now(UTC).strftime("%Y/%m/%d")
    return os.path.join(_LOCAL_EVIDENCE_DIR, today, email_id, filename)


def _save_local(email_id: str, raw_eml: bytes, verdict_doc: dict) -> dict:
    """Fallback: save to local filesystem."""
    try:
        eml_path = _local_path(email_id, "email.eml")
        rep_path = _local_path(email_id, "report.json")
        os.makedirs(os.path.dirname(eml_path), exist_ok=True)
        with open(eml_path, "wb") as f:
            f.write(raw_eml)
        with open(rep_path, "w") as f:
            json.dump(_safe_report(verdict_doc), f, indent=2, default=str)
        logger.info("evidence_saved_local", email_id=email_id, path=eml_path)
        return {"storage": "local", "path": eml_path, "email_id": email_id}
    except Exception as exc:
        logger.warning("evidence_local_err", email_id=email_id, error=str(exc))
        return {"storage": "failed", "error": str(exc)}


def _safe_report(verdict_doc: dict) -> dict:
    """Strip raw email body from the report — store only metadata."""
    doc = dict(verdict_doc)
    parsed = dict(doc.get("parsed") or {})
    parsed.pop("body_text", None)
    parsed.pop("body_html", None)
    doc["parsed"] = parsed
    return doc


async def store_evidence(
    email_id: str,
    raw_eml: bytes,
    verdict_doc: dict,
    settings,
) -> dict:
    """Store raw .eml + verdict report in MinIO. Falls back to local disk."""
    if not raw_eml:
        return {"storage": "skipped", "reason": "no_raw_bytes"}

    # Only store phishing and suspicious emails
    verdict = (verdict_doc.get("verdict") or "").lower()
    if verdict not in ("phishing", "suspicious"):
        return {"storage": "skipped", "reason": "clean_verdict"}

    today = datetime.now(UTC).strftime("%Y/%m/%d")
    eml_key   = f"{today}/{email_id}/email.eml"
    rep_key   = f"{today}/{email_id}/report.json"
    report_bytes = json.dumps(_safe_report(verdict_doc), indent=2, default=str).encode()

    endpoint   = getattr(settings, "minio_endpoint",   "minio:9000")
    access_key = getattr(settings, "minio_access_key", "phishguard")
    secret_key = getattr(settings, "minio_secret_key", "changeme123")
    bucket     = getattr(settings, "minio_bucket",     "phishguard-evidence")
    secure     = getattr(settings, "minio_secure",     False)

    try:
        from minio import Minio  # type: ignore
        from minio.error import S3Error  # type: ignore

        client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)

        # Create bucket if it doesn't exist
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
            logger.info("minio_bucket_created", bucket=bucket)

        # Upload .eml
        import io
        client.put_object(
            bucket, eml_key,
            data=io.BytesIO(raw_eml),
            length=len(raw_eml),
            content_type="message/rfc822",
            metadata={
                "x-phishguard-verdict": verdict,
                "x-phishguard-confidence": str(verdict_doc.get("confidence", 0)),
                "x-phishguard-email-id": email_id,
            },
        )

        # Upload report JSON
        client.put_object(
            bucket, rep_key,
            data=io.BytesIO(report_bytes),
            length=len(report_bytes),
            content_type="application/json",
        )

        minio_url = f"http://{endpoint}/{bucket}/{eml_key}"
        logger.info(
            "evidence_stored_minio",
            email_id=email_id,
            verdict=verdict,
            key=eml_key,
        )
        return {
            "storage": "minio",
            "bucket": bucket,
            "eml_key": eml_key,
            "report_key": rep_key,
            "url": minio_url,
            "email_id": email_id,
        }

    except ImportError:
        logger.warning("minio_sdk_missing", note="pip install minio")
        return _save_local(email_id, raw_eml, verdict_doc)
    except Exception as exc:
        logger.warning("minio_upload_failed", email_id=email_id, error=str(exc))
        return _save_local(email_id, raw_eml, verdict_doc)


def get_evidence_local(email_id: str) -> tuple[bytes | None, str]:
    """Retrieve a stored .eml from local fallback. Returns (bytes, filename)."""
    import glob
    pattern = os.path.join(_LOCAL_EVIDENCE_DIR, "**", email_id, "email.eml")
    matches = glob.glob(pattern, recursive=True)
    if matches:
        with open(matches[0], "rb") as f:
            return f.read(), "email.eml"
    return None, ""
