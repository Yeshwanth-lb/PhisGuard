"""Layer 7 - Historical Gmail inbox scanner: batch-scans past messages.

Maintains a SQLite checkpoint table so restarting a scan never re-processes
an already-scanned message. Safe to run multiple times.
"""
import asyncio
import sqlite3
import uuid
from collections.abc import Callable

import structlog

from .gmail_client import apply_label, fetch_raw_message, list_messages

logger = structlog.get_logger()

_CHECKPOINT_DB = "data/gmail_scan_checkpoint.db"


def _checkpoint_conn() -> sqlite3.Connection:
    import os
    os.makedirs("data", exist_ok=True)
    c = sqlite3.connect(_CHECKPOINT_DB, check_same_thread=False)
    c.execute("""CREATE TABLE IF NOT EXISTS scanned_messages (
        user_email  TEXT NOT NULL,
        message_id  TEXT NOT NULL,
        verdict     TEXT,
        scanned_at  REAL NOT NULL,
        PRIMARY KEY (user_email, message_id)
    )""")
    c.commit()
    return c


def _is_already_scanned(conn: sqlite3.Connection, user_email: str, msg_id: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM scanned_messages WHERE user_email=? AND message_id=?",
        (user_email, msg_id),
    ).fetchone()
    return row is not None


def _mark_scanned(conn: sqlite3.Connection, user_email: str, msg_id: str, verdict: str) -> None:
    import time
    conn.execute(
        "INSERT OR REPLACE INTO scanned_messages (user_email, message_id, verdict, scanned_at) VALUES (?,?,?,?)",
        (user_email, msg_id, verdict, time.time()),
    )
    conn.commit()


_DEFAULT_SCAN_QUERY = (
    # Skip emails already processed by PhishGuard
    "-label:PhishGuard-Scanned "
    "-label:PhishGuard-Quarantine "
    # Skip PhishGuard's own alert/notification emails (avoid feedback loop)
    "-subject:[PhishGuard] "
    "-subject:PhishGuard "
    # Only scan inbox (not sent, trash, spam folders)
    "in:inbox"
)


async def scan_inbox(
    analyze_fn: Callable,
    settings,
    query: str = "",
    max_messages: int = 500,
    concurrency: int = 5,
) -> dict:
    """Scan historical inbox messages concurrently. Returns summary counts."""
    from app import storage

    user_email = getattr(settings, "google_admin_impersonate_email", "") or "default"
    checkpoint = _checkpoint_conn()

    # Use safe default query unless caller explicitly overrides
    effective_query = query.strip() if query.strip() else _DEFAULT_SCAN_QUERY
    stubs = list_messages(settings, query=effective_query, max_results=max_messages)
    if not stubs:
        logger.info("scan_no_messages")
        return {"total": 0, "phishing": 0, "suspicious": 0, "clean": 0,
                "scanned": 0, "skipped": 0, "errors": 0}

    sem = asyncio.Semaphore(concurrency)
    counts = {
        "total": len(stubs), "scanned": 0, "skipped": 0,
        "phishing": 0, "suspicious": 0, "clean": 0, "errors": 0,
    }

    async def _process(stub: dict) -> None:
        msg_id = stub.get("id", "")

        # Skip already-scanned messages (checkpoint table prevents re-processing)
        if _is_already_scanned(checkpoint, user_email, msg_id):
            counts["skipped"] += 1
            return

        async with sem:
            raw = fetch_raw_message(settings, msg_id)
            if not raw:
                counts["errors"] += 1
                return
            try:
                result = await analyze_fn(raw, settings)
                counts["scanned"] += 1
                verdict = result.get("verdict", "clean")
                counts[verdict] = counts.get(verdict, 0) + 1

                # Save to database so results show in dashboard
                email_id = str(uuid.uuid4())
                parsed = result.pop("parsed", None) or {}
                result["email_id"] = email_id
                result["ingestion_source"] = "gmail_historical"
                result["gmail_message_id"] = msg_id

                # Feed the SAME bombing pipeline as the SMTP gateway (dormant unless
                # INBOX_INGESTION_ENABLED). NOTE: a historical backfill arrives as one
                # burst, which can look like a bomb — enabling ingestion is intended
                # mainly for the live push path; gated + best-effort here.
                try:
                    from app.security.bombing_pipeline import ingest_gmail_message
                    ingest_gmail_message(parsed, raw, settings, scan_id=email_id)
                except Exception as exc:
                    logger.warning("gmail_bombing_ingest_err", msg_id=msg_id, error=str(exc))
                try:
                    storage.save_scan(email_id, result, parsed)
                except Exception as exc:
                    logger.warning("scan_save_err", msg_id=msg_id, error=str(exc))

                # Mark as scanned so re-runs skip it
                _mark_scanned(checkpoint, user_email, msg_id, verdict)

                # Apply Gmail labels based on verdict
                if verdict == "phishing":
                    apply_label(settings, msg_id, settings.gmail_quarantine_label)
                else:
                    apply_label(settings, msg_id, settings.gmail_scanned_label)

            except Exception as exc:
                logger.warning("scan_err", msg_id=msg_id, error=str(exc))
                counts["errors"] += 1

    await asyncio.gather(*[_process(s) for s in stubs])
    checkpoint.close()
    logger.info("scan_complete", **counts)
    return counts
