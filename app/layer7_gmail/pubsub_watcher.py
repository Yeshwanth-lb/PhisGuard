"""Layer 7 - Gmail notification watcher."""
from __future__ import annotations

import asyncio
import base64
import json
import threading
from collections.abc import Callable

import structlog

from .gmail_client import _build_service, apply_label, fetch_raw_message

logger = structlog.get_logger()

def decode_notification(body: dict) -> str | None:
    try:
        data_b64 = body["message"]["data"]
        decoded = json.loads(base64.b64decode(data_b64 + "==").decode())
        return str(decoded.get("historyId", ""))
    except Exception as exc:
        logger.warning("decode_err", error=str(exc))
        return None

def fetch_new_message_ids(settings, start_history_id: str) -> list:
    svc = _build_service(settings)
    if not svc:
        return []
    try:
        resp = (
            svc.users().history().list(
                userId="me", startHistoryId=start_history_id, historyTypes=["messageAdded"]
            ).execute()
        )
        ids = []
        for rec in resp.get("history", []):
            for added in rec.get("messagesAdded", []):
                mid = added.get("message", {}).get("id")
                if mid:
                    ids.append(mid)
        return ids
    except Exception as exc:
        logger.warning("history_fetch_err", error=str(exc))
        return []

async def handle_push_notification(push_body: dict, analyze_fn: Callable, settings) -> dict:
    history_id = decode_notification(push_body)
    if not history_id:
        return {"status": "ignored", "reason": "no_history_id"}
    msg_ids = fetch_new_message_ids(settings, history_id)
    if not msg_ids:
        return {"status": "ok", "processed": 0}
    results = []
    for msg_id in msg_ids:
        raw = fetch_raw_message(settings, msg_id)
        if not raw:
            continue
        try:
            result = await analyze_fn(raw, settings)
            verdict = result.get("verdict", "unknown")
            # Feed through the SAME bombing pipeline as the SMTP gateway (dormant
            # unless INBOX_INGESTION_ENABLED). No-op + no Gmail calls when disabled.
            try:
                from app.security.bombing_pipeline import ingest_gmail_message
                ingest_gmail_message(result.get("parsed") or {}, raw, settings,
                                     scan_id=result.get("email_id", msg_id))
            except Exception as _be:
                logger.warning("gmail_bombing_ingest_err", msg_id=msg_id, error=str(_be))
            label = settings.gmail_quarantine_label if verdict == "phishing" else settings.gmail_scanned_label
            apply_label(settings, msg_id, label)
            results.append({"msg_id": msg_id, "verdict": verdict})
            logger.info("push_processed", msg_id=msg_id, verdict=verdict)
        except Exception as exc:
            logger.warning("push_analyze_err", msg_id=msg_id, error=str(exc))
    return {"status": "ok", "processed": len(results), "results": results}

class PullSubscriberThread(threading.Thread):
    def __init__(self, analyze_fn: Callable, settings):
        super().__init__(daemon=True, name="cloud-pull")
        self.analyze_fn = analyze_fn
        self.settings = settings
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        try:
            from google.cloud import pubsub_v1  # type: ignore
        except ImportError:
            logger.warning("cloud_queue_missing")
            return
        project = getattr(self.settings, "google_cloud_project", "")
        sub_name = getattr(self.settings, "gmail_queue_subscription", "")
        if not project or not sub_name:
            logger.warning("cloud_pull_not_configured")
            return
        sub_path = f"projects/{project}/subscriptions/{sub_name}"
        logger.info("cloud_pull_starting", sub=sub_path)
        subscriber = pubsub_v1.SubscriberClient()

        def _cb(message):
            try:
                raw_data = message.data.decode() if isinstance(message.data, bytes) else message.data
                loop = asyncio.new_event_loop()
                loop.run_until_complete(
                    handle_push_notification({"message": {"data": raw_data}}, self.analyze_fn, self.settings)
                )
                loop.close()
                message.ack()
            except Exception as exc:
                logger.warning("cloud_cb_err", error=str(exc))
                message.nack()

        future = subscriber.subscribe(sub_path, callback=_cb)
        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(timeout=5)
        finally:
            future.cancel()
            subscriber.close()
            logger.info("cloud_pull_stopped")

_pull_thread: PullSubscriberThread | None = None

def start_pull_subscriber(analyze_fn: Callable, settings) -> bool:
    global _pull_thread
    if _pull_thread and _pull_thread.is_alive():
        return True
    _pull_thread = PullSubscriberThread(analyze_fn, settings)
    _pull_thread.start()
    return True

def stop_pull_subscriber():
    global _pull_thread
    if _pull_thread:
        _pull_thread.stop()
        _pull_thread = None
