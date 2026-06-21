"""Layer 7 - Gmail watch setup helper."""
from __future__ import annotations

import structlog

from .gmail_client import _build_service

logger = structlog.get_logger()
GMAIL_PUSH_SA = "gmail-api-push@system.gserviceaccount.com"

def _gcp_clients(settings):
    try:
        from google.cloud import pubsub_v1  # type: ignore
        from google.oauth2 import service_account  # type: ignore
        creds = service_account.Credentials.from_service_account_file(
            settings.google_service_account_json,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        return pubsub_v1.PublisherClient(credentials=creds), pubsub_v1.SubscriberClient(credentials=creds)
    except Exception as exc:
        logger.warning("gcp_clients_err", error=str(exc))
        return None, None

def ensure_topic(settings) -> str | None:
    pub, _ = _gcp_clients(settings)
    if not pub:
        return None
    project = settings.google_cloud_project
    t_id = settings.gmail_queue_topic
    t_path = pub.topic_path(project, t_id)
    try:
        pub.get_topic(request={"topic": t_path})
        logger.info("topic_exists", path=t_path)
    except Exception:
        pub.create_topic(request={"name": t_path})
        logger.info("topic_created", path=t_path)
    try:
        policy = pub.get_iam_policy(request={"resource": t_path})
        sa_member = f"serviceAccount:{GMAIL_PUSH_SA}"
        for b in policy.bindings:
            if b.role == "roles/pubsub.publisher" and sa_member in b.members:
                return t_path
        policy.bindings.add(role="roles/pubsub.publisher", members=[sa_member])
        pub.set_iam_policy(request={"resource": t_path, "policy": policy})
        logger.info("iam_binding_set", topic=t_path)
    except Exception as exc:
        logger.warning("iam_err", error=str(exc))
    return t_path

def ensure_subscription(settings, t_path: str) -> str | None:
    _, sub_client = _gcp_clients(settings)
    if not sub_client:
        return None
    project = settings.google_cloud_project
    sub_id = settings.gmail_queue_subscription
    sub_path = sub_client.subscription_path(project, sub_id)
    try:
        sub_client.get_subscription(request={"subscription": sub_path})
        logger.info("sub_exists", path=sub_path)
        return sub_path
    except Exception:
        pass
    push_ep = getattr(settings, "gmail_push_endpoint", "")
    body: dict = {"name": sub_path, "topic": t_path}
    if push_ep:
        body["push_config"] = {"push_endpoint": push_ep}
    sub_client.create_subscription(request=body)
    logger.info("sub_created", path=sub_path)
    return sub_path

def register_watch(settings, t_path: str) -> dict | None:
    svc = _build_service(settings)
    if not svc:
        return None
    try:
        resp = svc.users().watch(
            userId="me",
            body={"topicName": t_path, "labelIds": ["INBOX"], "labelFilterAction": "include"},
        ).execute()
        logger.info("gmail_watch_registered", expiry=resp.get("expiration"))
        return resp
    except Exception as exc:
        logger.warning("gmail_watch_err", error=str(exc))
        return None

def setup_gmail_watch(settings) -> dict:
    """Full idempotent setup: notification channel + watch registration."""
    t_path = ensure_topic(settings)
    if not t_path:
        return {"ok": False, "error": "topic_failed"}
    sub_path = ensure_subscription(settings, t_path)
    watch = register_watch(settings, t_path)
    return {
        "ok": bool(watch),
        "topic": t_path,
        "subscription": sub_path,
        "watch_expiry": watch.get("expiration") if watch else None,
        "history_id": watch.get("historyId") if watch else None,
    }

def renew_gmail_watch(settings) -> dict:
    """Renew an expiring Gmail watch (call daily)."""
    t_path = f"projects/{settings.google_cloud_project}/topics/{settings.gmail_queue_topic}"
    watch = register_watch(settings, t_path)
    return {"ok": bool(watch), "watch_expiry": watch.get("expiration") if watch else None}

def stop_gmail_watch(settings) -> bool:
    svc = _build_service(settings)
    if not svc:
        return False
    try:
        svc.users().stop(userId="me").execute()
        logger.info("gmail_watch_stopped")
        return True
    except Exception as exc:
        logger.warning("gmail_stop_err", error=str(exc))
        return False
