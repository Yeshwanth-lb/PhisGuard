"""Layer 7 - Gmail API client: list, fetch, label and move messages."""
import base64
import structlog
from typing import List, Optional

logger = structlog.get_logger()


def _build_service(settings):
    try:
        from google.oauth2 import service_account  # type: ignore
        from googleapiclient.discovery import build  # type: ignore
        scopes = [
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/gmail.readonly",
        ]
        creds = service_account.Credentials.from_service_account_file(
            settings.google_service_account_json, scopes=scopes
        )
        delegated = creds.with_subject(settings.google_admin_impersonate_email)
        return build("gmail", "v1", credentials=delegated)
    except Exception as exc:
        logger.warning("gmail_build_failed", error=str(exc))
        return None


def list_messages(settings, query: str = "", max_results: int = 100) -> List[dict]:
    svc = _build_service(settings)
    if not svc:
        return []
    try:
        resp = svc.users().messages().list(
            userId="me", q=query, maxResults=max_results
        ).execute()
        return resp.get("messages", [])
    except Exception as exc:
        logger.warning("gmail_list_err", error=str(exc))
        return []


def fetch_raw_message(settings, msg_id: str) -> Optional[bytes]:
    svc = _build_service(settings)
    if not svc:
        return None
    try:
        resp = svc.users().messages().get(
            userId="me", id=msg_id, format="raw"
        ).execute()
        raw_b64 = resp.get("raw", "")
        return base64.urlsafe_b64decode(raw_b64 + "==")
    except Exception as exc:
        logger.warning("gmail_fetch_err", msg_id=msg_id, error=str(exc))
        return None


def _find_label_id(all_labels: list, name: str) -> Optional[str]:
    for entry in all_labels:
        if entry.get("name") == name:
            return entry.get("id")
    return None


def apply_label(settings, msg_id: str, label_name: str) -> bool:
    svc = _build_service(settings)
    if not svc:
        return False
    try:
        all_labels = svc.users().labels().list(userId="me").execute().get("labels", [])
        label_id = _find_label_id(all_labels, label_name)
        if not label_id:
            created = svc.users().labels().create(
                userId="me", body={"name": label_name}
            ).execute()
            label_id = created.get("id")
        svc.users().messages().modify(
            userId="me", id=msg_id,
            body={"addLabelIds": [label_id]}
        ).execute()
        logger.info("label_applied", msg_id=msg_id, label=label_name)
        return True
    except Exception as exc:
        logger.warning("gmail_label_err", error=str(exc))
        return False
