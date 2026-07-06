"""Layer 7 - Gmail API client: list, fetch, label and move messages."""
import base64
import os

import structlog

logger = structlog.get_logger()

_SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.readonly",
]


def _build_service(settings, user_email: str | None = None):
    """Build an authenticated Gmail API client (service-account or OAuth user).

    user_email: impersonate this specific mailbox via domain-wide delegation
    instead of the single settings.google_admin_impersonate_email — this is
    what lets one service account fan out across every mailbox in a Workspace
    domain rather than being pinned to one fixed account. Falls back to the
    single-mailbox behavior (unchanged) when omitted, so existing callers
    that don't pass it keep working exactly as before.
    """
    try:
        from googleapiclient.discovery import build
    except ImportError as exc:
        logger.warning("gmail_lib_missing", error=str(exc))
        return None

    sa_path = getattr(settings, "google_service_account_json", "") or ""
    impersonate = user_email or getattr(settings, "google_admin_impersonate_email", "") or ""
    oauth_path = getattr(settings, "gmail_oauth_token_file", "") or ""

    if sa_path and os.path.exists(sa_path) and impersonate:
        try:
            import importlib
            sa_mod = importlib.import_module("google.oauth2.service_account")
            sa_creds = sa_mod.Credentials.from_service_account_file(sa_path, scopes=_SCOPES)
            delegated = sa_creds.with_subject(impersonate)
            logger.info("gmail_auth_service_account", impersonate=impersonate)
            return build("gmail", "v1", credentials=delegated)
        except Exception as exc:
            logger.warning("gmail_sa_auth_failed", error=str(exc))

    if oauth_path and os.path.exists(oauth_path):
        try:
            import importlib
            req_mod = importlib.import_module("google.auth.transport.requests")
            uc_mod = importlib.import_module("google.oauth2.credentials")
            user_creds = uc_mod.Credentials.from_authorized_user_file(oauth_path, scopes=_SCOPES)
            if not user_creds.valid:
                if user_creds.expired and user_creds.refresh_token:
                    user_creds.refresh(req_mod.Request())
                    with open(oauth_path, "w") as fh:
                        fh.write(user_creds.to_json())
                    logger.info("gmail_oauth_token_refreshed", path=oauth_path)
                else:
                    logger.warning("gmail_oauth_token_invalid")
                    return None
            logger.info("gmail_auth_oauth_user")
            return build("gmail", "v1", credentials=user_creds)
        except Exception as exc:
            logger.warning("gmail_oauth_auth_failed", error=str(exc))

    logger.warning("gmail_no_auth_configured")
    return None


def list_messages(settings, query: str = "", max_results: int = 100,
                   user_email: str | None = None) -> list[dict]:
    svc = _build_service(settings, user_email=user_email)
    if not svc:
        return []
    try:
        resp = svc.users().messages().list(
            userId="me", q=query, maxResults=max_results
        ).execute()
        return resp.get("messages", [])
    except Exception as exc:
        logger.warning("gmail_list_err", error=str(exc), user_email=user_email)
        return []


def fetch_raw_message(settings, msg_id: str, user_email: str | None = None) -> bytes | None:
    svc = _build_service(settings, user_email=user_email)
    if not svc:
        return None
    try:
        resp = svc.users().messages().get(
            userId="me", id=msg_id, format="raw"
        ).execute()
        raw_b64 = resp.get("raw", "")
        return base64.urlsafe_b64decode(raw_b64 + "==")
    except Exception as exc:
        logger.warning("gmail_fetch_err", msg_id=msg_id, error=str(exc), user_email=user_email)
        return None


def _find_label_id(all_labels: list, name: str) -> str | None:
    for entry in all_labels:
        if entry.get("name") == name:
            return entry.get("id")
    return None


def apply_label(settings, msg_id: str, label_name: str, user_email: str | None = None) -> bool:
    svc = _build_service(settings, user_email=user_email)
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


def deliver_to_inbox(settings, raw_email: bytes, label_name: str = "PhishGuard-Delivered",
                      user_email: str | None = None) -> bool:
    """Inject a raw email directly into the Gmail inbox via Gmail API.

    This is used in demo/gateway mode when clean emails are approved —
    instead of relaying via SMTP (which requires a real mail server),
    we use the Gmail API to place the message directly into the inbox.
    The recipient actually SEES it in Gmail.
    """
    svc = _build_service(settings, user_email=user_email)
    if not svc:
        return False
    try:
        raw_b64 = base64.urlsafe_b64encode(raw_email).decode().rstrip("=")
        result = svc.users().messages().import_(
            userId="me",
            body={"raw": raw_b64},
            internalDateSource="receivedTime",
            processForCalendar=False,
            deleted=False,
        ).execute()
        msg_id = result.get("id", "")
        logger.info("gmail_inbox_delivered", msg_id=msg_id)

        if msg_id:
            all_labels = svc.users().labels().list(userId="me").execute().get("labels", [])

            # Ensure the custom label exists
            label_id = _find_label_id(all_labels, label_name)
            if not label_id:
                created = svc.users().labels().create(
                    userId="me", body={"name": label_name}
                ).execute()
                label_id = created.get("id")

            # Add INBOX label so it actually appears in the inbox,
            # plus the custom PhishGuard label for identification
            add_labels = ["INBOX"]
            if label_id:
                add_labels.append(label_id)

            svc.users().messages().modify(
                userId="me", id=msg_id,
                body={"addLabelIds": add_labels, "removeLabelIds": []}
            ).execute()
            logger.info("gmail_inbox_labelled", msg_id=msg_id, label=label_name)
        return True
    except Exception as exc:
        logger.warning("gmail_inbox_deliver_err", error=str(exc))
        return False
