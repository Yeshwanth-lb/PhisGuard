"""Layer 7 - Google Workspace Directory client: enumerate domain mailboxes.

Domain-wide delegation lets the service account impersonate any user's Gmail,
but it doesn't tell PhishGuard *who those users are* — that's a separate API
(Admin SDK Directory) that must itself be called as an impersonated super-admin
(google_admin_impersonate_email). Gmail API impersonation works for any regular
user; listing the directory only works impersonating an actual admin account.
"""
import os

import structlog

logger = structlog.get_logger()

_DIRECTORY_SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
]


def _build_directory_service(settings):
    """Build an Admin SDK Directory API client, impersonating the configured
    super-admin. Returns None (fail-closed) if not configured or auth fails —
    callers must treat that as "no users discovered", not an error to surface."""
    try:
        from googleapiclient.discovery import build
    except ImportError as exc:
        logger.warning("directory_lib_missing", error=str(exc))
        return None

    sa_path = getattr(settings, "google_service_account_json", "") or ""
    admin_email = getattr(settings, "google_admin_impersonate_email", "") or ""

    if not (sa_path and os.path.exists(sa_path) and admin_email):
        logger.warning("directory_not_configured")
        return None

    try:
        import importlib
        sa_mod = importlib.import_module("google.oauth2.service_account")
        sa_creds = sa_mod.Credentials.from_service_account_file(sa_path, scopes=_DIRECTORY_SCOPES)
        delegated = sa_creds.with_subject(admin_email)
        return build("admin", "directory_v1", credentials=delegated)
    except Exception as exc:
        logger.warning("directory_auth_failed", error=str(exc))
        return None


def list_domain_users(settings, max_results: int = 500) -> list[str]:
    """Return every user email in the configured Workspace domain. Paginates
    through the full directory. Returns [] (fail-closed) if not configured,
    auth fails, or the domain has no users — never raises to the caller."""
    domain = getattr(settings, "google_workspace_domain", "") or ""
    if not domain:
        logger.warning("directory_no_domain_configured")
        return []

    svc = _build_directory_service(settings)
    if not svc:
        return []

    emails: list[str] = []
    page_token = None
    try:
        while True:
            resp = svc.users().list(
                domain=domain,
                maxResults=max_results,
                orderBy="email",
                pageToken=page_token,
            ).execute()
            for user in resp.get("users", []):
                addr = user.get("primaryEmail", "")
                if addr and not user.get("suspended", False):
                    emails.append(addr)
            page_token = resp.get("nextPageToken")
            if not page_token:
                break
    except Exception as exc:
        logger.warning("directory_list_err", error=str(exc))
        return emails  # return whatever we got before the failure

    logger.info("directory_users_discovered", domain=domain, count=len(emails))
    return emails
