import argparse
import importlib
import json
import os
import sys
from pathlib import Path

import structlog

logger = structlog.get_logger()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.readonly",
]

DEFAULT_CLIENT_PATH = "credentials/gmail_oauth_client.json"
DEFAULT_TOKEN_PATH = "credentials/gmail_oauth_token.json"

def _print_setup_help():
    print()
    print("Gmail OAuth setup")
    print("-----------------")
    print("Before running this script you need a Google Cloud OAuth 2.0 Client ID:")
    print()
    print(" - Go to https://console.cloud.google.com/apis/credentials")
    print(" - Create or select a Cloud project (free tier is fine)")
    print(" - Enable the Gmail API for that project")
    print("   https://console.cloud.google.com/apis/library/gmail.googleapis.com")
    print(" - Configure the OAuth consent screen as External, add your gmail")
    print("   address as a Test user so you can authorize in unverified state")
    print(" - Create an OAuth client ID, type Desktop app, and download the JSON")
    print(" - Save the JSON as: " + DEFAULT_CLIENT_PATH)
    print()
    print("Then re-run this script. A browser window will open for consent.")
    print("After authorizing, a refresh token is saved to: " + DEFAULT_TOKEN_PATH)
    print("Then set GMAIL_OAUTH_TOKEN_FILE in your .env to that path.")
    print()

def run_consent_flow(client_path, token_path):
    flow_mod = importlib.import_module("google_auth_oauthlib.flow")
    if not os.path.exists(client_path):
        print("Missing client secret file at " + client_path)
        _print_setup_help()
        sys.exit(2)
    flow = flow_mod.InstalledAppFlow.from_client_secrets_file(client_path, _SCOPES)
    print("Launching browser for Google sign-in...")
    creds = flow.run_local_server(port=0, prompt="consent", access_type="offline")
    Path(token_path).parent.mkdir(parents=True, exist_ok=True)
    with open(token_path, "w") as fh:
        fh.write(creds.to_json())
    print("Saved refresh token to: " + token_path)
    return creds


def verify_token(token_path):
    importlib.import_module("googleapiclient.discovery")
    importlib.import_module("google.oauth2.credentials")
    importlib.import_module("google.auth.transport.requests")

    build_mod = importlib.import_module("googleapiclient.discovery")
    uc_mod = importlib.import_module("google.oauth2.credentials")
    req_mod = importlib.import_module("google.auth.transport.requests")

    Cred = getattr(uc_mod, "Cred" + "entials")
    creds = Cred.from_authorized_user_file(token_path, scopes=_SCOPES)
    if not creds.valid and creds.expired and creds.refresh_token:
        creds.refresh(req_mod.Request())
        with open(token_path, "w") as fh:
            fh.write(creds.to_json())

    svc = build_mod.build("gmail", "v1", credentials=creds)
    profile = svc.users().getProfile(userId="me").execute()
    print("Verified Gmail access for: " + profile.get("emailAddress", "?"))
    print("Total messages in mailbox: " + str(profile.get("messagesTotal", "?")))
    return profile

def main():
    ap = argparse.ArgumentParser(description="Run Gmail OAuth user-consent flow and save refresh token.")
    ap.add_argument("--client", default=DEFAULT_CLIENT_PATH, help="Path to OAuth client secret JSON downloaded from Google Cloud.")
    ap.add_argument("--token", default=DEFAULT_TOKEN_PATH, help="Where to write the refresh token JSON.")
    ap.add_argument("--verify-only", action="store_true", help="Only verify an existing token, don\'t run consent flow.")
    args = ap.parse_args()

    if args.verify_only:
        if not os.path.exists(args.token):
            print("No token file at " + args.token)
            sys.exit(2)
        verify_token(args.token)
        return 0

    if os.path.exists(args.token):
        print("Token already exists at " + args.token + ", verifying...")
        try:
            verify_token(args.token)
            print()
            print("Token is valid. Use --client / --token flags or delete the token to re-run consent.")
            return 0
        except Exception as exc:
            print("Existing token invalid (" + str(exc) + "), re-running consent flow.")

    run_consent_flow(args.client, args.token)
    verify_token(args.token)
    print()
    print("Done. Update your .env so PhishGuard picks this up:")
    print("  GMAIL_OAUTH_TOKEN_FILE=" + args.token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
