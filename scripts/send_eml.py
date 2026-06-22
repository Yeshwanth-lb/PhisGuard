#!/usr/bin/env python3
"""Pipe any real .eml file through the PhishGuard SMTP gateway for analysis.

How to get a .eml file from Gmail:
  1. Open the email in Gmail
  2. Click the three-dot menu (top-right of the email) → "Show original"
  3. Click "Download Original" — saves as a .eml file

Usage:
    python3 scripts/send_eml.py ~/Downloads/email.eml
    python3 scripts/send_eml.py ~/Downloads/email.eml --to yeshwanthlb0@gmail.com
    python3 scripts/send_eml.py ~/Downloads/email.eml --from attacker@phish.com --to you@gmail.com

After sending, check:
    http://localhost:8000  →  Reports tab (all scans)
                          →  Pending Review tab (if suspicious)
                          →  Quarantine tab (if phishing)
"""
import argparse
import re
import smtplib
import sys
from email import message_from_bytes
from email.policy import compat32

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"


def main():
    parser = argparse.ArgumentParser(
        description="Pipe a real .eml file through PhishGuard on port 8025"
    )
    parser.add_argument("eml_file", help="Path to the .eml file to analyse")
    parser.add_argument("--from", dest="mail_from", default="",
                        help="Override SMTP MAIL FROM (auto-detected from headers if omitted)")
    parser.add_argument("--to", dest="rcpt_to", default="yeshwanthlb0@gmail.com",
                        help="SMTP RCPT TO address (default: yeshwanthlb0@gmail.com)")
    parser.add_argument("--host", default="localhost", help="PhishGuard host (default: localhost)")
    parser.add_argument("--port", type=int, default=8025, help="PhishGuard SMTP port (default: 8025)")
    args = parser.parse_args()

    try:
        with open(args.eml_file, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        print(f"{RED}✗ File not found: {args.eml_file}{RESET}")
        sys.exit(1)

    msg = message_from_bytes(raw, policy=compat32)

    # Auto-detect From address from headers if not provided
    mail_from = args.mail_from
    if not mail_from:
        from_header = msg.get("From", "") or ""
        m = re.search(r"[\w.+\-]+@[\w.\-]+", from_header)
        mail_from = m.group(0) if m else "unknown@example.com"

    subject = msg.get("Subject", "(no subject)")
    date    = msg.get("Date", "(unknown)")

    print(f"\n{BOLD}{CYAN}PhishGuard — Real Email Analysis{RESET}")
    print("─" * 50)
    print(f"  File   : {args.eml_file}")
    print(f"  From   : {mail_from}")
    print(f"  To     : {args.rcpt_to}")
    print(f"  Subject: {subject}")
    print(f"  Date   : {date}")
    print(f"  Size   : {len(raw):,} bytes")
    print()

    try:
        with smtplib.SMTP(args.host, args.port, timeout=30) as s:
            s.ehlo()
            s.sendmail(mail_from, [args.rcpt_to], raw)
        print(f"{GREEN}{BOLD}✓ Accepted by PhishGuard gateway{RESET}")
    except ConnectionRefusedError:
        print(f"{RED}✗ Could not connect to {args.host}:{args.port}{RESET}")
        print("  Make sure PhishGuard is running: docker compose up -d app")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}✗ Error: {e}{RESET}")
        sys.exit(1)

    print()
    print(f"  Analysis is running through all 7 layers (~5-15 seconds).")
    print(f"  Check results at: {CYAN}http://localhost:8000{RESET}")
    print(f"  → Reports tab       — full verdict + layer scores")
    print(f"  → Pending Review    — if classified as suspicious (SOC holds it)")
    print(f"  → Quarantine tab    — if classified as phishing (blocked)")
    print()


if __name__ == "__main__":
    main()
