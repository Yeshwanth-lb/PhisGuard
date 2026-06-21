"""Demo script — sends 3 test emails through PhishGuard SMTP gateway on port 8025.

One clean, one suspicious, one phishing. Run AFTER starting:
    python3 scripts/fake_mail_server.py   (in terminal 1)
    docker compose up -d app              (already running)

Then run:
    python3 scripts/test_smtp_gateway.py
"""
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

PHISHGUARD_HOST = "localhost"
PHISHGUARD_PORT = 8025

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"


def send(mail_from, rcpt_to, subject, body, label, colour):
    msg = MIMEMultipart("alternative")
    msg["From"]    = mail_from
    msg["To"]      = rcpt_to
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    print(f"{colour}{BOLD}Sending: {label}{RESET}")
    print(f"  From   : {mail_from}")
    print(f"  To     : {rcpt_to}")
    print(f"  Subject: {subject}")

    try:
        with smtplib.SMTP(PHISHGUARD_HOST, PHISHGUARD_PORT, timeout=30) as s:
            s.ehlo()
            s.sendmail(mail_from, [rcpt_to], msg.as_bytes())
        print(f"  {colour}✓ Accepted by PhishGuard{RESET}\n")
    except Exception as e:
        print(f"  ✗ Error: {e}\n")


EMAILS = [
    # ── 3 CLEAN emails ──────────────────────────────────────────────────
    dict(
        mail_from = "alice@partnerco.com",
        rcpt_to   = "yeshwanthlb0@gmail.com",
        subject   = "Q3 project sync — notes from today",
        body      = (
            "Hi Yeshwanth,\n\nQuick summary from today's sync:\n\n"
            "1. API integration on track for Thursday\n"
            "2. Docs review scheduled for Monday\n"
            "3. Demo confirmed June 25th\n\nBest,\nAlice"
        ),
        label="CLEAN #1 — Normal business email",      colour=GREEN,
    ),
    dict(
        mail_from = "hr@mycompany.com",
        rcpt_to   = "yeshwanthlb0@gmail.com",
        subject   = "Team lunch on Friday — please RSVP",
        body      = (
            "Hi team,\n\nJoining us for lunch this Friday at 1pm?\n"
            "Venue: The Garden Cafe, Level 2.\nPlease reply by Thursday.\n\nHR Team"
        ),
        label="CLEAN #2 — Internal HR announcement",   colour=GREEN,
    ),
    dict(
        mail_from = "newsletter@techcrunch.com",
        rcpt_to   = "yeshwanthlb0@gmail.com",
        subject   = "This week in tech: AI funding rounds, new chip",
        body      = (
            "TechCrunch Weekly\n\n"
            "Top stories this week:\n"
            "- OpenAI raises $10B in new round\n"
            "- Intel releases next-gen chip\n"
            "- Startup of the week: PhishGuard\n\n"
            "Read more at techcrunch.com"
        ),
        label="CLEAN #3 — Newsletter",                 colour=GREEN,
    ),

    # ── 3 SUSPICIOUS emails (designed to score 42-62%) ─────────────────
    dict(
        mail_from = 'verify@account-management-portal-2026.com',
        rcpt_to   = 'yeshwanthlb0@gmail.com',
        subject   = 'Your account requires attention',
        body      = 'Hi, We noticed your account has not been verified yet. To ensure continued access to our services please complete verification. This will only take a few minutes. If you do not verify within 7 days your access may be restricted. Account Team',
        label='SUSPICIOUS #1 — Unknown domain account attention', colour=YELLOW,
    ),
    dict(
        mail_from = 'support@cloudstorage-backup-2026.com',
        rcpt_to   = 'yeshwanthlb0@gmail.com',
        subject   = 'Your backup completed successfully',
        body      = 'Hello, Your scheduled backup completed successfully. 2.3 GB of data has been backed up to our servers. Your next backup is scheduled for tomorrow. If you did not set up this service please contact us. Cloud Backup Support',
        label='SUSPICIOUS #2 — Unknown backup service notification', colour=YELLOW,
    ),
    dict(
        mail_from = 'billing@payment-services-hub-2026.com',
        rcpt_to   = 'yeshwanthlb0@gmail.com',
        subject   = 'Invoice pending for your review',
        body      = 'Dear Customer, An invoice from last month is pending your review. Amount due will be processed automatically in 10 days unless you raise a dispute. Please log in to review the invoice details. Finance Department',
        label='SUSPICIOUS #3 — Invoice from unknown domain', colour=YELLOW,
    ),

    # ── 3 PHISHING emails ───────────────────────────────────────────────
    dict(
        mail_from = "security@paypa1-verify.com",
        rcpt_to   = "yeshwanthlb0@gmail.com",
        subject   = "URGENT: Your PayPal account has been limited",
        body      = (
            "Dear Customer,\n\nYour PayPal account has been LIMITED.\n"
            "Verify your identity IMMEDIATELY:\n"
            "http://paypa1-verify.com/restore?id=8472\n\n"
            "You have 24 hours or your account will be permanently closed.\n\nPayPal Security"
        ),
        label="PHISHING #1 — Fake PayPal with malicious URL", colour=RED,
    ),
    dict(
        mail_from = "noreply@micros0ft-account-alert.net",
        rcpt_to   = "yeshwanthlb0@gmail.com",
        subject   = "Your Microsoft 365 session has expired",
        body      = (
            "Microsoft Account Security\n\n"
            "Your session has expired due to unusual activity.\n"
            "Click here to restore access immediately:\n"
            "http://micros0ft-account-alert.net/verify\n\n"
            "Failure to verify will result in account suspension.\n\nMicrosoft Security"
        ),
        label="PHISHING #2 — Fake Microsoft with typosquat domain", colour=RED,
    ),
    dict(
        mail_from = "ceo-transfer@company-exec-wire.net",
        rcpt_to   = "yeshwanthlb0@gmail.com",
        subject   = "CONFIDENTIAL: Urgent wire transfer — board approval",
        body      = (
            "This is strictly confidential.\n\n"
            "We are closing an acquisition today. Wire $87,500 immediately:\n"
            "Bank: First National Trust\nAccount: 4521987630\nRouting: 021000021\n\n"
            "Do NOT discuss with anyone. Confirm when done.\n\nCEO"
        ),
        label="PHISHING #3 — BEC wire fraud (bad auth domain)", colour=RED,
    ),
]


def main():
    print(f"\n{BOLD}{CYAN}PhishGuard SMTP Gateway — 9-Email Demo Test{RESET}")
    print(f"{CYAN}Sending 3 clean + 3 suspicious + 3 phishing to port {PHISHGUARD_PORT}{RESET}\n")
    print("─" * 60)

    for i, e in enumerate(EMAILS, 1):
        colour = e["colour"]
        print(f"\n{colour}{BOLD}[{i}/9] {e['label']}{RESET}")
        send(e["mail_from"], e["rcpt_to"], e["subject"], e["body"],
             e["label"], colour)
        time.sleep(2)

    print("─" * 60)
    print(f"\n{BOLD}All 9 emails sent. Expected results:{RESET}")
    print(f"  {GREEN}✅ 3 CLEAN     → arrive at fake mail server unchanged{RESET}")
    print(f"  {YELLOW}🟡 3 SUSPICIOUS → held in Pending Review tab on dashboard{RESET}")
    print(f"                   Approve  → email forwards to recipient")
    print(f"                   Reject   → email moves to Quarantine tab")
    print(f"  {RED}🔴 3 PHISHING  → blocked, RCPT rewritten to quarantine address{RESET}")
    print(f"                   Visible in Quarantine tab on dashboard")
    print(f"\n  Dashboard: {CYAN}localhost:8000{RESET}")
    print(f"  Fake server output: check Terminal 1\n")


if __name__ == "__main__":
    main()
