"""Inbox bombing demo — shows subscription bomb detection + smart routing.

Run BEFORE this script (once per session):
    docker compose exec app sh -c "SMTP_RATE_PER_IP=200 SMTP_RATE_GLOBAL=200"

Or just run with: python3 scripts/demo_bombing.py --raise-limits
which temporarily raises the rate limiter limits via the API so the
per-IP counter doesn't fire before the bombing detector does.

What to watch:
    docker compose logs -f app | grep -E "bombing|high_signal|surfaced|held|rate_limit"

Expected output:
    1. Emails 1–4:  smtp_received (no detection yet)
    2. Email 5:     inbox_bombing_velocity_detected (velocity trigger fires)
    3. All subsequent subscription emails: smtp_bombing_subscription_held
    4. OTP email:   smtp_bombing_high_signal_delivered (surfaces despite hold)
    5. Normal biz email: smtp_bombing_unmatched_surfaced (default delivery)
    6. Dashboard:   orange banner on Overview tab
"""
import argparse
import os
import smtplib
import time
from email.mime.text import MIMEText

PHISHGUARD_HOST = "localhost"
PHISHGUARD_PORT = 8025
VICTIM          = "victim@company.com"

RESET  = "\033[0m"; BOLD = "\033[1m"
GREEN  = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"; CYAN = "\033[96m"

BOMBING_EMAILS = [
    # ── Subscription noise — 15 emails (should be HELD) ──────────────────────
    ("noreply@amazon-newsletters.com",     "Confirm your Amazon account"),
    ("verify@github-mailer.com",           "Please verify your email address"),
    ("welcome@shopify-store-123.com",      "Welcome to our online store"),
    ("noreply@newsletter-service-a.com",   "Thanks for signing up"),
    ("signup@medium-stories.com",          "Complete your Medium registration"),
    ("activate@forum-platform-b.com",      "Activate your account now"),
    ("no-reply@linkedin-digest.com",       "Welcome to the community"),
    ("confirm@ecommerce-site-x.com",       "Confirm your email address"),
    ("registration@travel-app-c.com",      "Finish setting up your profile"),
    ("noreply@coupon-service-d.com",       "You've been registered successfully"),
    ("verify@app-service-e.com",           "Email verification required"),
    ("welcome@subscription-box-f.com",     "One more step to complete sign-up"),
    ("noreply@dating-app-g.com",           "Please confirm your registration"),
    ("activate@gaming-platform-h.com",     "Activate your gaming account"),
    ("signup@blog-platform-i.com",         "Thanks for joining our community"),

    # ── High-signal email — should SURFACE despite the hold ──────────────────
    ("security@mybank.com",                "Your one-time password is: 847291"),

    # ── Normal business email — unmatched subject, should SURFACE ─────────────
    ("alice@partnerco.com",                "Can we reschedule Thursday's call?"),

    # ── Another round of noise ────────────────────────────────────────────────
    ("noreply@saas-product-j.com",         "Confirm your email to get started"),
    ("welcome@fitness-app-k.com",          "Welcome to FitApp — verify now"),
    ("verify@fintech-startup-l.com",       "Action required: verify your account"),
]


def send(mail_from, subject, colour, label):
    msg = MIMEText("This is a test email for bombing detection demo.")
    msg["From"]    = mail_from
    msg["To"]      = VICTIM
    msg["Subject"] = subject
    try:
        with smtplib.SMTP(PHISHGUARD_HOST, PHISHGUARD_PORT, timeout=10) as s:
            s.ehlo()
            s.sendmail(mail_from, [VICTIM], msg.as_bytes())
        print(f"  {colour}✓ Accepted{RESET}  {label:<30} \"{subject}\"")
        return True
    except smtplib.SMTPResponseException as e:
        if e.smtp_code == 421:
            print(f"  {RED}✗ 421 RATE LIMITED{RESET}  \"{subject}\" — hit per-IP limit before bombing detector!")
            print(f"  {YELLOW}  Fix: set SMTP_RATE_PER_IP=200 in app env and restart{RESET}")
        else:
            print(f"  {RED}✗ SMTP {e.smtp_code}{RESET}  \"{subject}\"")
        return False
    except Exception as e:
        print(f"  {RED}✗ Error: {e}{RESET}")
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--delay", type=float, default=0.3,
                        help="Seconds between emails (default 0.3 — fast enough for velocity trigger)")
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}PhishGuard — Inbox Bombing Detection Demo{RESET}")
    print(f"{CYAN}Sending {len(BOMBING_EMAILS)} emails to {VICTIM}{RESET}")
    print(f"{CYAN}Delay: {args.delay}s between emails{RESET}\n")
    print("─" * 65)
    print(f"\n{YELLOW}NOTE: If emails start returning 421 after email 10,{RESET}")
    print(f"{YELLOW}the SMTP per-IP rate limiter fired before the bombing detector.{RESET}")
    print(f"{YELLOW}Fix: docker exec --user root phishguard-app sh -c{RESET}")
    print(f"{YELLOW}  'kill -HUP 1'  # or restart with SMTP_RATE_PER_IP=200{RESET}\n")

    for i, (mail_from, subject) in enumerate(BOMBING_EMAILS, 1):
        if "one-time password" in subject.lower() or "otp" in subject.lower():
            colour = GREEN
            label  = f"[{i:2d}] OTP — should SURFACE"
        elif subject.lower().startswith(("can ", "hi ", "re:", "fwd:", "meeting", "call")):
            colour = GREEN
            label  = f"[{i:2d}] Normal — should SURFACE"
        else:
            colour = YELLOW
            label  = f"[{i:2d}] Subscription — should HOLD"

        ok = send(mail_from, subject, colour, label)
        if not ok:
            break
        time.sleep(args.delay)

    print("\n" + "─" * 65)
    print(f"\n{BOLD}What to look for:{RESET}")
    print(f"  {YELLOW}inbox_bombing_velocity_detected{RESET}  — fires after email 5 (30s window)")
    print(f"  {YELLOW}smtp_bombing_subscription_held{RESET}   — subscription noise captured")
    print(f"  {GREEN}smtp_bombing_high_signal_delivered{RESET} — OTP surfaces despite hold")
    print(f"  {GREEN}smtp_bombing_unmatched_surfaced{RESET}    — normal email delivers")
    print(f"\n  {CYAN}Dashboard: http://localhost:8000 → Overview tab (orange banner){RESET}")
    print(f"  {CYAN}Logs: docker compose logs -f app | grep bombing{RESET}\n")


if __name__ == "__main__":
    main()
