"""PhishGuard SMTP Gateway — randomised 9-email demo test.

Picks 3 clean + 3 suspicious + 3 phishing at random from a pool of
diverse emails each run, so the ML model sees varied feature vectors
and avoids overfitting to a fixed synthetic set.

Usage:
    python3 scripts/test_smtp_gateway.py
    python3 scripts/test_smtp_gateway.py --seed 42   # reproducible run
"""
import argparse
import random
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

PHISHGUARD_HOST = "localhost"
PHISHGUARD_PORT = 8025
RECIPIENT       = "yeshwanthlb0@gmail.com"

RESET  = "\033[0m"; BOLD = "\033[1m"
GREEN  = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"; CYAN = "\033[96m"


# ── CLEAN pool (10 emails) ───────────────────────────────────────────────────
CLEAN_POOL = [
    dict(
        mail_from="alice@partnerco.com", subject="Q3 project sync — notes from today",
        body="Hi Yeshwanth,\n\nQuick summary from today's sync:\n1. API integration on track for Thursday\n2. Docs review Monday\n3. Demo confirmed June 25\n\nBest,\nAlice",
        label="Business sync (no links)",
    ),
    dict(
        mail_from="hr@mycompany.com", subject="Team lunch on Friday — please RSVP",
        body="Hi team,\n\nJoining us for lunch this Friday at 1pm?\nVenue: The Garden Cafe, Level 2.\nPlease reply by Thursday.\n\nHR Team",
        label="Internal HR (short, plain)",
    ),
    dict(
        mail_from="newsletter@techcrunch.com", subject="This week in tech: AI funding rounds",
        body="TechCrunch Weekly\n\nTop stories:\n- OpenAI raises $10B\n- Intel releases next-gen chip\n- PhishGuard wins security award\n\nRead more at techcrunch.com",
        label="Newsletter (known domain)",
    ),
    dict(
        mail_from="manager@acmecorp.com", subject="Can you cover the 3pm standup?",
        body="Hey,\n\nI'm stuck in another call at 3. Can you run the standup today and share notes?\n\nThanks,\nMike",
        label="Short internal ask (no links)",
    ),
    dict(
        mail_from="devops@mycompany.com", subject="Deployment successful — v2.4.1 is live",
        body="Hi team,\n\nDeployment of v2.4.1 completed successfully at 14:32 UTC.\nAll health checks passing. Rollback window closes in 2 hours.\n\nDevOps",
        label="Deployment notification",
    ),
    dict(
        mail_from="support@github.com", subject="Your pull request was merged",
        body="Hi Yeshwanth,\n\nYour pull request #42 'fix: handle edge case in parser' was merged into main by alice.\n\nView it on GitHub: github.com/myorg/repo/pull/42\n\nThe GitHub Team",
        label="GitHub PR notification",
    ),
    dict(
        mail_from="noreply@notion.so", subject="Yeshwanth shared a page with you",
        body="Alice shared 'Q3 Roadmap' with you on Notion.\n\nOpen it at notion.so to view.\n\nThe Notion Team",
        label="Notion share (trusted domain)",
    ),
    dict(
        mail_from="calendar@google.com", subject="Reminder: Team sync in 15 minutes",
        body="This is a reminder that 'Team sync' starts in 15 minutes.\n\nWhen: Today at 3:00 PM IST\nWhere: Google Meet\n\nGoogle Calendar",
        label="Calendar reminder (Google)",
    ),
    dict(
        mail_from="invoices@stripe.com", subject="Your invoice is ready — $49.00",
        body="Hi Yeshwanth,\n\nYour invoice for June 2026 is ready.\nAmount: $49.00\nPlan: Starter\n\nLog in to your Stripe dashboard to view it.\n\nStripe Billing",
        label="Stripe invoice (trusted)",
    ),
    dict(
        mail_from="recruiter@linkedin.com", subject="You have a new connection request",
        body="Hi Yeshwanth,\n\nSarah Chen wants to connect with you on LinkedIn.\nSarah is a Senior Engineer at Acme Corp.\n\nLinkedIn",
        label="LinkedIn connection (trusted)",
    ),
]

# ── SUSPICIOUS pool (10 emails) ──────────────────────────────────────────────
SUSPICIOUS_POOL = [
    dict(
        mail_from="verify@account-management-portal-2026.com",
        subject="Your account requires attention",
        body="Hi, We noticed your account has not been verified yet. To ensure continued access please complete verification. This will only take a few minutes. If you do not verify within 7 days your access may be restricted. Account Team",
        label="Unknown domain account verification",
    ),
    dict(
        mail_from="support@cloudstorage-backup-2026.com",
        subject="Your backup completed successfully",
        body="Hello, Your scheduled backup completed successfully. 2.3 GB backed up to our servers. Next backup tomorrow. If you did not set up this service please contact us. Cloud Backup Support",
        label="Unknown backup service",
    ),
    dict(
        mail_from="billing@payment-services-hub-2026.com",
        subject="Invoice pending for your review",
        body="Dear Customer, An invoice from last month is pending review. Amount due will be processed automatically in 10 days unless you raise a dispute. Log in to review. Finance Department",
        label="Unknown billing portal",
    ),
    dict(
        mail_from="noreply@secure-doc-review-2026.net",
        subject="Document shared with you — action required",
        body="A document has been shared with you for review. Please complete your review before the deadline on Friday. Access the document through our secure portal. Document Services Team",
        label="Suspicious doc share",
    ),
    dict(
        mail_from="alerts@it-helpdesk-notifications.com",
        subject="Your password expires in 3 days",
        body="Hi, Your company password is set to expire in 3 days. Please update it soon to avoid being locked out of your account. Contact the IT helpdesk if you have questions. IT Support",
        label="Password expiry from unknown IT domain",
    ),
    dict(
        mail_from="rewards@loyalty-program-hub.net",
        subject="You have unclaimed reward points — 4,200 pts",
        body="Hi Yeshwanth, You have 4,200 loyalty points that will expire this month. Log in to redeem them for gift cards or cashback. Loyalty Rewards Team",
        label="Reward points from unknown domain",
    ),
    dict(
        mail_from="survey@feedback-portal-enterprise.com",
        subject="Quick 2-minute survey — your opinion matters",
        body="Dear Customer, We value your feedback. Please take 2 minutes to complete our satisfaction survey. Your responses will help us improve our service. Customer Success",
        label="Survey from unknown domain",
    ),
    dict(
        mail_from="noreply@subscription-renewal-center.com",
        subject="Your subscription renews in 5 days — review now",
        body="Hi, Your annual subscription is set to auto-renew in 5 days for $149.99. Log in to your account to review or cancel before renewal. Billing Department",
        label="Subscription renewal from unknown",
    ),
    dict(
        mail_from="tax@refund-processing-gov-2026.com",
        subject="Tax refund notice — verify your details",
        body="Dear Taxpayer, A refund has been processed on your account. To receive it please verify your banking details. The process takes 3-5 business days. Revenue Department",
        label="Fake tax refund",
    ),
    dict(
        mail_from="hr@benefits-enrollment-portal-2026.com",
        subject="Open enrollment ends this week — update your benefits",
        body="Hi Yeshwanth, The annual benefits enrollment period closes on Friday. Please log in and confirm your selections to avoid losing your current coverage. HR Benefits Team",
        label="Benefits enrollment from unknown HR domain",
    ),
]

# ── PHISHING pool (10 emails) ────────────────────────────────────────────────
PHISHING_POOL = [
    dict(
        mail_from="security@paypa1-verify.com",
        subject="URGENT: Your PayPal account has been limited",
        body="Dear Customer,\n\nYour PayPal account has been LIMITED.\nVerify your identity IMMEDIATELY:\nhttp://paypa1-verify.com/restore?id=8472\n\nYou have 24 hours or your account will be permanently closed.\n\nPayPal Security",
        label="PayPal typosquat + malicious URL",
    ),
    dict(
        mail_from="noreply@micros0ft-account-alert.net",
        subject="Your Microsoft 365 session has expired",
        body="Microsoft Account Security\n\nYour session expired due to unusual activity.\nClick here to restore access immediately:\nhttp://micros0ft-account-alert.net/verify\n\nFailure to verify will result in account suspension.\n\nMicrosoft Security",
        label="Microsoft typosquat + credential harvest",
    ),
    dict(
        mail_from="ceo-transfer@company-exec-wire.net",
        subject="CONFIDENTIAL: Urgent wire transfer — board approval",
        body="This is strictly confidential.\n\nWe are closing an acquisition today. Wire $87,500 immediately:\nBank: First National Trust\nAccount: 4521987630\nRouting: 021000021\n\nDo NOT discuss with anyone. Confirm when done.\n\nCEO",
        label="BEC wire fraud",
    ),
    dict(
        mail_from="appleid@app1e-security-alert.com",
        subject="Your Apple ID has been locked — verify now",
        body="Dear Apple User,\n\nYour Apple ID was locked due to suspicious activity.\nVerify your account to restore access:\nhttp://app1e-security-alert.com/unlock\n\nIf you do not verify within 24 hours your account will be deleted.\n\nApple Support",
        label="Apple ID phish + homoglyph domain",
    ),
    dict(
        mail_from="netflix-billing@netfl1x-payments.com",
        subject="Payment failed — update your billing info now",
        body="Dear Member,\n\nWe were unable to process your payment. Your account will be suspended unless you update your billing information within 48 hours.\n\nUpdate now: http://netfl1x-payments.com/billing\n\nNetflix Support",
        label="Netflix billing phish + typosquat",
    ),
    dict(
        mail_from="security-alert@amaz0n-prime-verify.net",
        subject="Unusual sign-in detected — secure your account",
        body="Hello,\n\nWe detected a sign-in to your Amazon account from a new device in Lagos, Nigeria.\n\nIf this wasn't you, secure your account immediately:\nhttp://amaz0n-prime-verify.net/secure\n\nAmazon Security Team",
        label="Amazon phish + location urgency",
    ),
    dict(
        mail_from="hr-payroll@company-payslip-portal.net",
        subject="Action required: confirm your bank details for payroll",
        body="Dear Employee,\n\nOur payroll system is being upgraded. Please confirm your bank account details by Friday to ensure your salary is processed without delay.\n\nUpdate here: http://company-payslip-portal.net/confirm\n\nHR & Payroll",
        label="Payroll BEC + credential harvest",
    ),
    dict(
        mail_from="docu-sign@docusign-secure-document.net",
        subject="You have a document waiting for your signature",
        body="Yeshwanth LB has sent you a document to review and sign.\n\nIMPORTANT: This document expires in 24 hours.\n\nReview & Sign: http://docusign-secure-document.net/sign?id=X9K2\n\nDocuSign Electronic Signature",
        label="DocuSign impersonation",
    ),
    dict(
        mail_from="irs-refund@tax-refund-irs-gov-2026.com",
        subject="IRS: You are eligible for a $1,240 tax refund",
        body="Dear Taxpayer,\n\nAfter reviewing your tax return, the IRS has determined you are eligible for a refund of $1,240.00.\n\nClaim your refund: http://tax-refund-irs-gov-2026.com/claim\n\nThis offer expires in 72 hours.\n\nInternal Revenue Service",
        label="IRS impersonation + fake refund",
    ),
    dict(
        mail_from="admin@it-support-desk-helpdesk.com",
        subject="Your account will be deactivated in 24 hours",
        body="Dear User,\n\nYour corporate account is scheduled for deactivation due to inactivity.\n\nTo keep your account active please log in and verify:\nhttp://it-support-desk-helpdesk.com/verify?user=yeshwanth\n\nIT Security Department",
        label="IT helpdesk impersonation",
    ),
]


def send(mail_from, rcpt_to, subject, body, label, colour):
    msg = MIMEMultipart("alternative")
    msg["From"]    = mail_from
    msg["To"]      = rcpt_to
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    print(f"{colour}{BOLD}Sending: {label}{RESET}")
    print(f"  From   : {mail_from}")
    print(f"  Subject: {subject}")
    try:
        with smtplib.SMTP(PHISHGUARD_HOST, PHISHGUARD_PORT, timeout=30) as s:
            s.ehlo()
            s.sendmail(mail_from, [rcpt_to], msg.as_bytes())
        print(f"  {colour}✓ Accepted by PhishGuard{RESET}\n")
    except Exception as e:
        print(f"  ✗ Error: {e}\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducible run")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    clean     = rng.sample(CLEAN_POOL,      3)
    suspicious = rng.sample(SUSPICIOUS_POOL, 3)
    phishing  = rng.sample(PHISHING_POOL,   3)

    seed_str = f"seed={args.seed}" if args.seed is not None else "random"
    print(f"\n{BOLD}{CYAN}PhishGuard SMTP Gateway — 9-Email Demo ({seed_str}){RESET}")
    print(f"{CYAN}Sending 3 clean + 3 suspicious + 3 phishing to port {PHISHGUARD_PORT}{RESET}\n")
    print("─" * 60)

    for i, e in enumerate(clean, 1):
        print(f"\n{GREEN}{BOLD}[{i}/9] CLEAN — {e['label']}{RESET}")
        send(e["mail_from"], RECIPIENT, e["subject"], e["body"], e["label"], GREEN)
        time.sleep(2)

    for i, e in enumerate(suspicious, 1):
        print(f"\n{YELLOW}{BOLD}[{i+3}/9] SUSPICIOUS — {e['label']}{RESET}")
        send(e["mail_from"], RECIPIENT, e["subject"], e["body"], e["label"], YELLOW)
        time.sleep(2)

    for i, e in enumerate(phishing, 1):
        print(f"\n{RED}{BOLD}[{i+6}/9] PHISHING — {e['label']}{RESET}")
        send(e["mail_from"], RECIPIENT, e["subject"], e["body"], e["label"], RED)
        time.sleep(2)

    print("─" * 60)
    print(f"\n{BOLD}All 9 sent. Expected results:{RESET}")
    print(f"  {GREEN}✅ 3 CLEAN      → Gmail inbox (label: PhishGuard-Delivered){RESET}")
    print(f"  {YELLOW}🟡 3 SUSPICIOUS → Pending Review tab (press F5 first){RESET}")
    print(f"  {RED}🔴 3 PHISHING   → Quarantine tab{RESET}")
    print(f"\n  {CYAN}Dashboard: http://localhost:8000{RESET}\n")

    print(f"{BOLD}Emails sent this run:{RESET}")
    for label, pool, colour in [("Clean", clean, GREEN), ("Suspicious", suspicious, YELLOW), ("Phishing", phishing, RED)]:
        print(f"  {colour}{label}:{RESET}")
        for e in pool:
            print(f"    · {e['label']} ({e['mail_from']})")
    print()


if __name__ == "__main__":
    main()
