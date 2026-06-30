"""Demo: send 5 clean + 5 suspicious + 5 phishing emails through the live gateway.

Two-phase, so the demo never misfires:
  1. CALIBRATE — POST each candidate to /analyze (no delivery) and read its real
     verdict. We keep a few spares per category because "suspicious" is a gray-zone
     verdict we can't assume.
  2. SEND      — pick the first 5 that ACTUALLY classified as clean/suspicious/phishing
     and inject them via SMTP :8025 (the real gateway path). Each goes to a DISTINCT
     recipient so this stays a phishing-classification demo and does not trip the
     bombing detector.

Routing you'll see (smtp_receiver.handle_DATA):
  clean      -> delivered to Gmail   (label PhishGuard-Delivered)   -> inbox
  suspicious -> held for SOC review  (pending_review queue)          -> dashboard Pending
  phishing   -> quarantined          ([PHISHGUARD QUARANTINE ...])   -> dashboard Quarantine

Usage:
  PYTHONPATH=. python3 scripts/demo_phishing_15.py            # calibrate only (safe)
  PYTHONPATH=. python3 scripts/demo_phishing_15.py --send     # calibrate then send
"""
import argparse
import smtplib
import time
from email.mime.text import MIMEText
from email.utils import formatdate

import httpx

APP = "http://localhost:8000"
SMTP_HOST, SMTP_PORT = "localhost", 8025
API_KEY = "dev-key"

G = "\033[92m"; Y = "\033[93m"; Rd = "\033[91m"; C = "\033[96m"; B = "\033[1m"; D = "\033[2m"; R = "\033[0m"

# ── Candidate pools (a few spares per category; calibration decides the truth) ──
# (from, subject, body)
CLEAN = [
    ("rohan.mehta@infosys.com", "Re: Q3 partnership review",
     "Hi, following up on the Q3 partnership numbers. Can we sync sometime this week? Thanks, Rohan"),
    ("priya.sharma@company.com", "Notes from this morning's standup",
     "Sharing the standup notes. Backend API is on track, design review moved to Thursday. Let me know if I missed anything."),
    ("orders@bigbasket.com", "Your order #BB48213 has been delivered",
     "Your order was delivered today at 2:14 PM. Items: groceries (12). Thanks for shopping with us."),
    ("hr@company.com", "Reminder: submit your timesheet by Friday",
     "A friendly reminder to submit your timesheet for this week by end of day Friday. Reach out to HR with any questions."),
    ("newsletter@morningbrew.com", "The Morning Brew: markets, tech, and a good read",
     "Good morning. Today: markets edged higher, a new chip launch, and a profile of a founder you should know."),
    ("arjun.k@company.com", "Lunch tomorrow?",
     "Hey, a few of us are grabbing lunch tomorrow at 1. Want to join? No worries if you're busy."),
    ("status@projecthub.company.com", "Weekly project status: Phoenix",
     "Phoenix is green. Milestone 3 shipped, milestone 4 begins Monday. Risks: none. Full report in the wiki."),
]

SUSPICIOUS = [
    ("support@account-update-center.com", "Action required: confirm your billing details",
     "We were unable to process your last payment. Please update your billing information to avoid interruption. Click here: http://account-update-center.com/billing"),
    ("noreply@delivery-notice.net", "Your package could not be delivered",
     "We attempted delivery but no one was available. Reschedule your delivery here: http://delivery-notice.net/reschedule within 48 hours."),
    ("alerts@my-account-security.com", "Unusual sign-in detected",
     "We noticed a new sign-in to your account from an unrecognized device. If this wasn't you, review your activity: http://my-account-security.com/review"),
    ("team@docs-shared.net", "A document has been shared with you",
     "A document titled 'Q3 Budget' has been shared with you. View it here: http://docs-shared.net/open?id=8841"),
    ("rewards@survey-prize.co", "You're eligible for a $50 reward",
     "Thanks for being a valued customer. Complete a short survey to claim your $50 reward: http://survey-prize.co/claim"),
    ("billing@subscription-renew.info", "Your subscription is expiring soon",
     "Your subscription expires in 2 days. Renew now to keep your benefits: http://subscription-renew.info/renew"),
    ("no-reply@verify-mail.app", "Please verify your email address",
     "To finish setting up your account, please verify your email address by clicking the link: http://verify-mail.app/confirm?u=4471"),
    ("notice@invoice-portal.org", "Invoice #4471 is ready for review",
     "Your invoice is ready. Please review and confirm payment details here: http://invoice-portal.org/inv/4471"),
]

PHISHING = [
    ("security@paypa1-secure.com", "Your account is suspended - verify now",
     "Your PayPal account has been limited due to suspicious activity. Verify immediately or your account will be permanently closed: http://paypa1-secure-login.com/verify"),
    ("alert@hdfc-bank-secure.com", "Unusual login - confirm your identity immediately",
     "We detected a login from an unknown device. Confirm your netbanking credentials now to avoid suspension: http://hdfc-bank-secure.com/login"),
    ("it-helpdesk@office365-reset.com", "Your password expires TODAY - reset required",
     "Your company password expires today. Failure to reset will lock your account. Reset here using your current credentials: http://office365-reset.com/pwd"),
    ("rewards@amaz0n-giftcard.com", "Congratulations! You've won a $1000 gift card",
     "You have been selected to receive a $1000 Amazon gift card. Claim within 24 hours by entering your details: http://amaz0n-giftcard.com/claim"),
    ("docusign@secure-esign-doc.com", "You have a document waiting for signature",
     "An urgent document requires your signature. Sign in with your email and password to view: http://secure-esign-doc.com/sign"),
    ("appleid@apple-id-locked.com", "Your Apple ID has been locked",
     "Your Apple ID was locked due to too many failed attempts. Unlock now by verifying your account: http://apple-id-locked.com/unlock"),
    ("accounts@wire-payment-update.com", "URGENT: update vendor payment details",
     "Per finance, our bank details have changed. Update the vendor account before processing today's wire: http://wire-payment-update.com/ach"),
]


def analyze(client, token, frm, subject, body):
    raw = (f"From: {frm}\r\nTo: user@company.com\r\n"
           f"Date: {formatdate(localtime=True)}\r\nSubject: {subject}\r\n\r\n{body}")
    try:
        r = client.post(f"{APP}/analyze", headers={"Authorization": f"Bearer {token}"},
                        json={"raw_email": raw, "subject": subject})
        if r.status_code != 200:
            return None, f"http_{r.status_code}"
        d = r.json()
        return d.get("verdict"), round(float(d.get("confidence") or 0), 3)
    except Exception as exc:
        return None, str(exc)[:60]


def send_smtp(frm, rcpt, subject, body):
    msg = MIMEText(body)
    msg["From"] = frm
    msg["To"] = rcpt
    msg["Date"] = formatdate(localtime=True)
    msg["Subject"] = subject
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=60) as s:
        s.sendmail(frm, [rcpt], msg.as_bytes())


# Curated known-good set (verified by a prior calibration run) — lets --no-calibrate
# skip the slow /analyze pass and send a deterministic 5/5/5 that lands in each bucket.
CURATED = {
    "clean":      CLEAN[:5],
    "suspicious": SUSPICIOUS[1:6],   # SUSPICIOUS[0] sits on the phishing line; skip it
    "phishing":   PHISHING[:5],
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--send", action="store_true", help="actually inject via SMTP after calibration")
    ap.add_argument("--no-calibrate", action="store_true", help="skip /analyze; send the curated known-good set")
    ap.add_argument("--offset", type=int, default=0, help="recipient number offset (e.g. 15 -> user16..)")
    args = ap.parse_args()

    color = {"clean": G, "suspicious": Y, "phishing": Rd}

    if args.no_calibrate:
        buckets = {k: list(v) for k, v in CURATED.items()}
        print(f"{B}Skipping calibration — using curated known-good set "
              f"(clean={len(buckets['clean'])} suspicious={len(buckets['suspicious'])} phishing={len(buckets['phishing'])}){R}")
    else:
        token = httpx.post(f"{APP}/token", json={"api_key": API_KEY, "role": "admin", "sub": "demo"}).json()["access_token"]
        client = httpx.Client(timeout=60)

        print(f"{B}Phase 1 — calibrate against /analyze (no delivery){R}\n")
        pools = [("clean", CLEAN), ("suspicious", SUSPICIOUS), ("phishing", PHISHING)]
        buckets = {"clean": [], "suspicious": [], "phishing": []}

        for intended, pool in pools:
            print(f"{B}intended = {intended}{R}")
            for frm, subj, body in pool:
                verdict, conf = analyze(client, token, frm, subj, body)
                v = verdict or "ERR"
                mark = "✓" if v == intended else ("·" if v in buckets else "✗")
                col = color.get(v, D)
                print(f"  {col}{mark} {v:<11}{R}{D}conf={conf}{R}  {subj[:54]}")
                if v in buckets:
                    buckets[v].append((frm, subj, body))
            print()

        print(f"{B}Calibration result:{R} "
              f"clean={len(buckets['clean'])}  suspicious={len(buckets['suspicious'])}  phishing={len(buckets['phishing'])}")

        short = [k for k in ("clean", "suspicious", "phishing") if len(buckets[k]) < 5]
        if short:
            print(f"{Y}! not enough in: {', '.join(short)} — add candidates or send what we have.{R}")

    if not args.send:
        print(f"\n{D}Dry run. Re-run with --send to inject the set via SMTP :8025.{R}")
        return

    print(f"\n{B}Phase 2 — inject 5 per category via SMTP :8025 (distinct recipients){R}\n")
    n = args.offset
    for cat in ("clean", "suspicious", "phishing"):
        chosen = buckets[cat][:5]
        for i, (frm, subj, body) in enumerate(chosen, 1):
            n += 1
            rcpt = f"user{n}@company.com"           # distinct recipient → no bombing trip
            try:
                send_smtp(frm, rcpt, subj, body)
                print(f"  {color[cat]}{cat:<11}{R}-> {rcpt:<20} {D}{subj[:46]}{R}")
            except Exception as exc:
                print(f"  {Rd}FAILED{R} {cat} {subj[:40]}: {exc}")
            time.sleep(0.5)                          # gentle pacing

    print(f"\n{G}✓ sent {n} emails.{R}")
    print(f"{D}  • clean      → Gmail inbox (PhishGuard-Delivered)")
    print(f"  • suspicious → dashboard Pending Review (held)")
    print(f"  • phishing   → dashboard Quarantine{R}")
    print(f"{D}  Dashboard: {APP}/   Verify counts: curl -s {APP}/api/stats -H 'Authorization: Bearer <token>'{R}")


if __name__ == "__main__":
    main()
