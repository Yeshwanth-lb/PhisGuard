"""Demo: a REALISTIC mixed email bomb against the live gateway (port 8025).

Sends realistic-looking mail (real service signup confirmations, OTP/security codes,
spoofed bank alerts, business mail) so the inbox shows authentic-looking bombing traffic
— PhishGuard then prepends its own tier label. Each category lands in a different tier:

  SUBSCRIPTION  -> Tier 2 noise      -> "[Possible Bombing Noise]"
  OTP/SECURITY  -> Tier 3 uncertain  -> "[Received During Mail Bomb]" (not fast-tracked)
  SPOOFED BANK  -> spoofed_critical  -> QUARANTINED (claims .bank, no valid DKIM)
  BUSINESS      -> Tier 3 uncertain  -> "[Received During Mail Bomb]"
"""
import argparse
import smtplib
import threading
import time
from email.mime.text import MIMEText

# (from, subject, body) — realistic signup/confirmation traffic an email bomb produces
SUBSCRIPTION = [
    ("no-reply@accounts.spotify.com", "Confirm your email address",
     "Welcome to Spotify! Please confirm your email address to activate your account."),
    ("newsletter@e.medium.com", "Welcome to Medium",
     "Thanks for joining Medium. Confirm your email to start reading stories tailored to you."),
    ("no-reply@substack.com", "Confirm your subscription",
     "You're almost there — confirm your subscription to start receiving posts."),
    ("hello@mail.canva.com", "Verify your email to get started",
     "Welcome to Canva! Verify your email to start creating designs."),
    ("no-reply@quora.com", "Please confirm your email",
     "Confirm your email address to complete your Quora sign-up."),
    ("updates@reddit.com", "Verify your Reddit email address",
     "Verify your email to secure your account and get personalized feeds."),
    ("no-reply@coursera.org", "Welcome to Coursera — confirm your email",
     "Thanks for signing up. Confirm your email to start learning today."),
    ("team@notion.so", "Confirm your email",
     "Welcome to Notion. Confirm your email to set up your workspace."),
    ("no-reply@duolingo.com", "Confirm your email and start learning",
     "Welcome! Confirm your email to begin your first lesson."),
    ("hello@figma.com", "Verify your Figma account",
     "Please verify your email address to activate your Figma account."),
    ("no-reply@dropbox.com", "Please verify your email",
     "Verify your email to finish setting up your Dropbox."),
    ("newsletter@nytimes.com", "Welcome to The Morning",
     "Thanks for subscribing. Confirm to start receiving The Morning newsletter."),
    ("no-reply@grammarly.com", "Activate your Grammarly account",
     "Activate your account to start writing with confidence."),
    ("welcome@mail.airbnb.com", "Confirm your email address",
     "Confirm your email to complete your Airbnb account setup."),
    ("no-reply@account.booking.com", "Verify your email address",
     "Verify your email address to manage your bookings."),
]
OTP_SECURITY = [
    ("security@paypal.com", "Your PayPal security code is 928174",
     "Your one-time security code is 928174. It expires in 5 minutes. Do not share it."),
    ("no-reply@accounts.google.com", "Your Google verification code",
     "Your verification code is 471920. Don't share this code with anyone."),
    ("alert@chase.com", "Your one-time passcode",
     "Your Chase one-time passcode is 552081. It expires in 10 minutes."),
    ("verify@coinbase.com", "Your Coinbase verification code",
     "Use code 330145 to verify your identity. This code expires shortly."),
    ("account-security@microsoft.com", "Security alert: new sign-in",
     "We detected a new sign-in to your Microsoft account. If this wasn't you, secure your account."),
]
SPOOFED_BANK = [
    ("alerts@icicibank.bank", "Your account OTP is 663201",
     "Your OTP for the transaction of Rs.45,000 is 663201. Valid for 3 minutes."),
    ("security@hdfc.bank", "Unusual activity detected on your account",
     "We noticed a login from a new device. Verify your identity immediately to avoid suspension."),
]
BUSINESS = [
    ("rohan.mehta@infosys.com", "Re: Q3 partnership review",
     "Hi, following up on the Q3 partnership numbers — can we sync sometime this week?"),
    ("priya.sharma@deloitte.com", "Contract draft for your review",
     "Please find the draft contract attached. Let me know your comments by Friday."),
    ("ops@company.com", "Team offsite — logistics & agenda",
     "Sharing the offsite agenda and travel details for next month. Please review."),
]


def _send(host, port, frm, rcpt, subject, body):
    from email.utils import formatdate
    msg = MIMEText(body)
    msg["From"] = frm
    msg["To"] = rcpt
    msg["Date"] = formatdate(localtime=True)
    msg["Subject"] = subject
    try:
        with smtplib.SMTP(host, port, timeout=60) as s:
            s.sendmail(frm, [rcpt], msg.as_bytes())
    except Exception as e:
        print(f"  ERR {frm}: {e}")


def _blast(host, port, rcpt, batch, tag):
    ts = [threading.Thread(target=_send, args=(host, port, f, rcpt, s, b)) for f, s, b in batch]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=90)
    print(f"  sent {len(batch):2d} x {tag}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rcpt", default="ceo@company.com")
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=8025)
    args = ap.parse_args()

    print(f"MIXED BOMB -> {args.host}:{args.port} -> {args.rcpt}\n")
    print("Phase 1: subscription burst (trips detection)")
    _blast(args.host, args.port, args.rcpt, SUBSCRIPTION, "subscription confirmations")
    time.sleep(3)
    print("Phase 2: the mix (triaged while under attack)")
    _blast(args.host, args.port, args.rcpt, OTP_SECURITY, "OTP / security codes")
    _blast(args.host, args.port, args.rcpt, SPOOFED_BANK, "spoofed .bank alerts")
    _blast(args.host, args.port, args.rcpt, BUSINESS, "business mail")
    total = len(SUBSCRIPTION) + len(OTP_SECURITY) + len(SPOOFED_BANK) + len(BUSINESS)
    print(f"\nDone — {total} emails sent. Watch: curl -s localhost:8000/health | python3 -m json.tool")


if __name__ == "__main__":
    main()
