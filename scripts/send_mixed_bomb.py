"""Demo: a REALISTIC mixed email bomb against the live gateway (port 8025).

Sends a variety of mail during the flood so the demo shows the engine's ASYMMETRIC
triage — each category lands in a different tier with a different outcome:

  SUBSCRIPTION  -> Tier 2 noise      -> buffered, "[Possible Bombing Noise]"
  OTP/SECURITY  -> Tier 3 uncertain  -> buffered, "[Received During Mail Bomb]"
     (high-signal SUBJECT but UNauthenticated sender — delivered + soft-labeled,
      NOT fast-tracked: this is the throwaway-domain fake-OTP being denied trust)
  SPOOFED BANK  -> spoofed_critical  -> QUARANTINED (claims .bank, no valid DKIM)
  BUSINESS      -> Tier 3 uncertain  -> delivered, "[Received During Mail Bomb]"

Phase 1 fires the subscription burst to trip detection; phase 2 fires the mix so it's
triaged while the inbox is in bombing mode.
"""
import argparse
import smtplib
import threading
import time
from email.mime.text import MIMEText

SUBSCRIPTION = [
    ("noreply@amazon-deals.shop",     "Confirm your email address"),
    ("verify@github-mailer.io",       "Please verify your email"),
    ("welcome@shopify-store.co",      "Welcome to our store"),
    ("hello@medium-digest.net",       "Thanks for signing up"),
    ("signup@coursera-mail.org",      "Complete your registration"),
    ("activate@spotify-promo.com",    "Activate your account"),
    ("noreply@netflix-offers.tv",     "Confirm your subscription"),
    ("welcome@linkedin-jobs.biz",     "Welcome — please verify your email"),
    ("verify@reddit-updates.app",     "Verify your account now"),
    ("noreply@pinterest-pins.co",     "One more step to finish signup"),
    ("hello@canva-design.io",         "Confirm your email to get started"),
    ("signup@duolingo-learn.net",     "Thanks for joining — verify your account"),
    ("welcome@notion-team.so",        "Welcome! Confirm your registration"),
    ("noreply@figma-files.design",    "Please confirm your email"),
    ("activate@dropbox-share.cloud",  "Activate your new account"),
]
OTP_SECURITY = [
    ("otp@paytm-secure.app",          "Your OTP code is 482913"),
    ("noreply@razorpay-auth.io",      "Your verification code: 90210"),
    ("security@google-accounts.co",   "Security alert: new sign-in to your account"),
    ("no-reply@apple-id.support",     "Your Apple ID one-time passcode is 771234"),
    ("alerts@bank-notify.net",        "Password reset requested for your account"),
]
SPOOFED_BANK = [
    ("alerts@hdfcbank.bank",          "Your OTP for the transaction is 553210"),
    ("security@sbi.bank",             "Unusual activity detected on your account"),
]
BUSINESS = [
    ("alice@partnerco.com",           "Re: Q3 budget review"),
    ("bob@vendor-supply.io",          "Can we reschedule Thursday's call?"),
    ("pm@bigclient.com",              "Project status update — week 26"),
]


def _send(host, port, frm, rcpt, subject, tag):
    msg = MIMEText(f"PhishGuard mixed-bomb demo ({tag}) — safe to delete.")
    msg["From"] = frm
    msg["To"] = rcpt
    msg["Subject"] = subject
    try:
        with smtplib.SMTP(host, port, timeout=60) as s:
            s.sendmail(frm, [rcpt], msg.as_bytes())
    except Exception as e:
        print(f"  ERR {tag} {frm}: {e}")


def _blast(host, port, rcpt, batch, tag):
    ts = [threading.Thread(target=_send, args=(host, port, f, rcpt, s, tag)) for f, s in batch]
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
    _blast(args.host, args.port, args.rcpt, SUBSCRIPTION, "SUBSCRIPTION->Tier2 noise")
    time.sleep(3)   # let bombing mode engage
    print("Phase 2: the mix (triaged while under attack)")
    _blast(args.host, args.port, args.rcpt, OTP_SECURITY, "OTP/SECURITY->Tier3 (not fast-tracked)")
    _blast(args.host, args.port, args.rcpt, SPOOFED_BANK, "SPOOFED .bank->QUARANTINE")
    _blast(args.host, args.port, args.rcpt, BUSINESS, "BUSINESS->Tier3 uncertain")
    total = len(SUBSCRIPTION) + len(OTP_SECURITY) + len(SPOOFED_BANK) + len(BUSINESS)
    print(f"\nDone — {total} emails sent. Watch: curl -s localhost:8000/health | python3 -m json.tool")


if __name__ == "__main__":
    main()
