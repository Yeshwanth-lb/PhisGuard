#!/usr/bin/env python3
"""Simple direct-to-gateway sender for the demo. No copy-paste needed.

Usage:
  python3 scripts/lead_send.py                       # localhost, sends clean+suspicious+phishing
  python3 scripts/lead_send.py 192.168.32.94         # from another device, point at the Mac's IP
  python3 scripts/lead_send.py localhost phishing     # send only one kind
"""
import smtplib
import sys
import time
from email.mime.text import MIMEText

HOST = sys.argv[1] if len(sys.argv) > 1 else "localhost"
ONLY = sys.argv[2] if len(sys.argv) > 2 else None
PORT = 8025
STAMP = str(int(time.time()))   # unique recipient suffix so each run is fresh

MAILS = {
    "clean": ("rohan.mehta@infosys.com", "Re: Q3 partnership review",
              "Hi, following up on the Q3 numbers. Can we sync this week? Thanks, Rohan"),
    "suspicious": ("billing@account-update-center.com", "Action required: confirm your billing details",
                   "We couldn't process your payment. Update here: http://account-update-center.com/billing"),
    "phishing": ("security@paypa1-secure.com", "Your account is suspended - verify now",
                 "Your account is limited. Verify now: http://paypa1-secure-login.com/verify"),
}

kinds = [ONLY] if ONLY in MAILS else list(MAILS)
print("sending to %s:%d ..." % (HOST, PORT))
for i, kind in enumerate(kinds, 1):
    frm, subj, body = MAILS[kind]
    to = "leadtest_%s_%d@company.com" % (STAMP, i)
    m = MIMEText(body)
    m["From"] = frm
    m["To"] = to
    m["Subject"] = subj
    try:
        s = smtplib.SMTP(HOST, PORT, timeout=60)
        ok = s.sendmail(frm, [to], m.as_bytes()) == {}
        s.quit()
        print("  %-11s -> %-28s accepted=%s" % (kind, to, ok))
    except Exception as exc:
        print("  %-11s FAILED: %s" % (kind, exc))
