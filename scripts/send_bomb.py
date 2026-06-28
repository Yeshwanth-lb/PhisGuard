"""Demo: fire an email bomb at the live PhishGuard SMTP gateway (port 8025).

Sends N subscription-style emails CONCURRENTLY to one recipient — fast arrival trips the
velocity window, the engine flips to bombing mode, and Tier-2/3 mail is buffered then
released LABELED after the analysis window.

Usage:
    python3 scripts/send_bomb.py                 # 30 emails to victim@company.com
    python3 scripts/send_bomb.py --count 40 --rcpt victim@company.com
Watch it:
    curl -s localhost:8000/health | python3 -m json.tool   # bombing_detector + bombing_buffer
    docker logs -f phishguard-app | grep -iE "bombing"
"""
import argparse
import smtplib
import threading
from email.mime.text import MIMEText

SUBJECTS = [
    "Confirm your email address", "Please verify your email", "Welcome to our store",
    "Thanks for signing up", "Complete your registration", "Activate your account",
    "Verify your account now", "One more step to finish signup",
    "Confirm your subscription", "Welcome — please verify",
]


def _send(host, port, frm, rcpt, subject, results, idx):
    msg = MIMEText("PhishGuard bombing demo email — safe to delete.")
    msg["From"] = frm
    msg["To"] = rcpt
    msg["Subject"] = "[DEMO-BOMB] " + subject
    try:
        with smtplib.SMTP(host, port, timeout=60) as s:
            s.sendmail(frm, [rcpt], msg.as_bytes())
        results[idx] = True
    except Exception as e:
        results[idx] = f"ERR {e}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=30)
    ap.add_argument("--rcpt", default="victim@company.com")
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=8025)
    args = ap.parse_args()

    print(f"Firing {args.count} bombing emails at {args.host}:{args.port} -> {args.rcpt}")
    results = [None] * args.count
    threads = []
    for i in range(args.count):
        frm = f"noreply@promo-{i:02d}.example.com"          # distinct domains (high diversity)
        subj = SUBJECTS[i % len(SUBJECTS)]
        t = threading.Thread(target=_send, args=(args.host, args.port, frm, args.rcpt, subj, results, i))
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=90)

    ok = sum(1 for r in results if r is True)
    print(f"accepted: {ok}/{args.count}")
    errs = [r for r in results if r not in (True, None)]
    if errs:
        print("errors:", errs[:5])


if __name__ == "__main__":
    main()
