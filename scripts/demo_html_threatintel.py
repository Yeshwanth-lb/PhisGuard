"""Demo: HTML emails with real links + images, exercising the L1 THREAT-INTEL layer.

Unlike the plain-text demo (which is caught by NLP/structural heuristics), this sends
real HTML messages with <a href> links and <img> tags. The phishing samples carry URLs
that live reputation feeds actually flag, so you can show PhishGuard pulling the link out
of the HTML and confirming it malicious against VirusTotal + Google Safe Browsing.

  CLEAN       legit brand links + image            -> delivered
  SUSPICIOUS  shortened / odd link, mild urgency    -> held / borderline
  PHISHING    credential HTML + a feed-flagged URL  -> quarantined (L1 threat-intel)

The flagged URLs are GOOGLE'S OFFICIAL SAFE-BROWSING TEST PAGES — they register as
malicious in the feeds but are NOT real attacks. Safe to run live.

Two phases (same pattern as demo_phishing_15.py):
  1. ANALYZE  — POST each to /analyze and PRINT the L1 threat-intel hits (the showcase).
  2. SEND     — inject via SMTP :8025 so they route + appear in the dashboard.

Usage:
  PYTHONPATH=. python3 scripts/demo_html_threatintel.py            # analyze + show hits
  PYTHONPATH=. python3 scripts/demo_html_threatintel.py --send     # also inject via SMTP
  PYTHONPATH=. python3 scripts/demo_html_threatintel.py --send --offset 30
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

# Google Safe Browsing official TEST URLs — flagged by the feeds, not real attacks.
GSB_PHISH   = "http://testsafebrowsing.appspot.com/s/phishing.html"
GSB_MALWARE = "http://testsafebrowsing.appspot.com/s/malware.html"

# (intended, from, subject, html_body)
CASES = [
    # ── CLEAN — legitimate brand mail with a real link + image ───────────────
    ("clean", "newsletter@github.com", "Your weekly GitHub digest",
     '<html><body><h2>Your weekly digest</h2>'
     '<img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" width="48">'
     '<p>You have 3 new <a href="https://github.com/notifications">notifications</a>. '
     'Manage your <a href="https://github.com/settings/emails">email preferences</a>.</p>'
     '<p>Happy coding,<br>The GitHub Team</p></body></html>'),
    ("clean", "no-reply@atlassian.net", "Jira: 2 issues assigned to you",
     '<html><body><img src="https://wac-cdn.atlassian.com/dam/jcr:logo.png" width="40">'
     '<p>Two issues were assigned to you this week. '
     '<a href="https://your-team.atlassian.net/jira/your-work">Open your board</a>.</p></body></html>'),

    # ── SUSPICIOUS — borderline: shortened link + mild urgency, no feed hit ───
    ("suspicious", "promo@deals-mailer.net", "Your $50 reward is waiting",
     '<html><body><p>You have been selected for a reward. '
     'Claim within 24 hours: <a href="https://bit.ly/3xReward9">Claim your $50</a></p>'
     '<img src="http://deals-mailer.net/open.gif" width="1" height="1"></body></html>'),
    ("suspicious", "billing@account-renew-center.com", "Action required: confirm your billing",
     '<html><body><p>We could not process your payment. '
     'Please <a href="http://account-renew-center.com/billing">update your billing details</a> '
     'to avoid interruption.</p></body></html>'),

    # ── PHISHING — credential HTML carrying a feed-flagged URL ────────────────
    ("phishing", "security@paypa1-secure.com", "Your account is suspended - verify now",
     '<html><body><img src="http://paypa1-secure.com/paypal-logo.png" width="120">'
     '<p>Your account has been limited due to suspicious activity. '
     f'<a href="{GSB_PHISH}">Verify your password now</a> or your account will be permanently closed.</p>'
     '</body></html>'),
    ("phishing", "it-helpdesk@office365-reset.com", "Your password expires TODAY",
     '<html><body><img src="http://office365-reset.com/ms-logo.png" width="100">'
     '<p>Your company password expires today. '
     f'<a href="{GSB_PHISH}">Reset it here</a> using your current credentials to avoid lockout.</p></body></html>'),
    ("phishing", "alerts@secure-docs-delivery.com", "You have a secure document",
     '<html><body><p>A document is waiting for you. '
     f'Download the <a href="{GSB_MALWARE}">secure viewer</a> to open it.</p></body></html>'),
]


def raw_html(frm, rcpt, subj, html):
    msg = MIMEText(html, "html", "utf-8")
    msg["From"] = frm
    msg["To"] = rcpt
    msg["Date"] = formatdate(localtime=True)
    msg["Subject"] = subj
    return msg


def analyze(client, token, frm, subj, html):
    msg = raw_html(frm, "ceo@company.com", subj, html)
    try:
        r = client.post(f"{APP}/analyze", headers={"Authorization": f"Bearer {token}"},
                        json={"raw_email": msg.as_string(), "subject": subj})
        if r.status_code != 200:
            return {"verdict": None, "err": f"http_{r.status_code}"}
        d = r.json()
        l1 = d.get("l1") or {}
        l2 = d.get("l2") or {}
        return {"verdict": d.get("verdict"), "conf": round(float(d.get("confidence") or 0), 3),
                "l1_verdict": l1.get("verdict"), "hits": l1.get("hits") or [],
                "l2": l2.get("engine_scores")}
    except Exception as exc:
        return {"verdict": None, "err": str(exc)[:80]}


def send_smtp(msg, frm, rcpt):
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=90) as s:
        s.sendmail(frm, [rcpt], msg.as_bytes())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--send", action="store_true", help="inject via SMTP :8025 after analysis")
    ap.add_argument("--offset", type=int, default=30, help="recipient number offset (-> htmlN@)")
    args = ap.parse_args()

    color = {"clean": G, "suspicious": Y, "phishing": Rd}
    token = httpx.post(f"{APP}/token", json={"api_key": API_KEY, "role": "admin", "sub": "demo"}).json()["access_token"]
    client = httpx.Client(timeout=120)

    print(f"{B}Phase 1 — analyze HTML emails (links + images), show L1 threat-intel{R}\n")
    for intended, frm, subj, html in CASES:
        a = analyze(client, token, frm, subj, html)
        v = a.get("verdict") or f"ERR({a.get('err')})"
        col = color.get(v, D)
        print(f"{col}{B}{intended.upper():<11}{R} verdict={col}{v}{R} conf={a.get('conf')}  {D}{subj[:48]}{R}")
        mal_hits = [h for h in (a.get("hits") or []) if h.get("malicious")]
        if mal_hits:
            for h in mal_hits:
                src = str(h.get("source") or "?"); ioc = h.get("ioc") or ""
                sc = h.get("score"); sc_s = sc if sc is not None else "-"
                print(f"     {C}↳ threat-intel{R} {src:<20} {Rd}MALICIOUS{R} score={sc_s}  {D}{ioc}{R}")
        else:
            print(f"     {D}↳ no malicious feed hits (clean, or caught by heuristics){R}")
        print()

    if not args.send:
        print(f"{D}Analysis only. Re-run with --send to inject via SMTP :8025.{R}")
        return

    print(f"{B}Phase 2 — inject via SMTP :8025 (distinct recipients, no bombing trip){R}\n")
    n = args.offset
    for intended, frm, subj, html in CASES:
        n += 1
        rcpt = f"html{n}@company.com"
        try:
            send_smtp(raw_html(frm, rcpt, subj, html), frm, rcpt)
            print(f"  {color[intended]}{intended:<11}{R}-> {rcpt:<20} {D}{subj[:42]}{R}")
        except Exception as exc:
            print(f"  {Rd}FAILED{R} {intended} {subj[:36]}: {exc}")
        time.sleep(0.5)

    print(f"\n{G}✓ sent {len(CASES)} HTML emails.{R}")
    print(f"{D}  clean → inbox · suspicious → Pending Review · phishing → Quarantine (with L1 feed hits)")
    print(f"  Dashboard: {APP}/  → open a quarantined item to show the VirusTotal / Safe-Browsing IOC.{R}")


if __name__ == "__main__":
    main()
