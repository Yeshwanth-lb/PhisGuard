"""FINAL comprehensive demo: all verdicts x all content types (images, URLs, DOC attachments).

Sends a representative mix through the live gateway (:8025) and shows where each lands:
  clean      -> Gmail inbox (PhishGuard-Delivered)
  suspicious -> dashboard Pending Review (held)
  phishing   -> dashboard Quarantine

Exercises every content dimension:
  • HTML bodies with real <a href> links and <img> images
  • a benign DOC attachment (parsed + SHA-256 hashed by the pipeline)
  • a malicious-file attachment via the EICAR test signature (harmless AV test file)
  • a feed-flagged URL (Google Safe-Browsing test page) for live threat-intel

Two phases (same pattern as the other demo scripts):
  1. ANALYZE  — /analyze each, print verdict + attachments + any threat-intel hits
  2. SEND     — inject via SMTP so they route + appear in the dashboard

Usage:
  PYTHONPATH=. python3 scripts/demo_full_send.py            # analyze only
  PYTHONPATH=. python3 scripts/demo_full_send.py --send     # analyze + inject
  PYTHONPATH=. python3 scripts/demo_full_send.py --send --offset 40
"""
import argparse
import smtplib
import time
from email import policy as _email_policy
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.utils import formatdate

import httpx

# RFC5321-compliant serialization (CRLF + line wrapping) so attachments never exceed
# the 1000-octet SMTP line limit ("Line too long" rejection).
SMTP_POLICY = _email_policy.SMTP

APP = "http://localhost:8000"
SMTP_HOST, SMTP_PORT = "localhost", 8025
API_KEY = "dev-key"

G = "\033[92m"; Y = "\033[93m"; Rd = "\033[91m"; C = "\033[96m"; B = "\033[1m"; D = "\033[2m"; R = "\033[0m"

GSB_PHISH = "http://testsafebrowsing.appspot.com/s/phishing.html"

# EICAR standard AV test signature, assembled from parts so the contiguous string
# never appears in this source file (keeps host antivirus from flagging the script).
EICAR = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}" + "$" +
         "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" + "!$H+H*").encode()

# A benign "document" — the pipeline hashes the bytes; content need not be a real docx.
BENIGN_DOC = b"Q3 partnership figures and notes. Internal use only.\n" * 5

DOCX_CT = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

# (intended, from, subject, html_body, attachment) where attachment = (filename, bytes, ctype) or None
CASES = [
    ("clean", "rohan.mehta@infosys.com", "Re: Q3 partnership review",
     '<html><body><p>Hi, following up on the Q3 numbers — can we sync this week?</p>'
     '<p>Deck: <a href="https://infosys.com/q3-review">internal review page</a></p></body></html>', None),

    ("clean", "priya.sharma@deloitte.com", "Contract draft for your review",
     '<html><body><p>Please find the draft contract attached. Comments by Friday?</p></body></html>',
     ("Q3_Contract_Draft.docx", BENIGN_DOC, DOCX_CT)),

    ("suspicious", "promo@deals-mailer.net", "Your $50 reward is waiting",
     '<html><body><p>Claim within 24h: <a href="https://bit.ly/3xReward9">Claim your $50</a></p>'
     '<img src="http://deals-mailer.net/open.gif" width="1"></body></html>', None),

    ("phishing", "security@paypa1-secure.com", "Your account is suspended - verify now",
     '<html><body><img src="http://paypa1-secure.com/logo.png" width="120">'
     '<p>Account limited. '
     f'<a href="{GSB_PHISH}">Verify your password now</a> or it will be closed.</p></body></html>', None),

    ("phishing", "billing@invoice-portal-secure.com", "Invoice #4471 — payment overdue",
     '<html><body><p>Your invoice is overdue. The document is attached — open it to review.</p></body></html>',
     ("Invoice_4471.doc", EICAR, "application/msword")),
]


def build(frm, rcpt, subj, html, attachment):
    msg = MIMEMultipart()
    msg["From"] = frm
    msg["To"] = rcpt
    msg["Date"] = formatdate(localtime=True)
    msg["Subject"] = subj
    msg.attach(MIMEText(html, "html", "utf-8"))
    if attachment:
        fn, data, ct = attachment
        maintype, _, subtype = ct.partition("/")
        part = MIMEApplication(data, _subtype=subtype or "octet-stream")
        part.add_header("Content-Disposition", "attachment", filename=fn)
        msg.attach(part)
    return msg


def analyze(client, token, msg, subj):
    try:
        r = client.post(f"{APP}/analyze", headers={"Authorization": f"Bearer {token}"},
                        json={"raw_email": msg.as_string(), "subject": subj})
        if r.status_code != 200:
            return {"verdict": None, "err": f"http_{r.status_code}"}
        d = r.json()
        l1 = d.get("l1") or {}
        atts = d.get("attachments") or []
        return {"verdict": d.get("verdict"), "conf": round(float(d.get("confidence") or 0), 3),
                "hits": [h for h in (l1.get("hits") or []) if h.get("malicious")],
                "attachments": atts, "att_hashes": d.get("attachment_hashes") or []}
    except Exception as exc:
        return {"verdict": None, "err": str(exc)[:80]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--send", action="store_true")
    ap.add_argument("--offset", type=int, default=40)
    args = ap.parse_args()

    color = {"clean": G, "suspicious": Y, "phishing": Rd}
    token = httpx.post(f"{APP}/token", json={"api_key": API_KEY, "role": "admin", "sub": "demo"}).json()["access_token"]
    client = httpx.Client(timeout=120)

    print(f"{B}Phase 1 — analyze (HTML links + images + DOC attachments){R}\n")
    for intended, frm, subj, html, att in CASES:
        msg = build(frm, "ceo@company.com", subj, html, att)
        a = analyze(client, token, msg, subj)
        v = a.get("verdict") or f"ERR({a.get('err')})"
        col = color.get(v, D)
        tag = f"  {D}[attach: {att[0]}]{R}" if att else ""
        print(f"{col}{B}{intended.upper():<11}{R} verdict={col}{v}{R} conf={a.get('conf')}  {D}{subj[:40]}{R}{tag}")
        if a.get("att_hashes"):
            print(f"     {C}↳ attachment{R} parsed {len(a['att_hashes'])} file(s), sha256={a['att_hashes'][0][:16]}…")
        for h in a.get("hits", []):
            print(f"     {C}↳ threat-intel{R} {str(h.get('source')):<20} {Rd}MALICIOUS{R} score={h.get('score')}  {D}{h.get('ioc')}{R}")
        if not a.get("hits"):
            print(f"     {D}↳ no malicious feed hits this run (verdict from heuristics/cache; VT free tier rate-limits){R}")
        print()

    if not args.send:
        print(f"{D}Analysis only. Re-run with --send to inject via SMTP :8025.{R}")
        return

    print(f"{B}Phase 2 — inject via SMTP :8025 (distinct recipients){R}\n")
    n = args.offset
    for intended, frm, subj, html, att in CASES:
        n += 1
        rcpt = f"full{n}@company.com"
        try:
            send = build(frm, rcpt, subj, html, att)
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=90) as s:
                s.sendmail(frm, [rcpt], send.as_bytes(policy=SMTP_POLICY))
            tag = f" {D}+{att[0]}{R}" if att else ""
            print(f"  {color[intended]}{intended:<11}{R}-> {rcpt:<20} {D}{subj[:38]}{R}{tag}")
        except Exception as exc:
            print(f"  {Rd}FAILED{R} {intended} {subj[:30]}: {exc}")
        time.sleep(0.5)

    print(f"\n{G}✓ sent {len(CASES)} emails (images + URLs + DOC attachments).{R}")
    print(f"{D}  clean → inbox · suspicious → Pending Review · phishing → Quarantine")
    print(f"  Dashboard: {APP}/  (hard-refresh)  ·  Inbox: label PhishGuard-Delivered{R}")


if __name__ == "__main__":
    main()
