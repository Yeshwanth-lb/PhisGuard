"""Paste an email in the terminal -> send it through PhishGuard -> see the verdict.

Usage:
  PYTHONPATH=. python3 scripts/send_mail.py
  ...then PASTE the email (headers + blank line + body), and press Ctrl-D when done:

      From: security@some-bank.com
      To: john@company.com
      Subject: Your account is suspended - verify now

      Verify here: http://secure-verify-login.com

  (You can also paste just a body with no headers — it'll add defaults.)
"""
import re
import sys
import smtplib
from email.mime.text import MIMEText
from email.utils import formatdate
from email import policy

import httpx

APP = "http://localhost:8000"
G="\033[92m"; Y="\033[93m"; Rd="\033[91m"; C="\033[96m"; B="\033[1m"; D="\033[2m"; R="\033[0m"


def main():
    print(f"{B}Paste the email (From:/To:/Subject:, blank line, then body — put any URL in the body).{R}")
    print(f"{B}When done, type a single dot (.) on its own line and press Enter:{R}")
    lines = []
    for line in sys.stdin:
        if line.rstrip("\n") == ".":
            break
        lines.append(line)
    pasted = "".join(lines).strip()
    if not pasted:
        print(f"{Rd}nothing pasted.{R}"); return

    # Split headers from body (if the paste has a header block).
    frm, to, subj, body = "test-sender@example.com", "demo@company.com", "(no subject)", pasted
    if re.match(r"(?im)^(from|to|subject)\s*:", pasted) and "\n\n" in pasted:
        head, body = pasted.split("\n\n", 1)
        for line in head.splitlines():
            if re.match(r"(?i)^from\s*:", line):    frm  = line.split(":", 1)[1].strip()
            elif re.match(r"(?i)^to\s*:", line):    to   = line.split(":", 1)[1].strip()
            elif re.match(r"(?i)^subject\s*:", line): subj = line.split(":", 1)[1].strip()

    m = MIMEText(body, "plain", "utf-8")
    m["From"] = frm; m["To"] = to; m["Subject"] = subj; m["Date"] = formatdate(localtime=True)
    raw = m.as_string()
    env = (re.search(r"[\w.+-]+@[\w.-]+", frm) or [None])
    env_from = re.search(r"[\w.+-]+@[\w.-]+", frm); env_from = env_from.group(0) if env_from else "x@example.com"
    env_to = re.search(r"[\w.+-]+@[\w.-]+", to); env_to = env_to.group(0) if env_to else "demo@company.com"

    print(f"\n{D}From: {frm}  |  Subject: {subj}{R}")

    # 1) Verdict (the WHY) via /analyze
    try:
        tok = httpx.post(f"{APP}/token", json={"api_key": "dev-key"}, timeout=15).json()["access_token"]
        d = httpx.post(f"{APP}/analyze", headers={"Authorization": f"Bearer {tok}"},
                       json={"raw_email": raw, "subject": subj}, timeout=120).json()
        v = d.get("verdict"); col = {"clean": G, "suspicious": Y, "phishing": Rd}.get(v, R)
        l2 = d.get("l2") or {}; nlp = (l2.get("engines") or {}).get("nlp") or {}
        print(f"\n  {B}VERDICT:{R} {col}{v}{R}  (confidence {d.get('confidence')})")
        print(f"  engines: {l2.get('engine_scores')}")
        if nlp.get("tactics"): print(f"  tactics: {nlp.get('tactics')}  | intent: {nlp.get('intent')}")
    except Exception as exc:
        print(f"  {Rd}analyze error: {exc}{R}")

    # 2) Send through the SMTP gateway (real routing -> inbox/Pending/Quarantine)
    try:
        s = smtplib.SMTP("localhost", 8025, timeout=90)
        ok = s.sendmail(env_from, [env_to], m.as_bytes(policy=policy.SMTP)) == {}
        s.quit()
        print(f"\n  {G}sent via SMTP gateway (accepted={ok}){R} -> check the dashboard for routing")
    except Exception as exc:
        print(f"  {Rd}smtp error: {exc}{R}")


if __name__ == "__main__":
    main()
