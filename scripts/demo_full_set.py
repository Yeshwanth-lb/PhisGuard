"""ONE-COMMAND demo set: 5 clean + 5 suspicious + 5 phishing, where exactly ONE of the
suspicious emails carries a link that the L3 sandbox detonates + screenshots.

Routing you'll show:
  5 clean      -> Gmail inbox (PhishGuard-Delivered)
  5 suspicious -> Pending Review   (1 of them has a 🧪 Sandbox Screenshot of the link)
  5 phishing   -> Quarantine

The sandbox only fires on a SUSPICIOUS email with a URL (L2 conf >= 0.45); a feed-flagged
"bad" URL would be caught at L1 as phishing (no sandbox), so the screenshot email uses a
resolvable link (default google.com) that the sandbox safely renders in isolation.

Usage:
  PYTHONPATH=. python3 scripts/demo_full_set.py
  PYTHONPATH=. python3 scripts/demo_full_set.py --offset 200 --sandbox-url http://example.com
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
G="\033[92m"; Y="\033[93m"; Rd="\033[91m"; C="\033[96m"; B="\033[1m"; D="\033[2m"; R="\033[0m"

CLEAN = [
    ("rohan.mehta@infosys.com", "Re: Q3 partnership review",
     "Hi, following up on the Q3 numbers. Can we sync this week? Thanks, Rohan"),
    ("priya.sharma@company.com", "Notes from this morning's standup",
     "Sharing the standup notes. Backend API on track, design review moved to Thursday."),
    ("orders@bigbasket.com", "Your order #BB48213 has been delivered",
     "Your order was delivered today at 2:14 PM. Thanks for shopping with us."),
    ("hr@company.com", "Reminder: submit your timesheet by Friday",
     "A friendly reminder to submit your timesheet for this week by end of day Friday."),
    ("newsletter@morningbrew.com", "The Morning Brew: markets, tech, and a good read",
     "Good morning. Today: markets edged higher, a new chip launch, and a founder profile."),
]

# 4 content-only suspicious (no link -> no detonation)
SUSPICIOUS = [
    ("team@docs-shared.net", "A document has been shared with you",
     "A document titled 'Q3 Budget' has been shared with you. Please review it at your earliest convenience to keep the project on track."),
    ("alerts@my-account-security.com", "Unusual sign-in detected",
     "We noticed a new sign-in to your account from an unrecognized device. If this wasn't you, please review your recent activity right away."),
    ("noreply@delivery-notice.net", "Your package could not be delivered",
     "We attempted delivery but no one was available. Please reschedule your delivery within 48 hours or it will be returned."),
    ("rewards@survey-prize.co", "You're eligible for a $50 reward",
     "Congratulations! You have been selected for a $50 reward. Complete a short verification to claim it before it expires."),
]

# The ONE suspicious email with a link the sandbox detonates + screenshots
def sandbox_case(url):
    return ("alerts@account-review-portal.com", "Action required: review your account activity",
            f"Unusual sign-in detected on your account. Verify your identity immediately to avoid "
            f"suspension: {url}  Please act within 24 hours.")

PHISHING = [
    ("security@paypa1-secure.com", "Your account is suspended - verify now",
     "Your account has been limited due to suspicious activity. Verify immediately or your account will be permanently closed: http://paypa1-secure-login.com/verify"),
    ("alert@hdfc-bank-secure.com", "Unusual login - confirm your identity immediately",
     "We detected a login from an unknown device. Confirm your netbanking credentials now to avoid suspension: http://hdfc-bank-secure.com/login"),
    ("it-helpdesk@office365-reset.com", "Your password expires TODAY - reset required",
     "Your company password expires today. Reset it now using your current credentials: http://office365-reset.com/pwd"),
    ("rewards@amaz0n-giftcard.com", "Congratulations! You've won a $1000 gift card",
     "You have been selected to receive a $1000 Amazon gift card. Claim within 24 hours: http://amaz0n-giftcard.com/claim"),
    ("docusign@secure-esign-doc.com", "You have a document waiting for signature",
     "An urgent document requires your signature. Sign in with your email and password to view: http://secure-esign-doc.com/sign"),
]


def send(frm, rcpt, subj, body):
    m = MIMEText(body); m["From"]=frm; m["To"]=rcpt; m["Date"]=formatdate(localtime=True); m["Subject"]=subj
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=120) as s:
        s.sendmail(frm, [rcpt], m.as_bytes())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offset", type=int, default=200)
    ap.add_argument("--sandbox-url", default="http://www.google.com")
    args = ap.parse_args()

    token = httpx.post(f"{APP}/token", json={"api_key":API_KEY,"role":"admin","sub":"demo"}).json()["access_token"]
    H={"Authorization":f"Bearer {token}"}
    n = args.offset
    sandbox_rcpt = None

    print(f"{B}Sending demo set (5 clean, 5 suspicious incl. 1 sandbox, 5 phishing)...{R}\n")

    for frm,subj,body in CLEAN:
        n+=1; r=f"set{n}@company.com"; send(frm,r,subj,body); print(f"  {G}clean     {R} -> {r}  {D}{subj[:34]}{R}")
    for frm,subj,body in SUSPICIOUS:
        n+=1; r=f"set{n}@company.com"; send(frm,r,subj,body); print(f"  {Y}suspicious{R} -> {r}  {D}{subj[:34]}{R}")
    # the sandbox-screenshot suspicious email
    n+=1; sandbox_rcpt=f"set{n}@company.com"
    frm,subj,body = sandbox_case(args.sandbox_url)
    send(frm,sandbox_rcpt,subj,body); print(f"  {Y}suspicious{R} -> {sandbox_rcpt}  {C}{subj[:30]} [SANDBOX: {args.sandbox_url}]{R}")
    for frm,subj,body in PHISHING:
        n+=1; r=f"set{n}@company.com"; send(frm,r,subj,body); print(f"  {Rd}phishing  {R} -> {r}  {D}{subj[:34]}{R}")

    print(f"\n{D}Waiting for the sandbox detonation on {sandbox_rcpt} (~20-30s)...{R}")
    scan_id=None
    for _ in range(12):
        items = httpx.get(f"{APP}/api/pending",headers=H,timeout=30).json().get("items",[])
        hit=[i for i in items if i["original_rcpt"]==sandbox_rcpt]
        if hit: scan_id=hit[0]["scan_id"]; break
        time.sleep(3)
    if scan_id:
        d=httpx.get(f"{APP}/api/scan/{scan_id}",headers=H,timeout=30).json()
        l3=(d.get("data") or {}).get("l3") or {}
        rs=httpx.get(f"{APP}/api/scan/{scan_id}/screenshot",headers=H,timeout=30)
        ok = rs.status_code==200 and len(rs.content)>1000
        print(f"  {G if ok else Rd}sandbox screenshot: {'CAPTURED' if ok else 'not available'}{R}"
              f"  (detonated {l3.get('detonated_url')} -> {l3.get('title')})")
    else:
        print(f"  {Y}sandbox email not found in pending yet — check the dashboard in a moment.{R}")

    print(f"\n{B}Show it:{R} clean -> Gmail (PhishGuard-Delivered) · "
          f"suspicious -> Pending Review (open {sandbox_rcpt} for the 🧪 Sandbox Screenshot) · phishing -> Quarantine")
    print(f"{D}(hard-refresh the dashboard){R}")


if __name__ == "__main__":
    main()
