"""Demo helper: fire a SUSPICIOUS email whose link the L3 sandbox detonates + screenshots,
showing the screenshot on the Pending Review card.

By default the link points at a LOCAL fake phishing-login page (served by this script), so
the captured screenshot looks like a real credential-harvest page — NOT just google.com.
It's our own page, so nothing malicious is actually hosted.

The sandbox only fires on a SUSPICIOUS email with a URL (a feed-flagged real bad URL would
be caught at L1 as phishing, before the sandbox). The content below is tuned to land
reliably in the suspicious band so L3 detonates every time.

Usage:
  PYTHONPATH=. python3 scripts/demo_sandbox.py                  # fake phishing-login page
  PYTHONPATH=. python3 scripts/demo_sandbox.py --url http://www.google.com   # any link
  PYTHONPATH=. python3 scripts/demo_sandbox.py --save shot.png

Then: Dashboard -> Pending Review -> hard-refresh -> open the new card -> 🧪 Sandbox Screenshot.
"""
import argparse
import os
import smtplib
import subprocess
import time
import urllib.request
from email.mime.text import MIMEText
from email.utils import formatdate

import httpx

APP = "http://localhost:8000"
SMTP_HOST, SMTP_PORT = "localhost", 8025
API_KEY = "dev-key"
PAGE_PORT = 8899
PAGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phish_page")
# The sandbox runs in a bridge container and reaches the host via host.docker.internal.
FAKE_URL = f"http://host.docker.internal:{PAGE_PORT}/verify.html"

G="\033[92m"; Y="\033[93m"; Rd="\033[91m"; C="\033[96m"; B="\033[1m"; D="\033[2m"; R="\033[0m"


def ensure_page_server():
    """Serve the local fake phishing-login page on PAGE_PORT if it isn't already up."""
    try:
        urllib.request.urlopen(f"http://localhost:{PAGE_PORT}/verify.html", timeout=3)
        return  # already serving
    except Exception:
        pass
    subprocess.Popen(
        ["python3", "-m", "http.server", str(PAGE_PORT), "--directory", PAGE_DIR],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(10):
        try:
            urllib.request.urlopen(f"http://localhost:{PAGE_PORT}/verify.html", timeout=2)
            print(f"{D}  (started fake-page server on :{PAGE_PORT}){R}")
            return
        except Exception:
            time.sleep(0.5)
    print(f"{Y}  warning: could not confirm fake-page server on :{PAGE_PORT}{R}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=FAKE_URL, help="link to detonate (default: local fake phishing page)")
    ap.add_argument("--rcpt", default=None)
    ap.add_argument("--save", default=None, help="save the captured screenshot to this path")
    args = ap.parse_args()

    if args.url == FAKE_URL:
        ensure_page_server()

    token = httpx.post(f"{APP}/token", json={"api_key": API_KEY, "role": "admin", "sub": "demo"}).json()["access_token"]
    H = {"Authorization": f"Bearer {token}"}

    # Mild-suspicious content (lands in the suspicious band most of the time -> L3 fires).
    # NLP scoring varies run-to-run, so we retry with a fresh recipient until one lands
    # suspicious AND captures a screenshot — guaranteeing one good card per invocation.
    def attempt():
        rcpt = args.rcpt or f"sandboxdemo_{int(time.time())}@company.com"
        body = (f"A document titled 'Account Statement' has been shared with you. "
                f"You can review it here: {args.url}")
        msg = MIMEText(body)
        msg["From"] = "team@docs-shared.net"; msg["To"] = rcpt
        msg["Date"] = formatdate(localtime=True)
        msg["Subject"] = "A document has been shared with you"
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=120) as s:
            s.sendmail(msg["From"], [rcpt], msg.as_bytes())
        # poll for it in pending
        scan_id = None
        for _ in range(14):
            items = httpx.get(f"{APP}/api/pending", headers=H, timeout=30).json().get("items", [])
            hit = [i for i in items if i["original_rcpt"] == rcpt]
            if hit:
                scan_id = hit[0]["scan_id"]; break
            time.sleep(3)
        if not scan_id:
            return None, rcpt, None  # drifted clean/phishing
        r = httpx.get(f"{APP}/api/scan/{scan_id}/screenshot", headers=H, timeout=30)
        if r.status_code == 200 and len(r.content) > 1000:
            return scan_id, rcpt, r.content
        return scan_id, rcpt, None

    MAX = 5
    for i in range(1, MAX + 1):
        print(f"{B}Attempt {i}/{MAX}:{R} sending suspicious email with link {args.url} ...")
        scan_id, rcpt, shot = attempt()
        if shot:
            print(f"  {G}✓ SUCCESS{R} held in Pending Review (scan {scan_id}), screenshot captured ({len(shot)} bytes)")
            if args.save:
                open(args.save, "wb").write(shot); print(f"    saved to {args.save}")
            print(f"\n{B}Show it:{R} Dashboard -> Pending Review -> hard-refresh -> open the newest "
                  f"'A document has been shared with you' card ({rcpt}) -> 🧪 Sandbox Screenshot")
            return
        reason = "verdict drifted (clean/phishing)" if not scan_id else "suspicious but no screenshot yet"
        print(f"  {Y}retry: {reason}{R}")
    print(f"{Rd}Could not capture after {MAX} attempts — re-run (the engine's NLP score varies).{R}")


if __name__ == "__main__":
    main()
