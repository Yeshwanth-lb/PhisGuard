"""Realistic email-bomb demo: ~28 messages delivered to the real Gmail inbox at once,
showing the full asymmetric response with every label type:

  [PhishGuard-Priority]         authenticated bank OTPs   -> delivered instantly (Tier 1)
  [Possible Bombing Noise]      newsletter/signup flood   -> buffered, released labeled (Tier 2)
  [Received During Mail Bomb]   business mail             -> buffered, released labeled (Tier 3)
  [PHISHGUARD QUARANTINE ...]   spoofed .bank             -> quarantined (shown for visibility)

A real bomb is mostly NOISE burying a few real alerts — that's the point. Only the DKIM of
the authenticated OTPs is simulated offline; everything else runs the committed engine.
"""
import os
import tempfile

os.environ["PHISHGUARD_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "alllabels.db")
os.environ["BOMBING_ANALYSIS_WINDOW_SECS"] = "0"

import app.security.bombing_detector as bd          # noqa: E402
import app.security.bombing_pipeline as bp          # noqa: E402
import app.layer7_gmail.smtp_receiver as receiver   # noqa: E402
from app.layer7_gmail.gmail_client import deliver_to_inbox  # noqa: E402
from app.config import settings                     # noqa: E402

VICTIM = "victim@company.com"
G = "\033[92m"; Y = "\033[93m"; Rd = "\033[91m"; B = "\033[1m"; D = "\033[2m"; R = "\033[0m"; C = "\033[96m"

NOISE = [  # newsletter/signup flood -> Tier 2 (with List-Unsubscribe)
    ("no-reply@accounts.spotify.com", "Confirm your email address"),
    ("newsletter@e.medium.com", "Welcome to Medium"),
    ("no-reply@substack.com", "Confirm your subscription"),
    ("hello@mail.canva.com", "Verify your email to get started"),
    ("no-reply@quora.com", "Please confirm your email"),
    ("updates@reddit.com", "Verify your Reddit email address"),
    ("no-reply@coursera.org", "Welcome to Coursera — confirm your email"),
    ("team@notion.so", "Confirm your email"),
    ("no-reply@duolingo.com", "Confirm your email and start learning"),
    ("hello@figma.com", "Verify your Figma account"),
    ("no-reply@dropbox.com", "Please verify your email"),
    ("newsletter@nytimes.com", "Welcome to The Morning"),
    ("no-reply@grammarly.com", "Activate your Grammarly account"),
    ("welcome@mail.airbnb.com", "Confirm your email address"),
    ("no-reply@account.booking.com", "Verify your email address"),
    ("news@pinterest.com", "Confirm your email to get started"),
    ("no-reply@slack.com", "Confirm your email address"),
    ("no-reply@zoom.us", "Activate your Zoom account"),
    ("welcome@adobe.com", "Verify your Adobe ID"),
    ("no-reply@shopify.com", "Confirm your email to finish signup"),
    ("no-reply@instagram.com", "Confirm your email address"),
    ("verify@x.com", "Verify your email"),
    ("noreply@github.com", "Please verify your email address"),
    ("noreply@gitlab.com", "Confirm your email"),
    ("no-reply@trello.com", "Confirm your Trello account"),
    ("welcome@asana.com", "Verify your Asana email"),
]
UNCERTAIN = [  # known business contacts -> Tier 3
    ("rohan.mehta@infosys.com", "infosys.com", "Re: Q3 partnership review",
     "Following up on the Q3 numbers — can we sync this week?"),
    ("priya.sharma@deloitte.com", "deloitte.com", "Contract draft for your review",
     "Please find the draft contract attached. Comments by Friday?"),
    ("ops@globex.com", "globex.com", "Team offsite — logistics & agenda",
     "Sharing the offsite agenda and travel details for next month."),
]
PRIORITY = [  # authenticated bank OTPs (offline DKIM) -> Tier 1
    ("alert@axisbank.bank", "axisbank.bank", "Your OTP for fund transfer is 778451",
     "Your OTP for the fund transfer of Rs.1,20,000 is 778451. Valid 5 min."),
    ("otp@sbi.bank", "sbi.bank", "Your SBI NetBanking login OTP is 443120",
     "Use OTP 443120 to log in to SBI NetBanking. Do not share it."),
    ("secure@kotak.bank", "kotak.bank", "Transaction OTP: 901844",
     "Use 901844 to authorize your transaction of Rs.30,000."),
]
SPOOF = [  # spoofed .bank (no valid DKIM) -> quarantine
    ("security@hdfc.bank", "hdfc.bank", "Unusual activity detected on your account",
     "We noticed a login from a new device. Verify immediately."),
    ("alerts@icicibank.bank", "icicibank.bank", "Your account OTP is 663201",
     "Your OTP for the transaction of Rs.45,000 is 663201."),
]


def raw(frm, subject, body="", dkim=None, lu=False):
    from email.utils import formatdate
    h = f"From: {frm}\r\nTo: {VICTIM}\r\nDate: {formatdate(localtime=True)}\r\nSubject: {subject}\r\n".encode()
    if dkim:
        h += f"DKIM-Signature: v=1; a=rsa-sha256; d={dkim}; s=sel; h=from; bh=a; b=b\r\n".encode()
    if lu:
        h += b"List-Unsubscribe: <mailto:unsub@example.com>\r\n"
    return h + b"\r\n" + (body or "(body)").encode() + b"\r\n"


def parsed(domain, subject, frm=None):
    return {"sender_domain": domain, "from_header": frm or f"x@{domain}",
            "subject": subject, "sender_email": frm or f"x@{domain}",
            "return_path": "", "spf_result": "unknown"}


def deliver(frm, dom, subj, body, dkim=None, lu=False):
    rb = raw(frm, subj, body, dkim=dkim, lu=lu)
    d = bp.evaluate(VICTIM, frm, parsed(dom, subj, frm), rb)
    if d.action == "deliver_now":
        deliver_to_inbox(settings, receiver._tag_subject(rb, d.label), "PhishGuard-Priority")
        return "priority"
    if d.action == "phishing":
        deliver_to_inbox(settings, receiver._tag_subject(rb, f"[PHISHGUARD QUARANTINE — spoofed {dom}]"), "PhishGuard-Quarantined")
        return "quarantine"
    deliver_to_inbox(settings, receiver._tag_subject(rb, d.label), "PhishGuard-Released")
    return d.tier or "uncertain"


def _ai_narrative(total, noise_n, new_domains, priority_n, quarantine_n):
    """Option 3 — a short analyst-facing narrative of the incident.

    Uses the LLM if available; falls back to a deterministic template (so the demo
    never fails and never fabricates numbers — the facts are computed, not invented).
    """
    facts = (
        f"Email-bombing incident. An inbox received {total} emails within minutes: "
        f"{noise_n} subscription/newsletter confirmations from {new_domains} sender domains, "
        f"{priority_n} authenticated banking OTP(s), and {quarantine_n} spoofed bank alert(s) "
        f"that failed authentication."
    )
    system = (
        "You are a SOC analyst assistant. In exactly 3 short sentences, explain this "
        "email-bombing incident to an analyst: (1) what happened, (2) what the system did "
        "(surfaced the authenticated OTPs immediately, buffered the subscription noise and "
        "released it after the window, quarantined the spoofs), (3) the takeaway. "
        "Plain English. No preamble, no markdown, no bullet points."
    )
    try:
        import asyncio
        from app.llm.client import get_llm_client
        out = asyncio.run(get_llm_client().complete(system, facts, max_tokens=250))
        if out and out.strip():
            return out.strip()
    except Exception:
        pass
    return (
        f"This inbox received {noise_n} subscription emails from {new_domains} new sender domains "
        f"within minutes. {priority_n} authenticated banking OTP(s) arrived during the attack and "
        f"were delivered immediately, while the subscription noise was buffered and released after "
        f"the attack subsided. {quarantine_n} spoofed bank alert(s) were quarantined."
    )


def _redact(text):
    """Strip sensitive content (OTP codes, amounts) from a subject before it goes
    into a report or the terminal — replaces any run of 3+ digits with [redacted]."""
    import re as _re
    return _re.sub(r"\d{3,}", "[redacted]", text or "")


def main():
    import dkim, re as _re
    class _FakeDKIM:
        def __init__(self, message, *a, **k):
            self._m = message if isinstance(message, bytes) else b""
            self.domain = b""; self.signature_fields = {}
        def verify(self, idx=0, **k):
            m = _re.search(rb"\bd=([^;\s]+)", self._m)
            self.domain = m.group(1) if m else b""
            self.signature_fields = {b"h": b"from:subject"}
            return b"DKIM-Signature" in self._m
    dkim.DKIM = _FakeDKIM

    total = len(NOISE) + len(UNCERTAIN) + len(PRIORITY) + len(SPOOF)
    print(f"{B}REALISTIC EMAIL BOMB — delivering {total} messages to yeshwanthlb0@gmail.com{R}\n")

    # Pre-establish the business contacts so they land Tier-3 (not first-contact noise).
    for frm, dom, subj, body in UNCERTAIN:
        bp.evaluate(VICTIM, frm, parsed(dom, "earlier", frm), raw(frm, "earlier"))
    bd.clear_attack(VICTIM)

    # Trigger bombing mode.
    for i in range(6):
        bp.evaluate(VICTIM, f"x@noise{i}.com", parsed(f"noise{i}.com", "Confirm your email"),
                    raw(f"x@noise{i}.com", "Confirm your email"))
    print(f"{G}✓ bombing mode active — now delivering the flood...{R}\n")

    from collections import Counter
    tally = Counter()
    results = []  # (tier, from_domain, subject)
    for frm, subj in NOISE:
        dom = frm.split("@")[1]
        t = deliver(frm, dom, subj, "Please confirm your email to continue.", lu=True)
        tally[t] += 1; results.append((t, dom, subj))
    for frm, dom, subj, body in UNCERTAIN:
        t = deliver(frm, dom, subj, body); tally[t] += 1; results.append((t, dom, subj))
    for frm, dom, subj, body in PRIORITY:
        t = deliver(frm, dom, subj, body, dkim=dom); tally[t] += 1; results.append((t, dom, subj))
    for frm, dom, subj, body in SPOOF:
        t = deliver(frm, dom, subj, body); tally[t] += 1; results.append((t, dom, subj))

    print(f"{B}Delivered {total} emails. Breakdown:{R}")
    print(f"   {G}[PhishGuard-Priority]{R}        {tally.get('priority',0)}  (authenticated bank OTPs surfaced instantly)")
    print(f"   {Y}[Possible Bombing Noise]{R}     {tally.get('noise',0)}  (newsletter flood)")
    print(f"   {Y}[Received During Mail Bomb]{R}  {tally.get('uncertain',0)}  (business mail)")
    print(f"   {Rd}[PHISHGUARD QUARANTINE]{R}      {tally.get('quarantine',0)}  (spoofed .bank blocked)")
    print(f"\n{B}Check yeshwanthlb0@gmail.com — the OTPs are surfaced at the top despite the flood.{R}")

    # ── Option 2 — hidden-alert analysis (subjects redacted: no OTP codes) ─────
    surfaced = [(dom, _redact(subj)) for tier, dom, subj in results if tier == "priority"]
    print(f"\n{B}🎯 Hidden-alert analysis — what the bomb tried to bury:{R}")
    if surfaced:
        for dom, subj in surfaced:
            print(f"   {G}▸ CRITICAL{R} {subj}")
            print(f"     {D}from {dom} — authenticated critical sender (DKIM/DMARC-aligned){R}")
        print(f"   {D}{len(surfaced)} authenticated alert(s) surfaced instantly; "
              f"{tally.get('noise', 0)} subscription emails buffered as noise so they could not hide them.{R}")
    else:
        print(f"   {D}No authenticated critical alerts arrived during this window.{R}")

    # ── Option 3 — AI analyst narrative (facts only; no codes) ────────────────
    new_domains = len({dom for tier, dom, subj in results if tier == "noise"})
    narrative = _ai_narrative(
        total=total,
        noise_n=tally.get("noise", 0),
        new_domains=new_domains,
        priority_n=tally.get("priority", 0),
        quarantine_n=tally.get("quarantine", 0),
    )
    print(f"\n{B}🧠 AI analyst summary:{R}")
    print(f"   {C}{narrative}{R}")

    # ── Write a persistent JSON report (no email body content; codes redacted) ─
    import os as _os, json as _json
    from datetime import datetime as _dt
    report = {
        "report_type": "email_bombing_incident",
        "generated_at": _dt.now().isoformat(timespec="seconds"),
        "detection": {
            "target_inbox": VICTIM,
            "bombing_mode": "active",
            "trigger": "velocity",
            "emails_in_flood": total,
        },
        "tier_breakdown": {
            "priority_surfaced":   tally.get("priority", 0),
            "noise_buffered":      tally.get("noise", 0),
            "uncertain_delivered": tally.get("uncertain", 0),
            "quarantined_spoofed": tally.get("quarantine", 0),
        },
        "hidden_alerts": [
            {
                "sender_domain": dom,
                "type": "authenticated banking OTP",
                "authenticated": True,
                "alignment": "DKIM/DMARC",
            }
            for dom, _subj in surfaced
        ],
        "ai_summary": narrative,
        "privacy_note": "No email body content included. OTP codes and numeric amounts are redacted.",
    }
    report_dir = _os.environ.get("BOMBING_REPORT_DIR", "data/bombing_reports")
    fname_ts = _dt.now().strftime("%Y%m%d_%H%M%S")
    try:
        _os.makedirs(report_dir, exist_ok=True)
        path = _os.path.join(report_dir, f"bombing_report_{fname_ts}.json")
        with open(path, "w") as fh:
            _json.dump(report, fh, indent=2)
        print(f"\n{G}📄 Report saved (JSON): {path}{R}")
    except Exception as e:
        print(f"\n{Rd}Could not save report: {e}{R}")


if __name__ == "__main__":
    main()
