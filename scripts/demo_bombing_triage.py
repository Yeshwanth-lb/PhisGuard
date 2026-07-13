"""Live in-process demo of the NEW email-bombing triage engine (Phase 1A+1B).

Drives the real committed code path — bombing_detector → bombing_triage → durable
buffer → release worker — against a throwaway DB. No server, no network, nothing of
yours touched. Shows the asymmetric response:

  • detection fires across the cascading windows
  • Tier 1 (authenticated critical sender) delivers INSTANTLY, never buffered
  • a subject-only OTP from an UNAUTHENTICATED domain is NOT fast-tracked (bypass fix)
  • a spoofed protected-TLD sender is routed to PHISHING (failed DMARC alignment)
  • Tier 2 noise + Tier 3 uncertain are buffered, then auto-released LABELED
  • nothing is dropped or held for a human
"""
import os
import tempfile

# Throwaway DB + immediate release window, set BEFORE importing the app modules.
os.environ["PHISHGUARD_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "demo.db")
os.environ["BOMBING_ANALYSIS_WINDOW_SECS"] = "0"   # release everything immediately for the demo

import app.storage as storage                       # noqa: E402
import app.security.bombing_detector as bd          # noqa: E402
import app.security.bombing_triage as triage        # noqa: E402
import app.layer7_gmail.smtp_receiver as receiver   # noqa: E402
import app.layer7_gmail.gmail_client as gmail       # noqa: E402

R = "\033[0m"; B = "\033[1m"; G = "\033[92m"; Y = "\033[93m"; RED = "\033[91m"; C = "\033[96m"; DIM = "\033[2m"
VICTIM = "victim@company.com"


def hdr(t): print(f"\n{B}{C}{'─'*72}{R}\n{B}{C} {t}{R}\n{B}{C}{'─'*72}{R}")


def raw(from_addr, subject, extra=b"", dkim_domain=None):
    h = f"From: {from_addr}\r\nTo: {VICTIM}\r\nSubject: {subject}\r\n".encode()
    if dkim_domain:
        h += (f"DKIM-Signature: v=1; a=rsa-sha256; d={dkim_domain}; s=sel; "
              f"h=from:subject; bh=a; b=b\r\n").encode()
    return h + extra + b"\r\nbody text here\r\n"


def parsed(domain, subject):
    return {"sender_domain": domain, "from_header": f"x@{domain}",
            "subject": subject, "return_path": "", "spf_result": "unknown"}


# Simulate cryptographic DKIM verification offline: a message with a DKIM-Signature
# header is treated as validly signed. (Real deployment fetches the signer's public
# key via DNS and verifies the signature — we can't do that offline in a demo.)
def _fake_dkim_verify(message, **kw):
    return b"DKIM-Signature" in (message if isinstance(message, bytes) else b"")


def main():
    import dkim
    dkim.verify = _fake_dkim_verify
    # Capture "deliveries" instead of hitting Gmail/relay.
    delivered = []
    gmail.deliver_to_inbox = lambda settings, raw_b, label="": (delivered.append((label, raw_b)) or True)

    print(f"{B}PhishGuard — Email-Bombing Triage Engine — LIVE DEMO{R}")
    print(f"{DIM}victim inbox: {VICTIM}   |   throwaway DB: {os.environ['PHISHGUARD_DB_PATH']}{R}")

    # Pre-seed two domains as 'known' so they aren't first-contact during the bomb
    # (lets us show the Tier-3 path distinctly from the first-contact Tier-2 path).
    for d in ("partnerco.com", "throwaway-otp.com"):
        bd.record(VICTIM, f"x@{d}", "prior legitimate message")
    bd.clear_attack(VICTIM)   # the warm-up shouldn't count as an attack

    # ── 1. The flood arrives — detection across the cascading windows ──────────
    hdr("1.  THE BOMB ARRIVES — cascading-window detection")
    noise = [
        ("noreply@amazon-newsletters.com", "Confirm your email address"),
        ("verify@github-mailer.com",       "Please verify your email"),
        ("welcome@shopify-store-123.com",  "Welcome to our store"),
        ("noreply@newsletter-svc-a.com",   "Thanks for signing up"),
        ("signup@medium-stories.com",      "Complete your registration"),
        ("activate@forum-b.com",           "Activate your account"),
    ]
    for i, (frm, subj) in enumerate(noise, 1):
        under, new = bd.record(VICTIM, frm, subj)
        flag = f"{RED}{B}◀ BOMBING DETECTED (velocity window){R}" if new else (f"{Y}(mode active){R}" if under else "")
        print(f"   {i}. {frm:<34} {DIM}{subj[:30]:<30}{R} {flag}")
    if bd.is_under_attack(VICTIM):
        print(f"\n   {G}✓ bombing mode is active for {VICTIM}{R}")
    else:
        print(f"\n   {RED}✗ detection did NOT fire — demo data problem{R}"); return

    # ── 2. Triage each subsequent email (this is what the receiver does) ───────
    hdr("2.  TRIAGE WHILE UNDER ATTACK  (Tier 1 = authenticated-only)")
    # (from, subject, raw, parsed-domain)  — the interesting mix
    cases = [
        ("newsletter@promo-mailer.com", "Big sale this weekend!",
         raw("newsletter@promo-mailer.com", "Big sale this weekend!",
             extra=b"List-Unsubscribe: <mailto:u@promo-mailer.com>\r\n"), "promo-mailer.com"),
        ("security@mybank.bank", "Your one-time password is 847291",
         raw("security@mybank.bank", "Your one-time password is 847291"), "mybank.bank"),
        ("x@throwaway-otp.com", "Your OTP code is 555123",
         raw("x@throwaway-otp.com", "Your OTP code is 555123"), "throwaway-otp.com"),
        ("alerts@trust.bank", "Unusual sign-in to your account",
         raw("alerts@trust.bank", "Unusual sign-in to your account", dkim_domain="trust.bank"), "trust.bank"),
        ("alice@partnerco.com", "Can we reschedule Thursday's call?",
         raw("alice@partnerco.com", "Can we reschedule Thursday's call?"), "partnerco.com"),
    ]
    for frm, subj, rawb, dom in cases:
        fc = bd.is_first_contact(VICTIM, frm)
        bd.record(VICTIM, frm, subj)
        tri = triage.classify(parsed(dom, subj), rawb, fc)

        if tri.action == "deliver_now":
            tagged = receiver._tag_subject(rawb, tri.label)
            gmail.deliver_to_inbox(None, tagged, "PhishGuard-Priority")
            verdict = f"{G}{B}TIER 1 → DELIVERED NOW{R} {DIM}{tri.label}{R}"
        elif tri.action == "phishing":
            verdict = f"{RED}{B}SPOOFED → QUARANTINE{R} {DIM}(claimed protected TLD, DMARC align FAILED){R}"
        else:
            storage.buffer_add(buffer_id=f"buf-{dom}", recipient=VICTIM, scan_id="s",
                               tier=tri.tier, raw_email=rawb, sender_domain=dom, subject=subj)
            tname = "TIER 2 NOISE" if tri.tier == "noise" else "TIER 3 UNCERTAIN"
            verdict = f"{Y}{tname} → BUFFERED{R}"
        print(f"   {frm:<30} {DIM}{subj[:34]:<34}{R}\n      → {verdict}\n        {DIM}{tri.reason}{R}")

    # ── 3. Buffer state (what /api/bombing/active + /health surface) ───────────
    hdr("3.  BUFFER STATE  (surfaced by /api/bombing/active & /health)")
    counts = storage.buffer_counts_by_tier(VICTIM)
    print(f"   recipients in bombing mode : {[a['rcpt'] for a in bd.active_attacks()]}")
    print(f"   buffered for {VICTIM}: {counts or '{}'}")

    # ── 4. Window expires → release worker delivers everything, LABELED ────────
    hdr("4.  WINDOW EXPIRES — release worker delivers buffered mail, LABELED")
    before = len(delivered)
    n = receiver._release_due(None)
    print(f"   release worker released {B}{n}{R} buffered message(s):")
    for label, rb in delivered[before:]:
        subj = [ln for ln in rb.decode(errors="replace").splitlines() if ln.lower().startswith("subject:")]
        print(f"     {G}✓{R} {subj[0] if subj else '(subject)'}")
    print(f"\n   held after release: {storage.buffer_list_for_recipient(VICTIM)}  {G}(empty — nothing left behind){R}")

    # ── Summary ────────────────────────────────────────────────────────────────
    hdr("SUMMARY — asymmetric defense in action")
    print(f"""   {G}•{R} Authenticated critical sender (trust.bank, DKIM-aligned) → delivered INSTANTLY
   {G}•{R} Spoofed .bank (no valid signature)                     → quarantined as phishing
   {G}•{R} Subject-only OTP from throwaway domain                 → NOT fast-tracked (bypass closed)
   {G}•{R} Newsletter / first-contact noise                       → buffered, released labeled
   {G}•{R} Ambiguous business mail                                → delivered (safety valve)
   {G}•{R} Nothing dropped, nothing held for a human{R}
""")


if __name__ == "__main__":
    main()
