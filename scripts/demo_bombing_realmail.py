"""REAL end-to-end bombing test — actually delivers labeled mail to the Gmail inbox.

Runs the committed engine (detector → triage → durable buffer → release worker) with
REAL Gmail API delivery (deliver_to_inbox is NOT stubbed). Throwaway DB so your
dashboard data is untouched. Every message subject is prefixed [PG-DEMO] and safe to
delete.

Only the DKIM signature check is simulated (offline) for the one authenticated Tier-1
message — we can't forge a real bank's signature. Everything else is the real path.
"""
import os
import tempfile

os.environ["PHISHGUARD_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "realmail.db")
os.environ["BOMBING_ANALYSIS_WINDOW_SECS"] = "0"   # release immediately for the demo

import app.storage as storage                       # noqa: E402
import app.security.bombing_detector as bd          # noqa: E402
import app.security.bombing_pipeline as bp          # noqa: E402
import app.layer7_gmail.smtp_receiver as receiver   # noqa: E402
from app.config import settings                     # noqa: E402

VICTIM = "victim@company.com"
G = "\033[92m"; Y = "\033[93m"; R = "\033[0m"; B = "\033[1m"


def raw(frm, subject, body="", extra=b"", dkim=None):
    from email.utils import formatdate
    h = f"From: {frm}\r\nTo: {VICTIM}\r\nDate: {formatdate(localtime=True)}\r\nSubject: {subject}\r\n".encode()
    if dkim:
        h += f"DKIM-Signature: v=1; a=rsa-sha256; d={dkim}; s=sel; h=from; bh=a; b=b\r\n".encode()
    return h + extra + b"\r\n" + (body or "(message body)").encode() + b"\r\n"


def parsed(domain, subject, frm=None):
    return {"sender_domain": domain, "from_header": frm or f"x@{domain}",
            "subject": subject, "sender_email": frm or f"x@{domain}",
            "return_path": "", "spf_result": "unknown"}


def main():
    # Simulate cryptographic DKIM verification offline (real deployment verifies the
    # signature against the signer's DNS public key). The engine verifies EACH signature
    # via dkim.DKIM().verify(idx), so we stub that class: a message carrying a
    # DKIM-Signature is treated as validly signed by its d= domain, signing From.
    import dkim
    import re as _re

    class _FakeDKIM:
        def __init__(self, message, *a, **k):
            self._m = message if isinstance(message, bytes) else b""
            self.domain = b""
            self.signature_fields = {}

        def verify(self, idx=0, **k):
            m = _re.search(rb"\bd=([^;\s]+)", self._m)
            self.domain = m.group(1) if m else b""
            self.signature_fields = {b"h": b"from:subject"}
            return b"DKIM-Signature" in self._m

    dkim.DKIM = _FakeDKIM

    print(f"{B}REAL end-to-end bombing test → delivering to yeshwanthlb0@gmail.com{R}")

    # Pre-establish a KNOWN business contact so during the bomb it lands in Tier 3
    # (uncertain) rather than first-contact Tier-2 noise — gives a [Received During
    # Mail Bomb] example. (Real inboxes have prior correspondents.)
    bp.evaluate(VICTIM, "rohan.mehta@infosys.com",
                parsed("infosys.com", "Earlier thread", "rohan.mehta@infosys.com"),
                raw("rohan.mehta@infosys.com", "Earlier thread"))
    bd.clear_attack(VICTIM)

    # 1) Trigger bombing mode (6 subscription emails → velocity window).
    for i in range(6):
        bp.evaluate(VICTIM, f"x@noise{i}.com", parsed(f"noise{i}.com", "Confirm your email"),
                    raw(f"x@noise{i}.com", "Confirm your email"))
    assert bd.is_under_attack(VICTIM), "detection did not fire"
    print(f"{G}✓ bombing mode active{R}")

    # 2) Tier 1 — authenticated critical sender (DKIM-aligned bank) → delivered NOW.
    bank_from = "alert@axisbank.bank"
    bank_subj = "Your OTP for fund transfer is 778451"
    bank_body = "Your OTP for the fund transfer of Rs.1,20,000 is 778451. Valid for 5 minutes. Do not share it."
    bank_raw = raw(bank_from, bank_subj, bank_body, dkim="axisbank.bank")
    d = bp.evaluate(VICTIM, bank_from, parsed("axisbank.bank", bank_subj, bank_from), bank_raw)
    assert d.action == "deliver_now", d
    from app.layer7_gmail.gmail_client import deliver_to_inbox
    ok = deliver_to_inbox(settings, receiver._tag_subject(bank_raw, d.label), "PhishGuard-Priority")
    print(f"   Tier 1 (authenticated bank)  → delivered now: {G if ok else Y}{ok}{R}  {d.label}")

    # 3) Tier 2 / Tier 3 → buffered (real durable buffer).
    for frm, subj, body, extra, dom in [
        ("newsletter@e.medium.com", "Welcome to Medium",
         "Thanks for joining Medium. Confirm your email to start reading.",
         b"List-Unsubscribe: <mailto:u@e.medium.com>\r\n", "e.medium.com"),
        ("rohan.mehta@infosys.com", "Re: Q3 partnership review",
         "Following up on the Q3 numbers — can we sync this week?", b"", "infosys.com"),
    ]:
        rb = raw(frm, subj, body, extra)
        dd = bp.evaluate(VICTIM, frm, parsed(dom, subj, frm), rb)
        bp.buffer(dd, VICTIM, "demo", rb, dom, subj)
        print(f"   {dd.tier:<9} ({dom}) → buffered")

    # 4) Window expired → release worker delivers buffered mail LABELED (real).
    print(f"\n{B}release worker → delivering buffered mail (real Gmail API)...{R}")
    n = receiver._release_due(settings)
    print(f"{G}✓ released {n} buffered message(s) to the inbox, labeled{R}")
    print(f"\n{B}Check yeshwanthlb0@gmail.com — you should now see:{R}")
    print("   • [PhishGuard-Priority] Your OTP for fund transfer is 778451")
    print("   • [Possible Bombing Noise] Welcome to Medium")
    print("   • [Received During Mail Bomb] Re: Q3 partnership review")


if __name__ == "__main__":
    main()
