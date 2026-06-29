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


def raw(frm, subject, extra=b"", dkim=None):
    h = f"From: {frm}\r\nTo: {VICTIM}\r\nSubject: [PG-DEMO] {subject}\r\n".encode()
    if dkim:
        h += f"DKIM-Signature: v=1; a=rsa-sha256; d={dkim}; s=sel; h=from; bh=a; b=b\r\n".encode()
    return h + extra + b"\r\nThis is a PhishGuard demo email. Safe to delete.\r\n"


def parsed(domain, subject):
    return {"sender_domain": domain, "from_header": f"x@{domain}",
            "subject": f"[PG-DEMO] {subject}", "sender_email": f"x@{domain}",
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

    # 1) Trigger bombing mode (6 subscription emails → velocity window).
    for i in range(6):
        bp.evaluate(VICTIM, f"x@noise{i}.com", parsed(f"noise{i}.com", "Confirm your email"),
                    raw(f"x@noise{i}.com", "Confirm your email"))
    assert bd.is_under_attack(VICTIM), "detection did not fire"
    print(f"{G}✓ bombing mode active{R}")

    # 2) Tier 1 — authenticated critical sender → delivered NOW (real).
    d = bp.evaluate(VICTIM, "alerts@trust.bank", parsed("trust.bank", "Unusual sign-in to your account"),
                    raw("alerts@trust.bank", "Unusual sign-in to your account", dkim="trust.bank"))
    assert d.action == "deliver_now", d
    tagged = receiver._tag_subject(raw("alerts@trust.bank", "Unusual sign-in to your account", dkim="trust.bank"), d.label)
    from app.layer7_gmail.gmail_client import deliver_to_inbox
    ok = deliver_to_inbox(settings, tagged, "PhishGuard-Priority")
    print(f"   Tier 1 (authenticated bank)  → delivered now: {G if ok else Y}{ok}{R}  {d.label}")

    # 3) Tier 2 / Tier 3 → buffered (real durable buffer).
    for frm, subj, extra, dom in [
        ("newsletter@promo-mailer.com", "Big sale this weekend", b"List-Unsubscribe: <mailto:u@promo-mailer.com>\r\n", "promo-mailer.com"),
        ("alice@partnerco.com", "Can we reschedule Thursdays call", b"", "partnerco.com"),
    ]:
        dd = bp.evaluate(VICTIM, frm, parsed(dom, subj), raw(frm, subj, extra))
        bp.buffer(dd, VICTIM, "demo", raw(frm, subj, extra), dom, f"[PG-DEMO] {subj}")
        print(f"   {dd.tier:<9} ({dom}) → buffered")

    # 4) Window expired → release worker delivers buffered mail LABELED (real).
    print(f"\n{B}release worker → delivering buffered mail (real Gmail API)...{R}")
    n = receiver._release_due(settings)
    print(f"{G}✓ released {n} buffered message(s) to the inbox, labeled{R}")
    print(f"\n{B}Check yeshwanthlb0@gmail.com — you should now see:{R}")
    print("   • [PhishGuard-Priority] [PG-DEMO] Unusual sign-in to your account")
    print("   • [Possible Bombing Noise] [PG-DEMO] Big sale this weekend")
    print("   • [Received During Mail Bomb] [PG-DEMO] Can we reschedule Thursdays call")


if __name__ == "__main__":
    main()
