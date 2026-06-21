"""Fake downstream mail server — listens on port 1025, prints every email it receives.

This stands in for Gmail's real relay in the demo. In production this would be
smtp-relay.gmail.com delivering to the real recipient inbox.

Run with:
    python3 scripts/fake_mail_server.py
"""
import asyncio
import email
import textwrap
from aiosmtpd.controller import Controller


RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"

_count = 0


class FakeMailHandler:
    async def handle_DATA(self, server, session, envelope):
        global _count
        _count += 1

        raw = envelope.content
        try:
            msg = email.message_from_bytes(raw)
        except Exception:
            msg = None

        subject = msg.get("Subject", "(no subject)") if msg else "(parse error)"
        from_   = msg.get("From", envelope.mail_from) if msg else envelope.mail_from
        to_     = ", ".join(envelope.rcpt_tos)

        body = ""
        if msg:
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = (part.get_payload(decode=True) or b"").decode(errors="replace")[:200]
                        break
            else:
                body = (msg.get_payload(decode=True) or b"").decode(errors="replace")[:200]

        # Determine colour from subject tag
        subj_lower = subject.lower()
        if "[phishguard quarantine]" in subj_lower or "quarantine" in to_.lower():
            colour = RED
            label  = "🔴  PHISHING — QUARANTINED"
        elif "[phishguard suspicious" in subj_lower:
            colour = YELLOW
            label  = "🟡  SUSPICIOUS — FORWARDED WITH TAG"
        else:
            colour = GREEN
            label  = "✅  CLEAN — DELIVERED UNCHANGED"

        divider = "═" * 60
        print(f"\n{colour}{BOLD}{divider}{RESET}")
        print(f"{colour}{BOLD}  EMAIL #{_count} RECEIVED — {label}{RESET}")
        print(f"{colour}{divider}{RESET}")
        print(f"  {BOLD}From   :{RESET} {from_}")
        print(f"  {BOLD}To     :{RESET} {colour}{to_}{RESET}")
        print(f"  {BOLD}Subject:{RESET} {subject}")
        if body.strip():
            wrapped = textwrap.fill(body.strip(), width=55, initial_indent="  ", subsequent_indent="  ")
            print(f"  {BOLD}Body   :{RESET}\n{wrapped[:300]}")
        print(f"{colour}{divider}{RESET}\n")

        return "250 OK"


def main():
    print(f"\n{BOLD}{CYAN}PhishGuard — Fake Downstream Mail Server{RESET}")
    print(f"{CYAN}Listening on localhost:1025{RESET}")
    print(f"{CYAN}This simulates the recipient's mail server.{RESET}")
    print(f"─────────────────────────────────────────")
    print(f"Waiting for emails from PhishGuard...\n")

    controller = Controller(FakeMailHandler(), hostname="127.0.0.1", port=1025)
    controller.start()

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_forever()
    except KeyboardInterrupt:
        print(f"\n{CYAN}Server stopped. Received {_count} email(s).{RESET}")
    finally:
        controller.stop()


if __name__ == "__main__":
    main()
