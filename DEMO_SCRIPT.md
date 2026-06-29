# PhishGuard — Email-Bombing Defense: Demo Script

A talk-track + live-demo guide. Sections marked **🎤 SAY** are what to say out loud;
**💻 RUN** are commands; **👀 SHOW** is what to point at on screen.

---

## 1. The 30-second pitch

**🎤 SAY:** "An *email bomb* isn't spam — it's a cover attack. The attacker has just
stolen your password or made a fraudulent transaction, which triggers ONE real alert to
your inbox: an OTP, a 'was this you?' notice, a bank confirmation. To stop you seeing it,
they sign your address up to thousands of newsletters in minutes. Your inbox floods, and
the one email that matters is buried as #487 of 2,000. PhishGuard's job isn't to block the
flood — it's to **surface the one real alert while quietly isolating the noise, and never
drop or hold a single message.** We call it **asymmetric defense.**"

---

## 2. The problem with the naive approach

**🎤 SAY:** "The obvious response — 'detect the bomb, hold everything for review' — buries
the OTP a *second* way: now it's stuck in a queue waiting for a human at 2 AM. And deciding
what's 'important' by reading the subject line is naive: an attacker just sends a fake
'Your OTP is 838201' from a throwaway domain and it sails through. So we built something
smarter."

---

## 3. The core design — three tiers, decided by AUTHENTICATION not keywords

While an inbox is under an active bomb, every incoming email is triaged:

| Tier | What it is | Action | Label |
|------|-----------|--------|-------|
| **Tier 1 — IMPORTANT** | An **authenticated critical sender**: a protected domain (`.bank`, `.gov`, trusted list) that is **cryptographically DMARC-aligned** | **Delivered instantly**, never buffered | `[PhishGuard-Priority]` |
| **Tier 2 — NOISE** | Structural bulk-mail signals (below) | Buffered, released after the window | `[Possible Bombing Noise]` |
| **Tier 3 — UNCERTAIN** | Everything else (default favors delivery) | Buffered, released after the window | `[Received During Mail Bomb]` |

**🎤 SAY (the key insight):** "Trust is earned by **cryptography, not keywords.** A real
bank OTP is delivered instantly *because the message is cryptographically signed by the
bank's domain* (DMARC alignment). A 'Your OTP' email from a throwaway domain is NOT trusted
— it's delivered but soft-labeled, never fast-tracked. And a spoofed `.bank` email that
*claims* to be a bank but fails the signature check is **quarantined as phishing.** That
closes the obvious bypass."

**Tier-2 structural signals (language-independent — works on any language):**
`List-Unsubscribe` header · `Precedence: bulk` / `List-Id` · first-contact-ever sender ·
ESP fingerprint in `Received` (Mailchimp/SendGrid/Mailgun/…) · very-new sender domain.

---

## 4. How we DETECT a bomb — three cascading time windows

**🎤 SAY:** "A single 5-minute window is easy to evade by throttling. So we run three
windows at once; a bomb fires if ANY of them trips:"

- **Fast / velocity:** 5 subscription-style emails in 30s (bot speed)
- **Standard:** a weighted score ≥ 60 over 20 emails in 5 min
- **Slow-drip:** 100 emails in 1 hour (catches low-and-slow floods)

**🎤 SAY:** "The score is **language-independent** — volume (40) + sender diversity (40)
are raw counts and domain comparisons; the English subject-pattern is only a 20-point
booster, never required. So a non-English bomb is still caught." Bombing 'mode' is a
**sliding cooldown** — it stays active while the flood continues and auto-exits after a
quiet period (capped so it can't be held open forever).

---

## 5. Durability — nothing is ever lost

**🎤 SAY:** "Buffered mail lives in **SQLite with WAL mode**, so it survives a crash or
restart mid-bomb. A background worker releases anything past the window, **labeled**, and
then deletes only what was truly delivered. Each message is **atomically claimed** before
delivery, so even with multiple workers nothing is double-sent; and if a worker dies
mid-delivery, the claim is recovered and retried. The guarantee is: **nothing dropped,
nothing held for a human, nothing delivered twice.**"

---

## 6. The rate limiter ↔ detector reconciliation (a subtle but important point)

**🎤 SAY:** "There's a trap: the SMTP rate limiter caps 30 emails/minute per inbox. During
a bomb that limit would itself start rejecting mail — including the OTP. So once an inbox is
in bombing mode, we **bypass the per-recipient limit for it** and let the smart triage
engine take over. The per-IP, global, and TCP-drop protections still guard the gateway.
The blunt limit can never bury the alert it's supposed to protect."

---

## 7. Reducing false positives on real OTPs (the latest addition)

**🎤 SAY:** "Legit OTP/verify emails look like phishing — urgency, 'verify', a link. So the
normal detector sometimes flagged real ones. We fixed it with an **authenticated-sender
fast-pass**: if a message is DMARC-aligned to its From domain AND the domain is established
and not abusive, the content tactics don't condemn it. Crucially it's **reputation-gated** —
a brand-new aligned domain or a flagged IP still gets caught, because alignment alone only
proves the domain isn't *spoofed*, not that it's *trustworthy*."

---

## 8. 🔴 LIVE DEMO

> Prep: have two terminals + the Gmail inbox (`yeshwanthlb0@gmail.com`) open.

### Step 1 — fire a realistic mixed bomb
**💻 RUN:**
```
PYTHONPATH=. python3 scripts/send_mixed_bomb.py --rcpt ceo@company.com
```
**🎤 SAY:** "I'm firing 25 emails at once — 15 newsletter sign-ups, 5 OTP/security emails,
2 spoofed bank alerts, and 3 normal business emails — exactly like a real bomb."

### Step 2 — show detection (instant)
**💻 RUN:**
```
curl -s localhost:8000/health | python3 -m json.tool
```
**👀 SHOW:** `bombing_detector.active_attacks: 1`, `attacked_inboxes: [ceo@company.com]`,
and `bombing_buffer` with the noise count.
**🎤 SAY:** "The gateway instantly detected the bomb and flipped this inbox into triage mode."

### Step 3 — show the spoofed bank getting QUARANTINED (the highlight)
**💻 RUN:**
```
docker logs --since 2m phishguard-app | grep -E "spoofed_critical|quarantined"
```
**🎤 SAY:** "These two emails *claimed* to be from `.bank` domains — but they can't produce
a valid cryptographic signature for that domain, so PhishGuard caught them as spoofs and
quarantined them, even in the middle of the flood."

### Step 4 — show the noise released, LABELED
**🎤 SAY:** "Within about a minute, the buffered noise is released to the inbox — but
clearly labeled, so the user (or a filter) can sweep it." *(Wait ~45–60s.)*
**👀 SHOW:** the Gmail inbox filling with `[Possible Bombing Noise] …` emails.

### Step 5 — the asymmetry (explain)
**🎤 SAY:** "Notice what did NOT happen: nothing was deleted, nothing is stuck in a human
queue. A *genuinely authenticated* bank alert would have been delivered **instantly** with
a Priority tag — the opposite treatment from the noise. That's the asymmetry: accelerate
the signal, isolate the noise, trust only cryptographic proof."

---

## 9. Q&A — likely questions + answers

- **"Couldn't an attacker just spoof a bank to get Tier-1 delivery?"** No — Tier-1 requires
  real DMARC alignment (a cryptographic DKIM signature valid for that domain). A spoof fails
  it and is routed to quarantine. We even defend against the multi-signature trick (attaching
  a valid throwaway signature + a fake bank `d=` header) by only trusting the signature that
  actually verified.
- **"What if the bomb is in another language?"** Detection is volume + sender-diversity based
  (language-independent); subject patterns are only a minor booster.
- **"What if the server crashes mid-bomb?"** The buffer is durable (SQLite WAL) and in-flight
  deliveries are recovered on restart — nothing is lost.
- **"Does the rate limiter interfere?"** Once an inbox is under attack its per-recipient limit
  is bypassed so it can't reject the OTP; other limits + a TCP hard-drop still protect the gateway.
- **"Does this work with Gmail, not just your SMTP gateway?"** Yes — the same detection/triage
  is a shared component the Gmail ingestion path also calls; it's flag-gated (off until creds
  are configured).
- **"How is it tested?"** ~390 automated tests, including adversarial cases (spoofed banks,
  multi-sig DKIM, crash recovery, slow-drip). It's deployed in Docker, runs non-root, and was
  hardened after a full security review (endpoint auth, JWT, CORS, SSRF).

---

## 10. One-line close

**🎤 SAY:** "Old way: detect the bomb, then guess what's important by reading the subject,
and park the rest in a queue a human has to clear. **Our way: detect across three
time-scales, decide what's important by cryptographically verifying who actually sent it,
accelerate that, quietly buffer-and-auto-release the noise — nothing dropped, nothing held,
nothing trusted on forgeable evidence.**"
