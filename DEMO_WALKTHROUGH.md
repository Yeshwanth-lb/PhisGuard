# PhishGuard — Email-Bombing Defense: Demo Walkthrough (talking points)

Bullet points to present from. `💻 RUN` = command · `👀 SHOW` = point at screen.

---

## 1. What an email bomb is
- Not spam — it's a **cover attack**.
- The attacker just triggered **one real alert** to you: an OTP, a "was this you?" login, a bank notice.
- To hide it, they sign you up to **thousands of newsletters in minutes** → the real email is buried as #487 of 2,000.
- Our goal: **surface the one real alert, isolate the noise, never drop or hold anything.** → "asymmetric defense."
- Technically: all mail enters our **SMTP gateway (port 8025)**; detection runs **per-recipient, in real time**.

## 2. Why the obvious fix fails
- Naive approach = "detect bomb → hold everything for review" → buries the OTP **a second time** in a human queue.
- Judging importance by the **subject line** is naive → attacker sends a fake "Your OTP is 838201" and it sails through.
- So we tier mail by **who provably sent it, not what the subject says** — and there's **no human queue** in the flow.

## 3. The core — three tiers, decided by AUTHENTICATION not keywords
- **Tier 1 — IMPORTANT:** an **authenticated** critical sender (`.bank`/`.gov`/trusted domain, cryptographically signed) → **delivered instantly** → label `[PhishGuard-Priority]`.
- **Tier 2 — NOISE:** structural bulk-mail signals → buffered, released labeled `[Possible Bombing Noise]`.
- **Tier 3 — UNCERTAIN:** everything else (default = deliver) → buffered, released labeled `[Received During Mail Bomb]`.
- **Key line:** *trust is earned by cryptography, not keywords.*
  - Real bank OTP = signed by the bank → instant.
  - Fake "OTP" from a throwaway domain → **not trusted**.
  - Spoofed `.bank` that fails the signature → **quarantined as phishing**.
- Tier-2 signals (language-independent, headers only): `List-Unsubscribe` · `Precedence: bulk`/`List-Id` · first-contact sender · ESP fingerprint (Mailchimp/SendGrid/…) · brand-new domain.

## 4. How a bomb is detected
- **Three time windows at once** — fires if ANY trips:
  - **Fast:** 5 newsletter-style emails in 30s (bot speed)
  - **Standard:** high score over 20 emails in 5 min
  - **Slow-drip:** 100 emails in 1 hour (low-and-slow floods)
- **Language-independent score:** mostly volume + sender diversity; English subject pattern only a small boost → catches non-English bombs.
- **Sliding cooldown:** mode stays on while the flood continues, auto-exits after quiet (with a hard cap so it can't get stuck on).

## 5. Authentication = the trust signal (anti-spoof core)
- Fast-track only if **cryptographically proven** to come from the claimed domain — valid **DKIM** signature OR aligned **SPF** (together = DMARC alignment).
- Each DKIM signature **verified individually** → only trust one that actually verifies **and** signs the From header.
  - Defeats the spoof of attaching a valid throwaway signature + a fake "this is the bank" header.
- SPF checked against the **live sending IP** and must line up with From (a bare "SPF passed" on an unrelated domain doesn't count).
- Claims to be a protected sender but can't prove it → **quarantined** (strongest phishing signal).

## 6. Nothing is ever lost
- Buffered mail stored on disk in a **crash-safe DB (SQLite WAL)** → survives a restart mid-bomb.
- A background worker releases anything past the window, **labeled**, then marks it delivered.
- Each message **atomically claimed** before delivery → no double-send, even with multiple workers.
- Worker dies mid-delivery → claim is **recovered and retried**.
- Guarantee: **nothing dropped, nothing held for a human, nothing delivered twice.** Buffer also bounded per inbox (overflow delivers immediately, labeled).

## 7. The rate-limiter trap
- The gateway also caps ~30 emails/min per inbox — during a bomb **that** would start rejecting mail, including the OTP.
- Fix: once an inbox is under attack, we **bypass the per-recipient limit for it** and let triage take over.
- Per-IP + global limits + **TCP-drop** for abusive IPs still protect the gateway.
- → the blunt limit can never bury the alert it's meant to protect.

## 8. Not blocking real OTPs (false-positive fix)
- Legit OTP/verify emails *look* like phishing (urgency, "verify", a link) → sometimes flagged.
- Fix: if an email is **cryptographically aligned** to its domain AND the domain is **established** AND the IP isn't **abusive** → content tactics don't condemn it.
- **Reputation-gated** — alignment alone isn't enough (a phisher can sign their own throwaway domain), so brand-new/abusive senders still get caught.

## 9. 🔴 LIVE DEMO
> Prep: 2 terminals + Gmail inbox open; click the **PhishGuard-Priority** label in the sidebar.

- **Step 1 — fire a realistic mixed bomb**
  - 💻 `PYTHONPATH=. python3 scripts/send_mixed_bomb.py --rcpt ceo@company.com`
  - Say: "25 emails at once — newsletter sign-ups, OTP/security codes, 2 spoofed bank alerts, business mail."
- **Step 2 — show instant detection**
  - 💻 `curl -s localhost:8000/health | python3 -m json.tool`
  - 👀 `bombing_detector.active_attacks: 1` + the attacked inbox + buffer count.
- **Step 3 — spoofed banks QUARANTINED (the highlight)**
  - 💻 `docker logs --since 2m phishguard-app | grep -E "spoofed_critical|quarantined"`
  - Say: "Claimed to be `.bank` but couldn't produce a valid signature → caught and quarantined, mid-flood."
- **Step 4 — authenticated OTPs delivered instantly**
  - 💻 `PYTHONPATH=. python3 scripts/demo_bombing_realmail.py`
  - 👀 the **PhishGuard-Priority** label — signed bank OTPs (axisbank/sbi/kotak) delivered immediately.
- **Step 5 — noise releases, labeled**
  - Say: "~45s later the noise lands in the inbox tagged `[Possible Bombing Noise]` — nothing deleted, nothing in a queue."

## 10. Likely questions
- **Spoof a bank for priority?** No — Tier-1 needs real DMARC alignment; a spoof fails it → quarantine. Multi-signature trick is blocked too.
- **Bomb in another language?** Detection is volume + sender-diversity based → language-independent.
- **Server crashes mid-bomb?** WAL buffer + crash recovery → nothing lost, nothing double-sent.
- **Rate limiter in the way?** Per-recipient limit bypassed under attack; other limits still protect.
- **Gmail too?** Same engine is a shared component the Gmail path also calls (flag-gated, off until creds set).
- **Tested?** ~391 tests incl. adversarial cases; deployed in Docker, non-root, hardened after a full security review.

## 11. One-line close
- **Old way:** detect the bomb, guess importance from the subject, park the rest in a human queue.
- **Our way:** detect across three time-scales → decide importance by **cryptographically verifying who actually sent it** → deliver that instantly → quietly buffer-then-auto-release the noise.
- **Nothing dropped, nothing held, nothing trusted on forgeable evidence.**
