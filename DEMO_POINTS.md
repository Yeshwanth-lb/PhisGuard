# PhishGuard — Email-Bombing Defense (Demo Points)

Bullet talking points. `RUN` = command · `SHOW` = point at screen.

## 1. What an email bomb is
- Not spam — it's a **cover attack**.
- The attacker just triggered **one real alert** to you: an OTP, a "was this you?" login, a bank notice.
- To hide it, they sign you up to **thousands of newsletters in minutes** → the real email is buried as #487 of 2,000.
- Our goal: **surface the one real alert, isolate the noise, never drop or hold anything** ("asymmetric defense").
- Technically: all mail enters our **SMTP gateway (port 8025)**; detection runs **per-recipient, in real time**.

## 2. Why the obvious fix fails
- Naive = "detect bomb → hold everything for review" → buries the OTP **a second time** in a human queue.
- Judging importance by the **subject line** is naive → a fake "Your OTP is 838201" sails through.
- So we tier mail by **who provably sent it, not what the subject says** — and there's **no human queue**.

## 3. The core — three tiers, decided by AUTHENTICATION not keywords
- **Tier 1 — IMPORTANT:** authenticated critical sender (`.bank`/`.gov`/trusted, cryptographically signed) → **delivered instantly** → `[PhishGuard-Priority]`.
- **Tier 2 — NOISE:** structural bulk-mail signals → buffered → `[Possible Bombing Noise]`.
- **Tier 3 — UNCERTAIN:** everything else (default = deliver) → buffered → `[Received During Mail Bomb]`.
- **Key line:** trust is earned by **cryptography, not keywords**.
  - Real bank OTP signed by the bank → instant.
  - Fake "OTP" from a throwaway domain → not trusted.
  - Spoofed `.bank` that fails the signature → quarantined as phishing.
- Tier-2 signals (headers only): List-Unsubscribe · Precedence:bulk/List-Id · first-contact sender · ESP fingerprint · brand-new domain.

## 4. How a bomb is detected
- **Three windows at once** — fires if ANY trips: **Fast** (5 in 30s) · **Standard** (score over 20 in 5 min) · **Slow-drip** (100 in 1 hr).
- **Language-independent** score: volume + sender diversity; subject pattern only a small boost.
- **Sliding cooldown:** on while the flood continues, auto-exits after quiet (hard-capped).

## 5. Authentication = the trust signal (anti-spoof core)
- Fast-track only if **cryptographically proven** — valid DKIM OR aligned SPF (= DMARC alignment).
- Each DKIM signature **verified individually** → only trust one that verifies AND signs From (defeats the multi-signature spoof).
- SPF checked against the **live sending IP** + must align with From.
- Claims to be protected but can't prove it → **quarantined**.

## 6. Nothing is ever lost
- Buffer on disk in **crash-safe SQLite (WAL)** → survives a restart mid-bomb.
- Worker releases past-window mail **labeled**, then marks it delivered.
- **Atomic claim** before delivery → no double-send; a crashed claim is **recovered & retried**.
- Guarantee: **nothing dropped, nothing held for a human, nothing delivered twice.**

## 7. The rate-limiter trap
- The gateway also caps ~30 emails/min per inbox → during a bomb it would reject the OTP too.
- Fix: once an inbox is under attack, **bypass the per-recipient limit** for it.
- Per-IP + global limits + **TCP-drop** for abusive IPs still protect the gateway.

## 8. Not blocking real OTPs (false-positive fix)
- Legit OTP/verify mail looks like phishing (urgency, "verify", a link) → sometimes flagged.
- Fix: aligned to its domain + domain established + IP not abusive → content tactics don't condemn it.
- **Reputation-gated** — brand-new/abusive senders still caught.

## 9. LIVE DEMO
- **1. Fire bomb:** `PYTHONPATH=. python3 scripts/send_mixed_bomb.py --rcpt ceo@company.com`
- **2. Detection:** `curl -s localhost:8000/health | python3 -m json.tool` → `active_attacks: 1`
- **3. Spoof quarantined:** `docker logs --since 2m phishguard-app | grep -E "spoofed_critical|quarantined"`
- **4. Priority OTPs:** `PYTHONPATH=. python3 scripts/demo_bombing_realmail.py` → click the **PhishGuard-Priority** label
- **5. Noise releases labeled** in the inbox ~45s later.

## 10. Likely questions
- **Spoof a bank for priority?** No — needs real DMARC alignment; a spoof fails it → quarantine.
- **Bomb in another language?** Volume/diversity based → language-independent.
- **Crash mid-bomb?** WAL buffer + recovery → nothing lost, nothing double-sent.
- **Rate limiter in the way?** Per-recipient bypassed under attack; other limits still guard.
- **Gmail too?** Same shared engine the Gmail path also calls (flag-gated, off until creds set).
- **Tested?** ~391 tests incl. adversarial cases; deployed non-root in Docker; security-hardened.

## 11. One-line close
- **Old way:** detect the bomb, guess importance from the subject, park the rest in a human queue.
- **Our way:** detect across 3 time-scales → verify **who actually sent it** → deliver that instantly → buffer-then-auto-release the noise.
- **Nothing dropped, nothing held, nothing trusted on forgeable evidence.**
