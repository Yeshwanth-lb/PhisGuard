# PhishGuard — Email-Bombing Defense: Blended Walkthrough

Each section has two layers:
- **🗣 In plain English** — what it is / what to say out loud.
- **⚙️ Under the hood** — the technical "how", for engineering questions.

`💻 RUN` = command · `👀 SHOW` = point at screen.

---

## 1. What an email bomb actually is

**🗣 In plain English:** An email bomb isn't spam — it's a *cover attack*. The attacker just
did something that triggers ONE real alert to you (an OTP, a "was this you?" login notice, a
bank confirmation). To stop you seeing it, they sign your address up to thousands of
newsletters in minutes. Your inbox floods and the one email that matters is buried as #487 of
2,000. Our job isn't to block the flood — it's to **surface the one real alert, isolate the
noise, and never drop or hold a single message.** We call it **asymmetric defense.**

**⚙️ Under the hood:** Mail arrives at our inbound **SMTP gateway** (`aiosmtpd`, port 8025).
Every message hits `smtp_receiver.handle_DATA`, which runs: rate-limit → full analysis pipeline
→ bombing detection/triage → deliver or buffer. Detection is **per-recipient and streaming** —
we keep a sliding window of recent arrivals per inbox and decide in real time.

---

## 2. Why the naive approach fails

**🗣 In plain English:** The obvious fix — "detect the bomb, hold everything for a human to
review" — buries the OTP a *second* way: now it's stuck in a queue at 2 AM. And deciding
what's important by reading the subject line is naive — an attacker just sends a fake
"Your OTP is 838201" from a throwaway domain and it sails through. So we built something
smarter: tier mail by **who provably sent it**, not by what the subject says.

**⚙️ Under the hood:** We replaced the old "suspicious → Pending-Review hold" branch entirely.
There is no human queue in the bombing path. Classification is done by `bombing_triage.classify()`,
which gates on **cryptographic sender authentication** before anything else.

---

## 3. The core — three tiers, decided by AUTHENTICATION not keywords

**🗣 In plain English:** While an inbox is under attack, every email is sorted into one of three
tiers:

| Tier | What it is | What happens | Label |
|------|-----------|--------------|-------|
| **Tier 1 — IMPORTANT** | An **authenticated** critical sender (a `.bank`/`.gov`/trusted domain that is cryptographically signed) | **Delivered instantly** | `[PhishGuard-Priority]` |
| **Tier 2 — NOISE** | Bulk-mail signals (newsletters etc.) | Buffered, released labeled | `[Possible Bombing Noise]` |
| **Tier 3 — UNCERTAIN** | Everything else (default = deliver) | Buffered, released labeled | `[Received During Mail Bomb]` |

The key line to say: *"Trust is earned by **cryptography, not keywords.** A real bank OTP is
delivered instantly because the message is cryptographically signed by the bank. A 'Your OTP'
email from a throwaway domain is NOT trusted — and a spoofed `.bank` that fails the signature is
**quarantined as phishing.**"*

**⚙️ Under the hood:** `classify()` runs in strict order:
1. `critical_sender.is_critical_sender()` → if `spoofed_critical` → **phishing route**; if
   `critical` → **Tier 1 (`deliver_now`)**.
2. Else Tier-2 **structural signals** (headers only, never the body): `List-Unsubscribe`,
   `Precedence: bulk`/`List-Id`, first-contact-ever sender, ESP fingerprint in `Received`
   (Mailchimp/SendGrid/Mailgun…), very-new sender domain.
3. Else **Tier 3** (default-deliver). A high-signal subject ("OTP", "reset") is only a *label
   hint* here — it never fast-tracks an unauthenticated sender. (This closes the fake-OTP bypass.)

---

## 4. How we DETECT a bomb — three time windows at once

**🗣 In plain English:** A single 5-minute window is easy to dodge by sending slowly. So we
watch three windows simultaneously; a bomb fires if ANY trips:
- **Fast:** 5 newsletter-style emails in 30 seconds (bot speed)
- **Standard:** a high score over 20 emails in 5 minutes
- **Slow-drip:** 100 emails in an hour (catches low-and-slow floods)

And it's **language-independent** — it counts volume and how many *different* senders, so a
non-English bomb is caught just as well.

**⚙️ Under the hood:** `bombing_detector.record()` keeps a per-recipient `deque[(ts,
sender_domain, is_pattern)]` retained for the widest window (1 h). All three windows are derived
from that one deque each call. The **score** = volume (40, gates everything) + sender-diversity
(40, ratio of new domains, down-weighted during cold-start) + English subject pattern (20,
booster only). Bombing "mode" is a **sliding cooldown** (`under_attack_until = now + 300s`,
refreshed by ongoing bombing-ish mail, capped by `ATTACK_MAX_SECS` so it can't be pinned open
forever). A `_now()` clock seam lets tests drive the windows without real waits.

---

## 5. Authentication = the trust signal (the anti-spoof core)

**🗣 In plain English:** This is the heart of it. We only fast-track a "critical" email (bank,
gov) if it's **cryptographically proven** to come from that domain — a valid DKIM signature, or
an SPF pass that lines up with the From address (this is what DMARC alignment means). If an
email *claims* to be from a bank but can't prove it, it's not trusted — it's quarantined.

**⚙️ Under the hood:** `critical_sender.is_critical_sender()` = **protected?** (From's
org-domain is a protected TLD or in the trusted table) **AND aligned?**
- `_dkim_aligned()` **verifies each `DKIM-Signature` individually** (`dkim.DKIM(raw).verify(idx=i)`)
  and only trusts a *verified* signature whose `d=` organizationally aligns with `From` **and**
  whose `h=` actually signs `From`. *(This defeats the multi-signature spoof: attaching a valid
  throwaway signature plus a bogus `d=<victim-bank>` header.)*
- `_spf_aligned()` does a real SPF check against the live **connecting peer IP** for the envelope
  sender, and requires that envelope domain to align with `From` (a bare `spf=pass` on a
  non-aligned domain doesn't count).
- Protected/trusted claim that fails both → `signal="spoofed_critical"` → **quarantine**.

---

## 6. Durability — nothing is ever lost

**🗣 In plain English:** Buffered mail is written to disk, so even if the server crashes
mid-bomb, nothing is lost. A background worker releases anything past the window, **labeled**,
and only then deletes it. Nothing is dropped, nothing is held for a human, nothing is delivered
twice.

**⚙️ Under the hood:** The buffer is a SQLite table (`bombing_buffer`) opened in **WAL mode**.
Lifecycle per message: `buffer_add` (released=0) → `buffer_claim` (atomic `UPDATE … WHERE
released=0`, so only one worker wins — no double-send) → on success `buffer_mark_released`
(stamps `delivered_at`) → `buffer_purge_expired` deletes **only delivered** rows. If a worker
dies between claim and delivery, `buffer_reclaim_stale` recovers it next cycle. The release
worker is a daemon thread polling every 15 s; on per-recipient overflow it delivers
immediately-labeled instead of buffering (bounded storage, still no drop).

---

## 7. The rate-limiter trap (and how we reconcile it)

**🗣 In plain English:** There's a subtle trap. The gateway also has a rate limiter that caps
~30 emails/minute per inbox. During a bomb that limit would *itself* start rejecting mail —
including the OTP we're trying to protect. So once an inbox is in bombing mode, we **turn off
the per-recipient limit for it** and let the smart triage engine take over. Other protections
(per-IP, global, and dropping abusive connections) still guard the gateway.

**⚙️ Under the hood:** `smtp_rate_limiter.check()` has 4 sliding windows (per-IP 10/60s,
per-domain 20/3600s, **per-recipient 30/60s**, global 60/60s), a 2 s tarpit before `421`, and a
**TCP hard-drop** for IPs that exceed 421 >3×/60s. The receiver passes
`skip_recipient_limit=is_under_attack(rcpt)`, so the blunt per-recipient cap can never 421 the
alert the triage engine is busy protecting.

---

## 8. Not blocking real OTPs (the false-positive fix)

**🗣 In plain English:** Legit OTP/verify emails *look* like phishing — urgency, "verify", a
link. So the normal detector sometimes flagged real ones. We fixed it: if an email is
cryptographically authenticated to its domain AND that domain is established and not abusive,
those scary content words don't condemn it. Importantly, alignment alone isn't enough — a
phisher can sign their own throwaway domain — so it's **reputation-gated**.

**⚙️ Under the hood:** In `pipeline.analyze_email`, after L1: if
`critical_sender.is_dmarc_aligned(parsed, raw)` **AND** no L1 `domain_age` weak-hit (domain
established) **AND** `abuse_max_score < threshold` (clean IP) → deliver clean, skipping L2
content scoring. Toggle: `auth_sender_fastpass`. L1 hard hits (denylist/VirusTotal/URLhaus) still
quarantine regardless.

---

## 9. 🔴 LIVE DEMO

> Prep: two terminals + the Gmail inbox (`yeshwanthlb0@gmail.com`) open, click the
> **PhishGuard-Priority** label in the sidebar so it's ready.

**Step 1 — fire a realistic mixed bomb**
💻 `PYTHONPATH=. python3 scripts/send_mixed_bomb.py --rcpt ceo@company.com`
🗣 "25 emails at once — newsletter sign-ups, OTP/security codes, 2 spoofed bank alerts, and
business mail — exactly like a real bomb."

**Step 2 — show detection (instant)**
💻 `curl -s localhost:8000/health | python3 -m json.tool`
👀 `bombing_detector.active_attacks: 1`, the attacked inbox, and `bombing_buffer` noise count.
🗣 "The gateway detected the bomb instantly and flipped this inbox into triage mode."

**Step 3 — the spoofed banks get QUARANTINED (the highlight)**
💻 `docker logs --since 2m phishguard-app | grep -E "spoofed_critical|quarantined"`
🗣 "These two *claimed* to be `.bank` domains but couldn't produce a valid signature — caught
and quarantined, mid-flood."

**Step 4 — authenticated OTPs delivered instantly**
💻 `PYTHONPATH=. python3 scripts/demo_bombing_realmail.py`
👀 the **PhishGuard-Priority** label — signed bank OTPs (axisbank/sbi/kotak `.bank`) delivered
instantly.
🗣 "Real, *signed* bank OTPs are surfaced immediately — the opposite treatment from the noise."

**Step 5 — the noise releases, labeled**
🗣 "Within ~45s the buffered noise is released to the inbox, clearly labeled
`[Possible Bombing Noise]` so it can be swept. Nothing deleted, nothing stuck in a human queue."

---

## 10. Q&A — likely questions

- **Spoof a bank to get priority?** No — Tier-1 needs real DMARC alignment; a spoof fails it →
  quarantine. We even block the multi-signature trick (only the *verified* signature's `d=` is trusted).
- **Bomb in another language?** Detection is volume + sender-diversity based — language-independent.
- **Server crashes mid-bomb?** WAL buffer + stale-claim recovery → nothing lost, nothing double-sent.
- **Rate limiter interfere?** Per-recipient limit is bypassed under attack so it can't bury the OTP;
  per-IP/global/TCP-drop still protect the gateway.
- **Gmail too, or just your gateway?** Same engine is a shared component the Gmail path also calls
  (flag-gated, off until creds set).
- **Tested?** ~391 tests incl. adversarial (spoofs, multi-sig DKIM, crash recovery, slow-drip).
  Deployed in Docker, non-root, hardened after a full security review.

---

## 11. One-line close

🗣 *"Old way: detect the bomb, guess what's important from the subject, and park the rest in a
queue a human has to clear. **Our way: detect across three time-scales, decide what's important
by cryptographically verifying who actually sent it, deliver that instantly, and quietly
buffer-then-auto-release the noise — nothing dropped, nothing held, nothing trusted on forgeable
evidence."***

**Technical one-liner:** *"A per-recipient streaming detector (three sliding windows over an
in-memory deque) gates a cryptographic-authentication classifier (per-signature DKIM + peer-IP
SPF alignment); non-critical mail is parked in a crash-durable WAL SQLite buffer with an atomic
claim/release lifecycle and auto-released labeled by a daemon — all behind a reconciled rate
limiter, exposed as one shared component both the SMTP and Gmail paths call."*
