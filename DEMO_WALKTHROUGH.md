# PhishGuard — Email-Bombing Defense: Demo Walkthrough

A single flowing explanation per topic — read it out as you show the screen.
`💻 RUN` = command to type · `👀 SHOW` = what to point at.

---

## 1. What an email bomb actually is

An email bomb isn't spam — it's a *cover attack*. The attacker has just done something that
triggers ONE real alert to you: an OTP, a "was this you?" login notice, a bank confirmation. To
stop you from seeing it, they sign your address up to thousands of newsletters in minutes, so
your inbox floods and the one email that matters is buried as #487 of 2,000. PhishGuard's job
isn't to block the flood — it's to **surface the one real alert, quietly isolate the noise, and
never drop or hold a single message.** We call it asymmetric defense. Technically, all mail
comes through our inbound SMTP gateway (port 8025), and detection runs **per-recipient in real
time** — we track a rolling window of recent arrivals for each inbox and react as the flood builds.

---

## 2. Why the obvious fix fails

The naive response is "detect the bomb, then hold everything for a human to review" — but that
buries the OTP a *second* way, stuck in a review queue at 2 AM. And deciding what's important by
reading the subject line is naive: an attacker just sends a fake "Your OTP is 838201" from a
throwaway domain and it sails through. So instead of a human queue, we tier every email by **who
provably sent it, not by what the subject says** — and there's no holding-for-a-human anywhere
in the flow.

---

## 3. The core idea — three tiers, decided by authentication

While an inbox is under an active bomb, every incoming email is sorted into one of three tiers.
**Tier 1 (Important)** is an *authenticated* critical sender — a bank/government/trusted domain
that is cryptographically proven to be genuine — and it's **delivered instantly** with a
`[PhishGuard-Priority]` tag, never buffered. **Tier 2 (Noise)** is bulk mail identified by
structural signals — a `List-Unsubscribe` header, `Precedence: bulk`/`List-Id`, a first-time
sender, a mass-mailer (Mailchimp/SendGrid) fingerprint, or a brand-new domain — and it's buffered
and later released tagged `[Possible Bombing Noise]`. **Tier 3 (Uncertain)** is everything else;
the default is to deliver, so it's buffered and released tagged `[Received During Mail Bomb]`.
The whole thing turns on one principle: **trust is earned by cryptography, not keywords** — a
real bank OTP is delivered instantly *because the message is cryptographically signed by the
bank*, while a "Your OTP" email from a throwaway domain is never fast-tracked, and a spoofed
`.bank` that fails the signature check is quarantined as phishing. Those tier checks read the
subject and headers only — never the message body — for privacy.

---

## 4. How a bomb is detected

A single five-minute window is easy to evade by sending slowly, so we watch three windows at the
same time and fire if any one trips: a **fast** window (5 newsletter-style emails in 30 seconds,
i.e. bot speed), a **standard** window (a high score over 20 emails in 5 minutes), and a
**slow-drip** window (100 emails in an hour, to catch low-and-slow floods). The score that drives
the standard window is **language-independent**: it's mostly raw volume plus how many *different*
senders are hitting the inbox, with the English subject pattern adding only a small boost — so a
non-English bomb is caught just as well. Internally each inbox keeps a rolling list of recent
arrivals and all three windows are computed from it; once triggered, "bombing mode" stays on as
long as the flood continues and switches off after a quiet period (with a hard cap so it can
never get stuck on forever).

---

## 5. Authentication is the trust signal

This is the heart of the design. We only fast-track a critical email if it's **cryptographically
proven** to come from the domain it claims — either a valid DKIM signature for that domain, or an
SPF pass from the sending server that lines up with the From address (together that's what DMARC
alignment means). We verify each DKIM signature individually and only trust one that actually
verifies *and* genuinely signs the From header — which defeats a clever spoof where an attacker
attaches a valid signature for their *own* throwaway domain alongside a fake "this is from the
bank" header. SPF is checked against the live connecting IP and must line up with the From
domain, so a bare "SPF passed" on an unrelated domain doesn't count. If something *claims* to be
a protected sender (a `.bank`, a trusted domain) but can't prove it, that's the strongest phishing
signal there is — it's quarantined, not delivered.

---

## 6. Nothing is ever lost

Buffered mail is written to disk in a crash-safe database (SQLite in WAL mode), so even if the
server restarts in the middle of a bomb, the held mail survives. A background worker releases
anything past the analysis window, tagged, and only then marks it delivered — and a message is
*claimed* atomically before delivery, so even if multiple workers run, nothing is sent twice; if
a worker dies mid-delivery, the claim is recovered and retried on the next cycle. The guarantee
we can state plainly: **nothing is dropped, nothing is held for a human, and nothing is delivered
twice.** The buffer is also bounded per inbox — if it ever fills, overflow mail is delivered
immediately (tagged) rather than dropped.

---

## 7. The rate-limiter trap, and how we handle it

There's a subtle trap worth calling out. The gateway also runs a rate limiter that caps roughly
30 emails per minute to any one inbox — and during a bomb *that* limit would start rejecting mail,
including the very OTP we're trying to protect. So the moment an inbox enters bombing mode, we
turn the per-recipient limit off *for that inbox* and let the smarter triage engine take over. The
other protections still stand — per-IP and global limits, plus dropping the TCP connection of any
IP that keeps hammering us — so the gateway stays protected while the blunt per-recipient limit
can never bury the alert it's supposed to be guarding.

---

## 8. Not blocking real OTPs

Legit OTP and "verify your account" emails *look* like phishing — urgency, the word "verify", a
link — so a content-based detector sometimes flags the real ones. We fixed that with an
authenticated-sender fast-pass: if an email is cryptographically aligned to its own domain **and**
that domain is established (not registered yesterday) **and** the sending IP isn't flagged abusive,
then those scary content words don't condemn it. The reputation gate matters — alignment alone
isn't enough, because a phisher can sign their *own* throwaway domain; so a brand-new aligned
domain or an abusive IP still gets caught, and hard blocklist/VirusTotal hits always quarantine
regardless.

---

## 9. 🔴 LIVE DEMO

> Prep: two terminals + the Gmail inbox (`yeshwanthlb0@gmail.com`) open; click the
> **PhishGuard-Priority** label in the sidebar so it's ready to show.

**Step 1 — fire a realistic mixed bomb.**
💻 `PYTHONPATH=. python3 scripts/send_mixed_bomb.py --rcpt ceo@company.com`
Say: "25 emails at once — newsletter sign-ups, OTP/security codes, two spoofed bank alerts, and
some business mail — exactly like a real bomb."

**Step 2 — show it was detected instantly.**
💻 `curl -s localhost:8000/health | python3 -m json.tool`
👀 Point at `bombing_detector.active_attacks: 1`, the attacked inbox, and the `bombing_buffer`
noise count. Say: "The gateway detected the bomb instantly and flipped this inbox into triage mode."

**Step 3 — the spoofed banks get quarantined (the highlight).**
💻 `docker logs --since 2m phishguard-app | grep -E "spoofed_critical|quarantined"`
Say: "These two claimed to be `.bank` domains but couldn't produce a valid signature — caught and
quarantined, in the middle of the flood."

**Step 4 — authenticated OTPs delivered instantly.**
💻 `PYTHONPATH=. python3 scripts/demo_bombing_realmail.py`
👀 Click the **PhishGuard-Priority** label — signed bank OTPs (axisbank/sbi/kotak `.bank`)
delivered immediately. Say: "Real, *signed* bank OTPs are surfaced instantly — the opposite
treatment from the noise."

**Step 5 — the noise releases, labeled.**
Say: "Within about a minute the buffered noise is released into the inbox, clearly tagged
`[Possible Bombing Noise]`, so it can be swept. Nothing was deleted; nothing is stuck in a queue."

---

## 10. Likely questions

- **Couldn't an attacker spoof a bank for priority?** No — Tier 1 needs real DMARC alignment; a
  spoof fails it and is quarantined. We even block the multi-signature trick by only trusting the
  signature that actually verified.
- **A bomb in another language?** Detection is volume- and sender-diversity-based, so it's
  language-independent.
- **Server crashes mid-bomb?** The buffer is on disk (WAL) and in-flight deliveries are recovered —
  nothing is lost and nothing is double-sent.
- **Does the rate limiter get in the way?** Its per-recipient limit is bypassed once an inbox is
  under attack, so it can't reject the OTP; the other limits still protect the gateway.
- **Gmail, or just your gateway?** The same engine is a shared component the Gmail ingestion path
  also calls — it's there, just turned off until credentials are configured.
- **How is it tested?** Around 391 automated tests, including adversarial cases (spoofed banks,
  multi-signature DKIM, crash recovery, slow-drip). It's deployed in Docker, runs non-root, and was
  hardened after a full security review.

---

## 11. One-line close

"Old way: detect the bomb, guess what's important from the subject, and park the rest in a queue a
human has to clear. **Our way: detect across three time-scales, decide what's important by
cryptographically verifying who actually sent it, deliver that instantly, and quietly
buffer-then-auto-release the noise — nothing dropped, nothing held, nothing trusted on forgeable
evidence."**
