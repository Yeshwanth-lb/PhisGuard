# PhishGuard — Email-Bombing Defense: End-to-End Walkthrough

How every piece works, mapped to the real code. Pair this with `scripts/demo_e2e.sh`
(the presenter-paced runner). Run the demo with:

```bash
bash scripts/demo_e2e.sh            # default recipient ceo@company.com
NOPAUSE=1 bash scripts/demo_e2e.sh  # rehearsal, no pauses
```

---

## 0. The problem in one sentence

An **email bomb** is a *cover attack*: the attacker triggers **one** real alert to you
(an OTP, a "was this you?" login, a bank notice) and then signs you up to **thousands**
of newsletters so the real alert is buried as #487 of 2,000. The goal is not to spam —
it's to make you miss the one message that matters.

PhishGuard's response is **asymmetric**: surface the one real alert instantly, isolate
the noise, and **drop nothing / hold nothing for a human**.

---

## 1. How mail enters — the SMTP gateway

- All mail arrives at the **SMTP gateway on port 8025** (`app/layer7_gmail/smtp_receiver.py`,
  an `aiosmtpd` `Controller` bound to `0.0.0.0:8025`).
- Every message hits `handle_DATA()`. Detection + triage run **per-recipient, in real time** —
  there is no batch step.
- The gateway and the (flag-gated) Gmail ingestion path are **thin adapters**. Both call the
  same brain: `bombing_pipeline.evaluate(recipient, mail_from, parsed, raw_bytes, peer_ip)`.
  This guarantees identical detection, tiering, and labels regardless of entry point.

```
SMTP :8025 ─┐
            ├─► bombing_pipeline.evaluate() ─► detector + triage ─► decision ─► act
Gmail pull ─┘                                                                   (deliver / phishing / buffer)
```

---

## 2. How a bomb is DETECTED — three windows at once

`app/security/bombing_detector.py`, `record()`. Detection fires if **ANY** of three
windows trips. It is **language-independent** — volume + sender diversity alone is enough;
the subject pattern is only a confidence booster, never a gate.

| Window | Rule | Why it exists |
|---|---|---|
| **Fast / velocity** (30s) | ≥ **5** subscription-pattern emails in 30s | bot-speed signup burst → trip *before* the volume gate is reached |
| **Standard** (5 min) | weighted **score ≥ 60** | the main detector (see scoring below) |
| **Slow-drip** (1 hr) | ≥ **100** total emails | catches a low-and-slow flood that throttles under the 5-min gate |

**The score** (`_compute_score`, 0–100, volume gates everything):

- `+40` volume — ≥ `VOLUME_THRESHOLD` (20) emails in the window (below this → score 0).
- `+40` diversity — ≥ 70% of senders are *new* domains (`+20` if ≥ 50%).
- `+20` subject pattern — ≥ 60% match signup phrasing ("confirm your email", …). English-only, optional.

So: `volume + diversity = 80` (non-English bomb still detected); `volume + pattern = 60`
(low-diversity newsletter blast detected); `volume alone = 40` (a normal company all-hands
CC is **not** flagged).

**Cold-start grace:** a brand-new mailbox has seen 0 domains, so diversity would always read
100%. When history < `COLD_START_MIN_HISTORY` (10), diversity is down-weighted so a new
employee isn't flagged on day one.

**Sliding cooldown, not a fixed hold:** once tripped, "bombing mode" stays active while
bombing-ish mail keeps arriving and **auto-exits after 300s of quiet** (`COOLDOWN_SECS`),
hard-capped at 6h (`ATTACK_MAX_SECS`) so a trickle can't pin it open forever. A **high-signal**
email (likely the real OTP) does **not** extend the cooldown — so a lone alert can't keep
triage alive.

**On trip** (`_trigger`): logs `inbox_bombing_detected`, and fires a **Slack alert** (once per
inbox, suppressed 10 min after — `ALERT_SUPPRESS_SECS`). The dashboard banner reads
`active_attacks` from `/health` / `/api/bombing/active`.

---

## 3. How each email is TRIAGED — three tiers, decided by AUTHENTICATION

Only runs while a recipient is in active bombing mode. `app/security/bombing_triage.py`,
`classify()`. **Trust is earned by cryptography, not by keywords.**

### Tier 1 — IMPORTANT → delivered instantly, never buffered → `[PhishGuard-Priority]`
- ONLY an **authenticated critical sender** (`critical_sender.is_critical_sender`).
- Requires **both**: (1) From domain is a *protected* type (`.bank`/`.gov`/… in
  `PROTECTED_TLDS`, or an org domain in the trusted-domains table), **and** (2) the message is
  **DMARC-aligned**.
- Subject words alone do **not** qualify — this closes the "fake OTP from a throwaway domain"
  bypass.

### Tier 2 — NOISE → buffered, released labeled → `[Possible Bombing Noise]`
Language-independent **structural** signals (subject + headers only, **never the body**):
1. `List-Unsubscribe` present
2. `Precedence: bulk` or `List-Id` present
3. first-contact-ever sender domain (from the detector's history)
4. ESP relay fingerprint in `Received` (mailchimp / sendgrid / mailgun / amazonses / …)
5. very-new sender domain (WHOIS age — only if `BOMBING_TIER2_WHOIS` enabled)

### Tier 3 — UNCERTAIN → buffered, released labeled → `[Received During Mail Bomb]`
- The **default safety valve**. Business mail, non-English, empty subject, **and** a
  subject-only OTP/bank match from an *unauthenticated* sender all land here.
- Still delivered + soft-labeled (we never bury a possible alert) — just not fast-tracked.

### The spoof path → `spoofed_critical` → routed to phishing, **never delivered as trusted**
A message that **claims** a protected TLD (e.g. `security@hdfc.bank`) but **fails** alignment
returns the distinct `spoofed_critical` signal → the caller routes it to the phishing path.
This is the anti-spoof core.

---

## 4. How authentication (DMARC alignment) actually works

`app/security/critical_sender.py`. The From header is forgeable, so we compute alignment
**ourselves** — we don't trust the `Authentication-Results` header (absent on our own MTA,
and attacker-forgeable when present). **Trust = DKIM-aligned OR SPF-aligned. Fail-closed.**

- **DKIM alignment** (`_dkim_aligned`): we verify **each** `DKIM-Signature` *individually*
  with `dkimpy` (`dkim.DKIM().verify(idx=i)`), and only trust the `d=` of a signature that
  (a) cryptographically **passes**, (b) **organizationally aligns** with the From domain, and
  (c) actually **signs the From header** (`h=` includes `from`). Verifying each signature
  defeats the multi-signature spoof (attach one valid throwaway signature + a bogus
  `d=<victim>` header).
- **SPF alignment** (`_spf_aligned`): a live SPF check (`pyspf`) against the **connecting peer
  IP** for the envelope MAIL FROM, **and** that envelope domain must align with From. A bare
  `spf=pass` on a non-aligned domain does **not** count (that's how forged-From mail passes
  SPF). Peer IP exists only on the SMTP path; Gmail-ingested mail has none, so DKIM carries it.
- `checkdmarc` (optional) annotates whether the domain publishes an enforcing policy —
  informational only, never flips the trust decision.

> Alignment proves the From isn't spoofed; it does **not** imply the domain is reputable
> (a phisher can DKIM-sign their own throwaway domain). Tier 1 additionally requires the
> domain be a *protected* type, and the broader gateway pairs alignment with reputation.

---

## 5. How nothing is ever lost — the durable buffer + release worker

- Tier-2/3 mail is parked in a **crash-safe SQLite (WAL) buffer** (`bombing_pipeline.buffer` →
  `storage.buffer_add`). Synchronous write — no ack-before-persist; it survives a restart
  mid-bomb.
- Per-inbox buffer ceiling `MAX_BUFFER_PER_RCPT` (500). On overflow the message is
  **delivered immediately, labeled** instead of buffered — bounds storage, **never drops**.
- The **release worker** (`smtp_receiver._release_due`, polled every 15s) delivers every
  message older than `BOMBING_ANALYSIS_WINDOW_SECS` (`.env`: **45** for the demo; production
  default **300**), tags the subject by tier (`_tag_subject`), then marks it delivered.
- **Atomic claim before delivery** (`buffer_claim`) → uvicorn multi-workers never double-send.
- **Crash recovery:** a claim held > `CLAIM_STALE_SECS` (120) is reclaimed and retried; if a
  delivery fails the claim is reverted so it retries next cycle.

> **Guarantee: nothing dropped, nothing held for a human, nothing delivered twice.**

---

## 6. How a message reaches the inbox

`app/layer7_gmail/gmail_client.py`, `deliver_to_inbox()` injects the raw message straight into
Gmail via the API (`users().messages().insert`, `userId="me"`) and applies a Gmail label
(`PhishGuard-Priority` / `PhishGuard-Released` / …). Because it's `userId="me"`, **everything
lands in the authenticated mailbox** (`yeshwanthlb0@gmail.com`) regardless of the `To:` header —
which is why the live-gateway path and the realmail script both populate that one inbox.

---

## 7. Two complementary defenses the gateway also runs

- **Rate-limiter trap fix:** the gateway caps ~30 emails/min/inbox — during a bomb that would
  reject the OTP too. Once an inbox is under attack, the per-recipient limit is **bypassed**
  for it; per-IP, global, and TCP-drop protections still guard the gateway.
- **False-positive fix:** legit OTP/verify mail looks like phishing (urgency, "verify", a link).
  If it's aligned to its domain, the domain is established, and the IP isn't abusive, content
  tactics don't condemn it — but brand-new/abusive senders are still caught (reputation-gated).

---

## 8. What the demo script does, act by act (`scripts/demo_e2e.sh`)

1. **Preflight** — app health, scripts present, container up.
2. **Baseline** — `/health` shows `active_attacks: 0`.
3. **Fire the bomb** — `send_mixed_bomb.py` sends 25 realistic messages (15 signups, 5 OTP/
   security, 2 spoofed `.bank`, 3 business) to the live gateway → §2 trips detection.
4. **Detection** — `/health` shows `active_attacks: 1`; dashboard banner; Slack alert.
5. **Spoof quarantine** — container logs show `spoofed_critical` for the fake `.bank` (§3/§4).
6. **Payoff** — `demo_bombing_realmail.py` delivers real labeled mail: an authenticated bank
   OTP **instantly** as `[PhishGuard-Priority]`, plus a `[Possible Bombing Noise]` and a
   `[Received During Mail Bomb]` example. (Only the bank's DKIM is simulated offline — we can't
   forge a real bank's key; everything else is the real path.)
7. **Auto-release** — ~45s after act 3, the buffered flood releases itself into Gmail, labeled.

**Close line:** *Old way — detect the bomb, guess importance from the subject, park the rest in
a human queue. Our way — detect across 3 time-scales, verify who actually sent it, deliver that
instantly, buffer-then-auto-release the noise. Nothing dropped, nothing held, nothing trusted
on forgeable evidence.*
