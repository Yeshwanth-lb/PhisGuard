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

---

## 11. Technical Deep-Dive (for the engineering questions)

### 11.1 Tech stack
Python 3 · **FastAPI** (REST + dashboard) · **aiosmtpd** (inbound SMTP gateway, port 8025) ·
**SQLite (WAL)** for state/buffer · **Redis** (L1 OSINT cache) · **dkimpy** (DKIM crypto
verify) · **pyspf** (SPF) · **Gmail API** (inbox delivery) · **structlog** (JSON logs) ·
Docker Compose (13+ services) · ~390 **pytest** tests. Runs as a single non-root uvicorn worker.

### 11.2 Where the code lives (module map)
| File | Responsibility |
|------|----------------|
| `app/layer7_gmail/smtp_receiver.py` | SMTP `handle_DATA` entry; rate-limit → pipeline → triage → deliver/buffer; the **release-worker daemon** |
| `app/security/bombing_detector.py` | Detection: cascading windows, scoring, per-recipient state, sliding cooldown |
| `app/security/bombing_triage.py` | The **3-tier classifier** (`classify()`) |
| `app/security/critical_sender.py` | **DMARC alignment** (DKIM crypto + SPF), protected-TLD / spoofed-critical logic |
| `app/security/bombing_pipeline.py` | **Shared component** `evaluate()` — called by BOTH SMTP and Gmail paths |
| `app/security/smtp_rate_limiter.py` | 4 sliding-window counters, tarpit, 421, TCP-drop |
| `app/storage.py` | `bombing_buffer` table + claim/release/reclaim helpers (WAL) |
| `app/pipeline.py` | L1–L5 orchestrator + the **authenticated-sender fast-pass** |

### 11.3 Request flow through `handle_DATA` (per email)
1. **Rate limiter** `check(peer_ip, mail_from, rcpt, skip_recipient_limit=is_under_attack(rcpt))`
   → if blocked: tarpit (sleep) → `421`; repeat offenders → TCP socket dropped.
2. **Full pipeline** `analyze_email(raw, settings)` → L0 pre-filter → L1 OSINT → (auth fast-pass)
   → L2 AI → L3 sandbox → L5 ML → blended verdict.
3. **Bombing pipeline** `evaluate(rcpt, mail_from, parsed, raw, peer_ip)`: reads first-contact,
   calls `detector.record(...)` (updates windows), and if under attack calls `triage.classify(...)`.
4. **Act on the decision:** `deliver_now` → tag `[PhishGuard-Priority]` + `deliver_to_inbox()` →
   `250`; `buffer` → `storage.buffer_add(tier=…)` (overflow-deliver if full) → `250`;
   `phishing` (spoofed_critical) → quarantine routing; not-under-attack → normal routing.

### 11.4 Detection internals (`bombing_detector.record`)
- **Per-recipient state**: `arrivals` = `deque[(ts, sender_domain, is_pattern)]` retained for the
  widest window (1h); `seen_domains` = bounded **LRU** (`OrderedDict`); `under_attack_until`,
  `attack_started_at`. Guarded by a `threading.Lock`.
- **Three windows** from one deque: velocity (pattern matches in last 30s ≥ 5), slow-drip
  (`len(arrivals) ≥ 100`), standard (subset within last 300s, `score ≥ 60`).
- **Score** = volume(40, gates everything) + diversity(40, new-domain ratio, cold-start
  down-weighted) + subject-pattern(20). Language-independent core.
- **Sliding cooldown:** non-high-signal mail refreshes `under_attack_until = now+300s`, capped by
  `ATTACK_MAX_SECS`. Clock seam `_now()` makes the windows testable without real waits.

### 11.5 DMARC alignment (`critical_sender`) — the anti-spoof core
- `is_critical_sender(...)` → `protected?` (TLD in `BOMBING_PROTECTED_TLDS` or org-domain trusted)
  **AND** `aligned?` (`_dkim_aligned OR _spf_aligned`).
- `_dkim_aligned`: **verifies EACH `DKIM-Signature` individually** (`dkim.DKIM(raw).verify(idx=i)`)
  and only trusts a *verified* sig whose `d=` org-aligns with `From` **and** whose `h=` signs
  `From` — defeats the multi-signature spoof (valid throwaway sig + fake `d=<victim>` header).
- `_spf_aligned`: real SPF check vs the live **peer IP** for the envelope MAIL FROM, **and** that
  envelope domain must org-align with `From` (bare `spf=pass` on a non-aligned domain is rejected).
- `organizational_domain()` = eTLD+1 with a multi-part-suffix table. Protected claim that fails
  alignment → `signal="spoofed_critical"` → phishing route.

### 11.6 Triage (`bombing_triage.classify`) — order matters
1. `spoofed_critical` → **phishing**; `critical` → **Tier 1 deliver_now**.
2. Tier-2 structural signals (headers only, never body): List-Unsubscribe, Precedence:bulk/List-Id,
   first-contact, ESP fingerprint, new-domain → **Tier 2 noise**.
3. Else **Tier 3 uncertain** (default deliver). `is_high_signal()` is only a label hint, never a
   fast-track. Privacy: subject + structural headers only.

### 11.7 Durable buffer + release worker
- `bombing_buffer(id, recipient, scan_id, timestamp, tier CHECK(important|noise|uncertain),
  released, raw_email BLOB, sender_domain, subject, claimed_at, delivered_at)`; `PRAGMA
  journal_mode=WAL; synchronous=NORMAL`.
- **Lifecycle:** `buffer_add`(released=0) → `buffer_claim` (atomic `UPDATE … WHERE released=0`;
  only the winner delivers — safe across workers) → `buffer_mark_released` (stamps `delivered_at`)
  → `buffer_purge_expired` deletes only *delivered* rows. `buffer_reclaim_stale` recovers crashed
  claims (no drop).
- **Release worker** (daemon, polls 15s): `buffer_list_due(window)` → claim → `_tag_subject` with
  the tier label → `deliver_to_inbox` (relay fallback) → mark delivered → purge. Per-recipient cap
  → overflow delivers immediately-labeled.

### 11.8 Rate limiter + reconciliation
4 sliding windows (per-IP 10/60s, per-domain 20/3600s, **per-recipient 30/60s**, global 60/60s);
`RLock`; 2s tarpit before `421`; burst Slack alert; **TCP hard-drop** after >3×421/60s. Under
attack the receiver passes `skip_recipient_limit=True` so the blunt cap can't reject the OTP.

### 11.9 Shared pipeline + dormant Gmail feed
`bombing_pipeline.evaluate()` is the single source of truth; `ingest_gmail_message()` is the
flag-gated (`INBOX_INGESTION_ENABLED`, default off) adapter `pubsub_watcher`/`historical_scanner`
call with the real delivered-to mailbox — identical tiers/labels/alerts.

### 11.10 Authenticated-sender fast-pass (false-positive fix)
In `analyze_email` after L1: if `is_dmarc_aligned(parsed, raw)` AND no L1 `domain_age` weak-hit
(established) AND `abuse_max_score < threshold` (clean IP) → deliver clean, skipping L2 content
scoring. Reputation-gated, so aligned-phishing on a new/abusive domain is NOT trusted. Toggle:
`auth_sender_fastpass`.

### 11.11 Key env knobs (documented defaults)
`BOMBING_VELOCITY_THRESHOLD/_WINDOW_SECS`, `BOMBING_VOLUME_THRESHOLD`, `BOMBING_SLOWDRIP_*`,
`BOMBING_MODE_COOLDOWN_SECS`, `BOMBING_ATTACK_MAX_SECS`, `BOMBING_ANALYSIS_WINDOW_SECS` (release
window — 45 for demos), `BOMBING_PROTECTED_TLDS`, `BOMBING_ESP_FINGERPRINTS`,
`BOMBING_MAX_BUFFER_PER_RCPT`, `BOMBING_TCP_DROP_THRESHOLD`, `BOMBING_DEMO_MODE`,
`INBOX_INGESTION_ENABLED`, `auth_sender_fastpass`.

### 11.12 Testing & verification
~390 pytest tests incl. adversarial: multi-signature DKIM spoof, spoofed `.bank` → quarantine,
slow-drip detection, buffer-survives-restart + crash-reclaim, atomic-claim (no double-deliver),
SSRF blocking, endpoint-auth, JWT alg/forgery. DKIM/SPF/Gmail mocked (no network in tests).
Deployed in Docker, non-root, single worker, verified live via `/health`.

### 11.13 One-sentence technical summary
"A per-recipient streaming detector (three sliding windows over an in-memory deque) gates a
cryptographic-authentication classifier (per-signature DKIM + peer-IP SPF alignment) that tiers
each email; non-critical mail is parked in a crash-durable WAL-backed SQLite buffer with an
atomic claim/release lifecycle and auto-released labeled by a daemon — all behind a reconciled
rate limiter, exposed as one shared component both the SMTP and Gmail ingestion paths call."
