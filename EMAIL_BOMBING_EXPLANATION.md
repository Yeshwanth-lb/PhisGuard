# PhishGuard — Email Bombing Protection: Complete Technical Reference

> **Audience:** engineers, SOC analysts, or anyone recreating / extending this system.
> Everything in this document reflects the live build as of 2026-07-02.

---

## 1. What is email bombing?

Email bombing is an attack where someone **floods a victim's inbox with hundreds or thousands of emails in a short period**. The goal is not to deliver a phishing email directly — it is to create so much noise that the victim cannot find critical alerts buried in the flood.

### Type 1 — Direct SMTP flooding
The attacker connects directly to a mail server and fires thousands of emails from one place. Simpler and easier to block (per-IP rate limiting catches it).

### Type 2 — Subscription bombing (the real modern threat)
The attacker uses a free online tool: enter the victim's email and the tool auto-registers it on hundreds of legitimate services — newsletters, e-commerce, forums, apps. Within minutes the inbox fills with emails from Amazon, GitHub, LinkedIn, and real services. **Every email is legitimate and passes all authentication checks.**

---

## 2. Why subscription bombing is dangerous — the real attack sequence

```
9:00 AM  Attacker already has the victim's password (breach, credential stuffing, etc.)

9:01 AM  Before logging in, attacker enters victim@company.com into
         a subscription bombing tool. Tool submits 500 sign-up forms.

9:02 AM  Inbox starts filling up:
           "Welcome to Amazon"                    (amazon.com)
           "Confirm your GitHub account"          (github.com)
           "Thanks for subscribing"               (newsletter.com)
           ... 497 more emails in minutes

9:04 AM  Attacker logs into victim's bank with the stolen password.
         Bank sends "New device login detected" to victim's inbox.
         Bank sends "Sign-in from a new location" to victim's inbox.
         These alerts are BURIED in the flood.

9:05 AM  Attacker changes account details, makes a transfer.
         Victim has no idea. The bomb hid all the warning signs.
```

**Key point:** The attacker is NOT trying to obtain the OTP. They already have the password. The bomb hides the **account-change notifications** that would otherwise warn the victim. Every individual email in the flood is genuine — the attack is in the volume and timing.

---

## 3. PhishGuard's two-layer defence

### Layer A — SMTP Rate Limiter
**File:** `app/security/smtp_rate_limiter.py`
**Purpose:** Stop Type 1 (direct flooding of SMTP gateway port 8025)

Before reading any email, four counters are checked:

| Counter | Limit | What it stops |
|---|---|---|
| Per sending IP | 200/min (demo) / 10/min (prod) | One machine flooding directly |
| Per sender domain | 20/hour | One domain blasting many emails |
| Per recipient inbox | 30/min | 500 rotating IPs all targeting same person |
| Global | 200/min (demo) / 60/min (prod) | Total system overload |

The **per-recipient counter** is the most critical — it catches an attacker using 500 different IPs all targeting the same inbox.

Returns **SMTP 421** (temporary failure — MTA retries later). No legitimate email is permanently lost.

**Tarpit:** waits 2 seconds before returning 421. A bot sending 500/min is slowed to ~30/min.

All limits are configurable: `SMTP_RATE_PER_IP`, `SMTP_RATE_PER_DOMAIN`, `SMTP_RATE_PER_RCPT`, `SMTP_RATE_GLOBAL`.

> **Demo note:** Per-IP and global limits are raised to 200/min for the demo (all emails come from the same laptop IP). In production these would be 10/min and 60/min.

### Layer B — Inbox Bombing Detector
**File:** `app/security/bombing_detector.py`, `app/security/bombing_pipeline.py`
**Purpose:** Stop Type 2 (subscription bombs from legitimate sources)

Since every individual email is legitimate, PhishGuard **stops watching the sender and watches the recipient** instead.

---

## 4. Bombing detection — how the score is computed

Three signals are combined into a score (not a hard AND gate, so the system degrades gracefully when some signals are absent):

### Signal 1 — Volume (40 points, gateway signal)
```
Emails to this recipient in the last 5 minutes:
  < 20   →  score = 0  (detection gated entirely — no further checks)
  ≥ 20   →  score += 40
```

### Signal 2 — Sender Diversity (graduated: 0 / 20 / 40 points)
```
What fraction of window emails are from domains this recipient
has NEVER received from before?

  ≥ 70%  → +40  (strong signal)
  50–70% → +20  (moderate signal)
  < 50%  →  +0
```
**Cold-start protection:** If the recipient has seen fewer than 10 sender domains historically (e.g. a new employee), diversity is downweighted — only ≥ 90% new domains gets partial credit. This prevents false positives for new accounts.

### Signal 3 — Subject Pattern (graduated: 0 / 10 / 20 points, English only)
```
What fraction of window emails match subscription-style subjects?
("Confirm your email", "Welcome to...", "Thanks for signing up", etc.)

  ≥ 60%  → +20
  30–60% → +10
  < 30%  →  +0
```
This is the **weakest and most evadable signal** — regex-based, English only. It is a booster that adds confidence when the other signals are present, not a required condition.

**Detection threshold: score ≥ 60**

| Scenario | Volume | Diversity | Pattern | Score | Result |
|---|---|---|---|---|---|
| Subscription bomb (English) | +40 | +40 | +20 | 100 | **DETECTED** |
| Subscription bomb (non-English, high diversity) | +40 | +40 | 0 | 80 | **DETECTED** |
| Subscription bomb (moderate diversity) | +40 | +20 | +20 | 80 | **DETECTED** |
| High-volume all-hands day | +40 | +40 | 0 | 80 | **DETECTED** (see §5) |
| One-domain newsletter blast | +40 | 0 | 0 | 40 | Not detected |
| Below volume threshold | 0 | any | any | 0 | Not detected |

**Early velocity trigger** (fires on email 5 — before reaching email 20):
If 5+ subscription-pattern emails arrive within 30 seconds → bot speed → hold fires immediately. In a real attack, hold is active by email 5 and captures emails 6 through 500.

---

## 5. The four-tier asymmetric response during a hold

This is the most critical design decision. A naive "hold everything" response would **help the attacker** — the bomb is designed to bury account alerts.

Every email arriving during an active bombing hold is classified into one of four tiers:

### Tier 1 — PRIORITY: surface immediately (never held)
Condition: email is from a **DMARC-aligned** sender on a **protected TLD** (`.bank`, `.gov.in`, `.insurance`).

These TLDs are exclusively reserved for regulated entities (licensed banks, Indian government bodies, licensed insurers). An attacker **cannot register** `fake.bank` — it requires regulatory documentation and annual re-verification with the fTLD registry or NIC. The trust decision is based on authentication, not email content.

**Emails that get Priority treatment (demo set — 7 examples):**
```
alert@axisbank.bank      — "Your OTP for fund transfer is 778451"
otp@sbi.bank             — "Your SBI NetBanking login OTP is 443120"
secure@kotak.bank        — "Transaction OTP: 901844"
alerts@yesbank.bank      — "Security alert: sign-in from a new device"      ← not an OTP
statements@idfcbank.bank — "Your monthly account statement is ready"        ← not an OTP
noreply@incometax.gov.in — "Your income-tax refund has been processed"      ← not an OTP
policy@licindia.insurance — "Policy renewal confirmation"                   ← not an OTP
```

**Critical point:** Priority is NOT the word "OTP" — it is DMARC alignment from a protected TLD. Any authenticated `.bank`/`.gov.in`/`.insurance` email is surfaced, whether it's an OTP, a security alert, a statement, or a policy notice.

**What happens to a SPOOFED `.bank` email:**
If someone sends `From: alert@hdfc.bank` without valid DKIM (`d=hdfc.bank` DKIM signature), it fails DMARC alignment → **Tier 4 Quarantine**, with a `critical_sender_spoofed` warning logged.

Label applied to Gmail: `PhishGuard-Priority`

### Tier 2 — NOISE: buffer, release labeled (subscription flood)
Emails matching known subscription/newsletter patterns (`List-Unsubscribe` header present, sender is a high-volume brand like Spotify/Coursera/GitHub). These are the flood — the attacker's tool. They are held, then released after the bombing window expires with a `[Possible Bombing Noise]` label so the user knows their inbox was under attack.

Label: `PhishGuard-Released` → `[Possible Bombing Noise]`

### Tier 3 — UNCERTAIN: buffer, release labeled (business mail)
Known business senders (pre-established before the attack — contacts the system has seen before) that arrive during the bomb window. Held briefly but released with a `[Received During Mail Bomb]` label.

Label: `PhishGuard-Released` → `[Received During Mail Bomb]`

### Tier 4 — QUARANTINE: blocked (spoofed critical senders)
Emails that claim to be from a protected TLD (`.bank`, `.gov.in`, `.insurance`) but **fail DKIM/DMARC authentication**. These are definitively spoofed — an attacker trying to slip a fake bank alert into the flood. Quarantined with label `[PHISHGUARD QUARANTINE — spoofed domain.bank]`.

Label: `PhishGuard-Quarantined`

**Routing decision code (simplified from `bombing_pipeline.py`):**
```python
if is_authenticated_protected_sender(email):
    → TIER 1: deliver_now (PhishGuard-Priority)
elif is_spoofed_protected_sender(email):
    → TIER 4: quarantine
elif is_subscription_noise(email):
    → TIER 2: hold then release (Possible Bombing Noise)
else:
    → TIER 3: hold then release (Received During Mail Bomb)
```

**The default is always surface.** Only positively-identified subscription subjects are held. Anything uncertain delivers.

---

## 6. Demo script — how it works

**File:** `scripts/demo_bombing_all_labels.py`
**Wrapper:** `scripts/run_bombing_demo.sh`

### What the script sends (38 emails total)
```python
NOISE    = 26 emails  # newsletter/signup flood (Spotify, GitHub, Notion, etc.)
UNCERTAIN = 3 emails  # business contacts (Infosys, Deloitte, Globex)
PRIORITY  = 7 emails  # authenticated critical senders (3 OTPs + 4 non-OTP)
SPOOF     = 2 emails  # spoofed .bank without valid DKIM (HDFC, ICICI)
```

### Setup (critical — must run before the flood)
```python
# 1. Pre-establish business contacts so they land Tier 3, not Tier 2
for frm, dom, subj, body in UNCERTAIN:
    bp.evaluate(VICTIM, frm, parsed(dom, "earlier", frm), raw(frm, "earlier"))

# 2. Clear any prior attack state
bd.clear_attack(VICTIM)

# 3. Trigger bombing mode (velocity trigger on email 5)
for i in range(6):
    bp.evaluate(VICTIM, f"x@noise{i}.com", ...)
```

### DKIM simulation
The script patches `dkim.DKIM` with a `_FakeDKIM` class that:
- Returns `True` (DKIM pass) for any email that has a `DKIM-Signature: d=<domain>` header
- Validates that the signing domain matches the `From:` domain

Priority emails are sent with `dkim=dom` (DKIM-Signature header set to their own domain → aligned → TIER 1).
Spoof emails are sent without a DKIM header → fail alignment → TIER 4.

### Option 2 — Hidden-alert analysis
Prints which authenticated critical senders were surfaced, with OTP codes and numeric amounts redacted (`[redacted]`). Shows the demo reviewer exactly what the bomb tried to bury.

### Option 3 — AI analyst narrative
Calls the LLM to generate a 3-sentence analyst summary of the incident:
1. What happened (volume + composition)
2. What the system did (surfaced Priority, buffered noise, quarantined spoofs)
3. Takeaway (e.g. "classic distraction tactic to mask account takeover")

Falls back to a deterministic template if LLM is unavailable. Never fabricates numbers — all facts are computed before the prompt.

### JSON incident report
Written to `data/bombing_reports/bombing_report_YYYYMMDD_HHMMSS.json` in the container.

**Schema:**
```json
{
  "report_type": "email_bombing_incident",
  "generated_at": "2026-07-02T06:27:00",
  "detection": {
    "target_inbox": "victim@company.com",
    "bombing_mode": "active",
    "trigger": "velocity",
    "emails_in_flood": 38
  },
  "tier_breakdown": {
    "priority_surfaced": 7,
    "noise_buffered": 26,
    "uncertain_delivered": 3,
    "quarantined_spoofed": 2
  },
  "hidden_alerts": [
    {
      "sender_domain": "axisbank.bank",
      "type": "authenticated critical sender",
      "authenticated": true,
      "alignment": "DKIM/DMARC"
    }
  ],
  "ai_summary": "...",
  "privacy_note": "No email body content included. OTP codes and numeric amounts are redacted."
}
```

**Privacy:** No email body content is ever written. Any sequence of 3+ digits is replaced with `[redacted]` (covers OTPs, amounts, reference numbers).

### Wrapper script — auto-pulls report to Mac
```bash
bash scripts/run_bombing_demo.sh
```
Does: copy script into container → run demo → pull latest JSON report to `./data/bombing_reports/` on the host Mac via `docker cp`.

Why needed: `/app/data` is a named Docker volume (not a bind mount), so files written inside the container don't auto-appear on the Mac.

---

## 7. Running the demo — commands

```bash
# Full demo (recommended — copies script, runs, pulls report):
bash scripts/run_bombing_demo.sh

# Run directly in container (no report pull):
docker exec -w /app phishguard-app python3 demo_bombing_all_labels.py

# Watch logs while running:
docker logs -f phishguard-app 2>&1 | grep -E "bombing|priority|quarantine|spoofed"
```

**Expected output:**
```
✓ bombing mode active — now delivering the flood...

Delivered 38 emails. Breakdown:
   [PhishGuard-Priority]        7  (authenticated critical senders surfaced instantly)
   [Possible Bombing Noise]    26  (newsletter flood)
   [Received During Mail Bomb]  3  (business mail)
   [PHISHGUARD QUARANTINE]      2  (spoofed .bank blocked)

🎯 Hidden-alert analysis — what the bomb tried to bury:
   ▸ CRITICAL Your OTP for fund transfer is [redacted]
     from axisbank.bank — authenticated critical sender (DKIM/DMARC-aligned)
   ... (7 total)

🧠 AI analyst summary:
   An email-bombing attack flooded the inbox with 38 messages ...
```

---

## 8. SOC workflow during an attack

**Slack alert fires immediately:**
```
🌊 PhishGuard — Inbox Bombing Attack Detected
Target inbox:   victim@company.com
Emails in 5min: 47
Trigger:        velocity (5 subscription emails in 30s)
New domains:    98%
Hold duration:  20 minutes
```

**Dashboard:** Orange warning banner on the Overview tab showing which inbox is under attack with a countdown timer. "Clear Hold" button releases immediately.

**Auto-expiry:** Hold releases automatically after 20 minutes (configurable via `BOMBING_HOLD_MINUTES`).

---

## 9. Protected TLD security model

| TLD | Registry | Who can register | Barrier |
|---|---|---|---|
| `.bank` | fTLD Registry | Licensed regulated financial institutions only | Must prove regulatory standing (FDIC/RBI), annual re-verification |
| `.gov.in` | NIC (India) | Indian government bodies only | No public registration — NIC-assigned only |
| `.insurance` | fTLD Registry | Licensed insurance entities only | Same as `.bank` |

**Can an attacker register `evil.bank`?** No — ICANN and fTLD require regulatory documentation. The attack surface is:
1. Compromising a real `.bank` domain (nation-state level, not email phishing)
2. Using `hdfcbank.com` instead (caught by the normal phishing pipeline as L1/L2/structural)

---

## 10. What is NOT yet built

**`.com`/`.co.in` bank domains in trusted list:** Real users get HDFC mail from `hdfcbank.com`, SBI from `sbi.co.in`. These currently go through the normal phishing pipeline rather than getting Priority treatment. Post-demo task: populate the `trusted_domains` table with real bank `.com` domains.

**Gmail Workspace real-time ingestion:** The code infrastructure exists (`pubsub_watcher.py`). What is missing is a service account with domain-wide delegation and an `INBOX_INGESTION_ENABLED` feature flag. For a real deployment: add a Workspace routing rule (admin config, no code change).

**Demote-trusted-bulk-mail fix:** Senders like `no-reply@spotify.com` are in the trusted-sender list, which means they *skip* the bombing noise classification and route differently. Post-demo: these bulk-mail senders should be moved to a separate "known-bulk" list that forces them into Tier 2 during a bombing attack.

---

## 11. All configurable thresholds

| Env var | Default | What it controls |
|---|---|---|
| `BOMBING_ANALYSIS_WINDOW_SECS` | 300 (45 in demo) | Window for volume counting |
| `BOMBING_VOLUME_THRESHOLD` | 20 | Emails before scoring begins |
| `BOMBING_VELOCITY_THRESHOLD` | 5 | Subscription emails in 30s → early trigger |
| `BOMBING_VELOCITY_WINDOW_SECS` | 30 | Velocity detection window |
| `BOMBING_DIVERSITY_RATIO` | 0.70 | Fraction of new domains for +40 |
| `BOMBING_DETECT_SCORE` | 60 | Score threshold for detection |
| `BOMBING_HOLD_MINUTES` | 20 | Hold duration after detection |
| `BOMBING_COLD_START_MIN_HISTORY` | 10 | Min known domains before diversity is trusted |
| `SMTP_RATE_PER_IP` | 10 (200 demo) | Per-IP limit |
| `SMTP_RATE_PER_RCPT` | 30 | Per-recipient limit |
| `SMTP_RATE_GLOBAL` | 60 (200 demo) | Global limit |
| `BOMBING_REPORT_DIR` | `data/bombing_reports` | Where JSON reports are written |

---

## 12. For management — one paragraph

> *"Email bombing tools are freely available online. An attacker enters a victim's email address and within minutes floods their inbox with hundreds of legitimate emails from Amazon, GitHub, and thousands of other real services — every email passes all security checks because it genuinely came from those services. The attack is designed to bury account-change alerts and new-login notifications so the victim does not notice while the attacker acts on a stolen password. PhishGuard detects this in two ways: a fast check fires after just 5 subscription emails in 30 seconds, well before email 20, and a deeper scoring system works even for non-English attacks because its strongest signals — volume spike and sender diversity — are language-independent. When an attack is detected, PhishGuard does not hold all emails, which would help the attacker. It classifies every email in the flood into four tiers: authenticated critical-sender emails (bank OTPs, security alerts, government notices, insurance confirmations) are surfaced immediately; subscription noise is buffered and released labeled; business mail is similarly buffered; and spoofed bank emails that fail authentication are quarantined. The SOC sees the attack in real time via Slack and the dashboard, bulk-rejects the noise with one click, and the hold expires automatically after 20 minutes."*
