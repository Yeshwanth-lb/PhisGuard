# Email Bombing Protection — Complete Explanation

---

## 1. What is email bombing?

Email bombing is an attack where someone **floods a victim's inbox with hundreds or thousands of emails in a short period**. The goal is not to send a phishing email directly — it is to create so much noise that the victim cannot find important emails buried in the flood.

There are two types:

**Type 1 — Direct SMTP flooding:**
The attacker directly connects to a mail server and sends thousands of emails from one place. Simpler and easier to block.

**Type 2 — Subscription bombing (the real modern threat):**
The attacker uses a free online tool where they enter the victim's email address. The tool automatically signs that email address up to hundreds of legitimate websites — newsletters, e-commerce, forums, apps. Within minutes the victim's inbox fills with emails from Amazon, GitHub, Mailchimp, LinkedIn, and hundreds of other real services. Every single email is legitimate and passes all security checks.

---

## 2. Why subscription bombing is dangerous — the real attack sequence

```
9:00 AM  Attacker already has the victim's email and password
         (bought from a breach, guessed, or stolen earlier)

9:01 AM  Before logging in, attacker enters victim@company.com
         into an email bombing tool.
         Tool submits 500 newsletter/sign-up forms across the internet.

9:02 AM  Victim's inbox starts filling up:
           "Welcome to Amazon"                (amazon.com)
           "Confirm your GitHub account"      (github.com)
           "Thanks for subscribing"           (newsletter123.com)
           "Verify your email"                (somesite.com)
           ... 496 more emails arriving in minutes

9:03 AM  Victim has 500+ unread emails. Inbox is completely unusable.

9:04 AM  Attacker logs into victim's bank with the stolen password.
         Bank sends a "New device login detected" alert to the victim's inbox.
         Bank sends a "We noticed a sign-in from a new location" notification.

9:04 AM  These critical alerts arrive buried in the victim's flood of 500 emails.
         Victim cannot see them. They are buried in subscription noise.

9:05 AM  Attacker changes account details, makes a transfer, or completes the fraud.
         Victim has no idea. The bomb hid all the warning signs.
```

**Key point:** The attacker is NOT trying to get the OTP by flooding the inbox. The attacker already has the password. The bomb hides the account-change notifications and new-login alerts that would otherwise warn the victim something is wrong and give them time to react.

**Why traditional security cannot stop this:**
- Every email comes from a legitimate source (Amazon, GitHub, Mailchimp)
- Every email passes SPF, DKIM, DMARC authentication
- Every email has no malicious links or attachments
- There is nothing wrong with any individual email
- The attack is in the volume and timing, not the content

---

## 3. What PhishGuard builds to defend against this

Two completely separate layers of protection:

---

### Layer A — SMTP Rate Limiter

**Purpose:** Stops Type 1 (direct flooding of the gateway port 8025).

Before reading an email, PhishGuard checks four counters:

| Counter | Limit | What it stops |
|---|---|---|
| Per sending IP | 10 emails/min | One machine flooding directly |
| Per sender domain | 20 emails/hour | One domain sending many emails |
| Per recipient inbox | 30 emails/min | 500 rotating IPs all targeting same person |
| Global | 60 emails/min | Total system overload |

The **per-recipient counter** is most critical. An attacker using 500 different IPs passes the per-IP check, but all go to the same inbox — that counter catches them.

Returns **SMTP 421** (temporary failure, MTA retries later). No legitimate email is permanently lost.

**Tarpit:** Waits 2 seconds before sending the 421. An automated tool sending 500 emails/min is slowed to ~30/min.

All limits are configurable via env vars: `SMTP_RATE_PER_IP`, `SMTP_RATE_PER_DOMAIN`, `SMTP_RATE_PER_RCPT`, `SMTP_RATE_GLOBAL`.

---

### Layer B — Inbox Bombing Detector

**Purpose:** Stops Type 2 (subscription bombs from legitimate sources).

Since every individual email is legitimate, PhishGuard **stops watching the sender and watches the recipient** instead. The attacker can rotate infinite domains. They cannot change who the victim is.

**Three signals, combined into a score (not a hard AND gate):**

**Signal 1 — Volume (40 points)**
```
How many emails has this recipient received in the last 5 minutes?
  Below 20  →  score 0  (detection gated entirely — no further checks)
  20 or more → score +40
```

**Signal 2 — Sender Diversity (graduated, 0/20/40 points)**
```
What fraction of the window emails are from domains
this recipient has NEVER received from before?

  ≥ 70%  → +40  (strong signal)
  50–70% → +20  (moderate signal)
  < 50%  →  +0  (not unusual)
```
Cold-start protection: if the recipient has seen fewer than 10 sender domains
historically (e.g. a new employee), diversity is downweighted — partial credit
only for extreme cases (≥ 90% new domains).

**Signal 3 — Subject Pattern (graduated, 0/10/20 points, English only)**
```
What fraction of window emails match subscription-style subjects?
("Confirm your email", "Welcome to...", "Thanks for signing up", etc.)

  ≥ 60%  → +20  (confidence booster)
  30–60% → +10  (partial credit)
  < 30%  →  +0
```
This is the weakest and most evadable signal — English-only, regex-based.
It is a booster, not a required condition.

**Detection threshold: score ≥ 60**

| Scenario | Volume | Diversity | Pattern | Score | Result |
|---|---|---|---|---|---|
| Subscription bomb (English) | +40 | +40 | +20 | 100 | **DETECTED** |
| Subscription bomb (non-English, high diversity) | +40 | +40 | 0 | 80 | **DETECTED** |
| Subscription bomb (moderate diversity) | +40 | +20 | +20 | 80 | **DETECTED** |
| Company all-hands / busy day (high volume + diverse senders) | +40 | +40 | 0 | 80 | **DETECTED** (see below) |
| Company newsletter blast (one domain) | +40 | 0 | 0 | 40 | Not detected |
| Below volume threshold | 0 | any | any | 0 | Not detected |

**The company all-hands case — why it is still safe:**

A legitimate all-hands email from many senders WILL trip detection (score 80 ≥ 60). This is a deliberate design trade-off: the system is sensitive to protect against real attacks.

But the response is harmless because of how routing works during a hold:
- All-hands subjects ("Q4 company update", "CEO announcement") match neither the high-signal list nor the subscription-noise list
- Unmatched subjects → **default: deliver immediately**
- No legitimate all-hands email is ever held
- The "false positive" only affects emails with explicit subscription subjects

The sensitivity buys detection of real attacks. The smart response neutralises the cost of false positives.

**Early velocity trigger (fires on email 5):**

If 5+ subscription-pattern emails arrive within 30 seconds → bot speed → hold fires immediately, before reaching email 20.

In a real attack: hold is active by email 5. Emails 6 through 500 are captured.

---

## 4. The three-way routing decision during a hold

This is the most critical piece. A naive "hold everything" response would help the attacker — the bomb is designed to bury account-change notifications.

**Every email arriving during an active bombing hold goes through:**

```python
if is_high_signal(subject):
    → SURFACE (deliver immediately)
elif is_subscription_pattern(subject):
    → HOLD (SOC Pending Review)
else:
    → SURFACE (deliver — default when uncertain)
```

**SURFACE examples (delivered immediately):**
- "Your one-time password is: 847291"
- "Password reset request"
- "New device login detected"
- "Security alert: unusual sign-in"
- "Your payment of USD 250 processed"
- "Unusual activity on your account"

**HOLD examples (subscription noise):**
- "Confirm your email address"
- "Welcome to Amazon Prime"
- "Please verify your account"
- "Thanks for signing up"

**SURFACE by default (unmatched):**
- "Team meeting Thursday at 3pm"
- "Q3 roadmap update"
- "Confirmez votre adresse e-mail" ← non-English
- "Invoice from Vendor Corp"
- (empty subject)

**The default is always SURFACE.** Only positively-identified subscription subjects are held. Any unmatched subject delivers. A held real alert is the worst failure this system can produce — when uncertain, err toward delivery.

---

## 5. SOC workflow during an attack

**Slack alert fires immediately:**
```
🌊 PhishGuard — Inbox Bombing Attack Detected
Target inbox:   victim@company.com
Emails in 5min: 47
Trigger:        velocity (5 subscription emails in 30s)
New domains:    98%
Hold duration:  20 minutes

• Subscription noise → held for SOC review
• New-login/OTP/bank emails → delivered immediately
SOC: bulk-reject held emails, clear hold when done
```

**Dashboard:** Orange warning banner on the Overview tab shows which inbox is under attack with a countdown timer. "Clear Hold" button releases immediately.

**Auto-expiry:** Hold releases automatically after 20 minutes regardless.

---

## 6. What is NOT yet built

**Gmail Workspace real-time ingestion** — receiving emails directly from Google Workspace via Pub/Sub push notifications requires a service account with domain-wide delegation approved by a Workspace admin. The code infrastructure exists (`pubsub_watcher.py`). What is missing is the credentials and an `INBOX_INGESTION_ENABLED` feature flag. Currently PhishGuard receives emails through its own SMTP gateway on port 8025.

For a real deployment, the Workspace admin would add a Gmail routing rule that copies all incoming emails to PhishGuard's port 8025 — no code change needed, just admin configuration.

---

## 7. How to demo it live

```bash
# Terminal 1 — watch the logs
docker compose logs -f app | grep -E "bombing|high_signal|surfaced|held"

# Terminal 2 — run the demo
python3 scripts/demo_bombing.py
```

**Important:** The demo sends all emails from the same laptop IP. The SMTP per-IP rate limiter (10/min) fires before the bombing detector (20 emails) unless you raise it first:

```bash
# Raise rate limits for demo only (resets on container restart)
docker exec --user root phishguard-app \
  sh -c 'echo SMTP_RATE_PER_IP=200 >> /proc/1/environ' 2>/dev/null || true

# Simpler — just use the env var when restarting
SMTP_RATE_PER_IP=200 SMTP_RATE_GLOBAL=200 docker compose up -d app
```

Expected sequence in logs:
```
email 1–4:   smtp_received (no detection)
email 5:     inbox_bombing_velocity_detected (trigger=velocity)
email 6–15:  smtp_bombing_subscription_held
email 16:    smtp_bombing_high_signal_delivered (OTP surfaces)
email 17:    smtp_bombing_unmatched_surfaced (normal email delivers)
email 18–20: smtp_bombing_subscription_held
```

---

## 8. In one paragraph for management

> *"Email bombing tools are freely available online. An attacker enters a victim's email address and within minutes floods their inbox with hundreds of legitimate emails from Amazon, GitHub, and thousands of other real services — every email passes all security checks because it genuinely came from those services. The attack is designed to bury account-change alerts and new-login notifications so the victim does not notice while the attacker acts on a stolen password. PhishGuard detects this in two ways: a fast check fires after just 5 subscription emails in 30 seconds (well before email 20), and a deeper scoring system works even for non-English attacks because its strongest signals — volume spike and sender diversity — are language-independent. When an attack is detected, PhishGuard does not hold all emails, which would help the attacker. It classifies every email in the flood: account-change alerts, login notifications and OTPs are delivered immediately; subscription noise is held for SOC review; anything else defaults to delivery. The SOC sees the attack in real time via Slack and the dashboard, bulk-rejects the noise, and clears the hold.*"

---

## 9. Thresholds — all configurable

No rebuild required. Set env vars before starting the container:

| Env var | Default | What it controls |
|---|---|---|
| `BOMBING_VOLUME_THRESHOLD` | 20 | Emails in window before scoring begins |
| `BOMBING_VELOCITY_THRESHOLD` | 5 | Subscription emails in 30s → velocity trigger |
| `BOMBING_VELOCITY_WINDOW_SECS` | 30 | Velocity detection window |
| `BOMBING_DIVERSITY_RATIO` | 0.70 | Fraction of new domains for +40 |
| `BOMBING_DETECT_SCORE` | 60 | Score threshold for detection |
| `BOMBING_HOLD_MINUTES` | 20 | Hold duration after detection |
| `BOMBING_COLD_START_MIN_HISTORY` | 10 | Domains seen before diversity is trusted |
| `SMTP_RATE_PER_IP` | 10 | Per-IP limit (raise for demo) |
| `SMTP_RATE_PER_RCPT` | 30 | Per-recipient limit |
