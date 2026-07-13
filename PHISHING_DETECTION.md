# PhishGuard — Phishing Detection: Complete Technical Reference

> **Audience:** engineers, SOC analysts, or anyone recreating / extending this system.
> Everything in this document reflects the live build as of 2026-07-02.

---

## 1. What is phishing?

Phishing is an email that **impersonates a trusted party to trick the recipient into an action** — clicking a malicious link, entering credentials on a fake page, paying a fraudulent invoice, or opening a weaponised attachment.

The variants PhishGuard is built to catch:

**Credential harvesting** — a fake login page ("Your password expires today, reset here") that captures the username/password the victim types.

**Brand impersonation / lookalike domains** — `paypa1-secure.com` instead of `paypal.com`, `office365-reset.com` instead of `microsoft.com`. Visually convincing, registered days ago.

**Business Email Compromise (BEC)** — no link, no malware, just text: "Per finance, our bank details changed — update the vendor account before today's wire." The hardest class, because there is nothing technical to scan.

**Reward / urgency scams** — "You've won a $1000 gift card, claim in 24 hours."

---

## 2. Why traditional filters miss modern phishing

A spam filter asks *"is this unwanted bulk mail?"*. Phishing is the opposite — it is **targeted, low-volume, and often references real context**.

- The sending domain can be brand-new and pass SPF/DKIM (the attacker owns it).
- There may be **no link and no attachment at all** (BEC) — nothing for a URL/file scanner to flag.
- The content is *designed* to look legitimate — it copies real brand language.
- A single reputation source (e.g. VirusTotal) is blind to a domain registered an hour ago.

The attack is in the **intent and the deception**, not in a virus signature. So a single check is never enough — PhishGuard layers reputation, AI content understanding, live page detonation, and machine learning, with a human in the loop for the gray zone.

---

## 3. The layered pipeline — architecture

Every email enters via the SMTP gateway on port 8025 (`app/layer7_gmail/smtp_receiver.py`), is parsed into a structured dict, and is then passed through layers in order by `app/pipeline.py`:

```
SMTP :8025
   │
   ▼
[Parser] — extracts headers, auth, URLs, attachments, body
   │
   ▼
[L1 — OSINT]  ──── reputation + auth (fast, cheap, runs first)
   │
   ▼
[L2 — AI Engines] — NLP + Behavioral + Structural (core detection)
   │
   ▼
[L3 — Sandbox] ─── live URL detonation (only fires conditionally)
   │
   ▼
[L4 — SOAR] ────── export to MISP / OpenCTI / MinIO / Slack / ES (phishing only)
   │
   ▼
[L5 — ML] ─────── ExtraTrees calibrated classifier (blended 60/40 with L2)
   │
   ▼
[Routing] ─────── clean → inbox · suspicious → pending · phishing → quarantine
```

---

## 4. What the parser extracts

Before any detection runs, the raw email bytes are parsed into a structured dict. Every downstream layer reads from this dict — nothing re-parses the raw email.

**Envelope / routing:**
- `sender_email`, `sender_domain`, `sender_ip`, `recipient`
- `return_path` — where bounces go (mismatch with `From:` is a spoofing signal)

**Authentication:**
- `dkim_result` — pass/fail + signing domain (`d=` tag)
- `spf_result` — pass/fail/softfail
- `dmarc_alignment` — whether DKIM/SPF domain aligns with the `From:` domain
- `dkim_aligned` — boolean

**Message headers:**
- `from_header` — display name + address (can be spoofed — attacker puts "SBI Bank" here)
- `subject`, `date`, `message_id`
- `reply_to` — if different from `From:`, a suspicious signal
- `List-Unsubscribe` — indicates bulk/newsletter sender (used in bombing triage)
- `x-mailer`, `x-originating-ip` — mailer fingerprint

**Body / content:**
- `body_text`, `body_html`
- `urls` — all extracted URLs (checked against URLhaus/PhishTank/VT in L1)
- `url_count`, `attachment_names`, `attachment_count`, `attachment_hashes`

**Derived signals (computed by parser, before any ML):**
- Domain age / registrar
- Display name ≠ `From:` domain mismatch flag
- HTML-to-text ratio

---

## 5. Layer 1 — OSINT reputation & authentication pre-filter

**File:** `app/layer1/verdicts.py`, `app/layer1/osint_v2.py`

The cheap, fast first pass. Runs reputation and auth checks concurrently via `asyncio.gather`.

| Source | What it catches | Threshold |
|---|---|---|
| VirusTotal | Known-bad URLs / domains / IPs | ≥ 3 detections |
| Google Safe Browsing | Google's live phishing/malware URL list | any hit |
| AbuseIPDB | Abusive sender IPs | ≥ 25 confidence |
| URLhaus | Known malware-distribution URLs | any hit |
| PhishTank | Known phishing URLs | any hit |
| MISP | Own + shared threat-intel indicators | High or Medium threat level |
| Spamhaus / WHOIS | Blocklisted infra; domain age < 30 days = suspect | configurable |
| Internal denylist | Previously blocked senders/URLs | instant quarantine |

A confirmed hit quarantines outright. If nothing fires, the email continues to L2.

**Trusted-sender fast-path:** ~40 high-volume brands (Google, LinkedIn, major banks…) skip the OSINT pass — **but only if SPF/DKIM pass**. A trusted domain that *fails* auth is treated as a **spoofing attempt** (suspicious verdict), which is *more* dangerous than an unknown sender, not less.

---

## 6. Layer 2 — AI engines (the core of phishing detection)

**File:** `app/layer2_ai/orchestrator.py`

Three independent engines run concurrently, then combine into a weighted composite:

### Engine 1 — NLP (weight 0.40)
`app/layer2_ai/nlp_engine.py`

Claude (`claude-opus-4-7`) reads subject + body and extracts **intent and tactics** — urgency, credential request, payment redirection, impersonation. Falls back OpenAI → Gemini → keyword heuristic if a provider is unavailable.

**This is what catches BEC** — where there is no link or attachment to scan. The AI reads the *meaning* of the email, not its technical properties.

Model resolution order: Anthropic Claude → OpenAI GPT → Google Gemini → offline keyword heuristic.

### Engine 2 — Behavioral (weight 0.35)
`app/layer2_ai/behavioral_engine.py`

Isolation Forest + per-sender Gaussian model. Learns each sender's normal pattern (time of day, recipient set, body length, URL density) and flags anomalies.

**This catches:** unusual sending time, unusual content type for a known sender, a finance address suddenly sending wire-transfer requests.

### Engine 3 — Structural (weight 0.25)
`app/layer2_ai/structural_engine.py`

Deterministic checks: typosquatting / lookalike domains (Levenshtein distance vs. known-good brand list), domain age, macro-bearing attachments, link/anchor mismatch (display says `paypal.com`, href points elsewhere).

### Three-tier verdict logic

```
any single engine ≥ 0.90                → phishing   (single engine certain)
composite (0.40·nlp + 0.35·beh + 0.25·str) ≥ 0.65 → phishing
composite ≥ ~0.42                        → suspicious (gray zone → human review)
otherwise                                → clean
```

The **~0.42 suspicious threshold** is the most critical calibration parameter. Emails sitting right on this boundary will drift across it run-to-run due to non-zero LLM temperature (known issue — fix: set `temperature=0` in `app/llm/client.py`).

---

## 7. Layer 3 — URL sandbox

**File:** `app/layer3_sandbox/`

Fires **only when all three conditions are met:**
1. L2 verdict = suspicious (not already phishing)
2. Email contains at least one URL
3. L2 confidence ≥ 0.35

It detonates the link in a disposable headless browser (Playwright), screenshots the page, extracts page text and any login form elements. Catches a fake login page that no static check could see.

**Skipped for:** phishing already decided at L2 (no need to confirm); clean mail; emails with no URLs.

**Caveat:** Sophisticated phishing pages detect headless browsers and serve benign content. Fingerprint randomisation is a post-demo hardening task.

Time cost: 15–30 seconds when it fires.

---

## 8. Layer 4 — SOAR (Security Orchestration, Automation and Response)

**File:** `app/layer4_soar/`

Fires concurrently on a **phishing verdict only**. All actions run in parallel via `asyncio.gather`:

| Action | What it does |
|---|---|
| Elasticsearch | Writes full verdict document to `phishguard-verdicts-YYYY.MM.DD` |
| MISP | Creates a MISP event with IOCs (sender domain, URLs, IPs) |
| OpenCTI | Syncs the threat as an Observable + Indicator |
| MinIO | Archives the raw email bytes and verdict JSON as objects |
| Slack | Sends alert to the SOC channel |
| Internal denylist | Auto-blocks the sender domain for future emails |
| Jira | Creates a ticket (wired, currently no token — post-demo task) |

The SOC can also **manually trigger** MISP/OpenCTI export from the dashboard for suspicious verdicts.

---

## 9. Layer 5 — ML classifier

**File:** `app/layer5_ml/`

`ExtraTreesClassifier` wrapped in `CalibratedClassifierCV`. Produces a calibrated phishing probability.

**Blending:** `final = 0.60 × L2_confidence + 0.40 × ML_score`

**ML floor (critical protection):** ML cannot *downgrade* a verdict the other layers already raised.
- Suspicious floor: 0.43 — if L2 said suspicious, ML-blended score cannot go below 0.43
- Phishing floor: 0.65 — if L2 said phishing, ML cannot clear it

ML can confirm or strengthen, but never quietly clear a flagged email.

> **Routing uses the L2 verdict, not the ML-blended score.** This deliberately stops the ML floor from pushing a *suspicious* email into *phishing* and bypassing human review.

---

## 10. The verdict and routing decision

| Verdict | Meaning | Action | Destination |
|---|---|---|---|
| **clean** | No meaningful threat signal | Deliver | Gmail inbox (`PhishGuard-Delivered` label) |
| **suspicious** | Gray zone — signals but not conclusive | **Hold** | Dashboard → Pending Review |
| **phishing** | High-confidence threat | **Quarantine** | Dashboard → Quarantine (never delivered) |

**Core rule:** *suspicious mail is never auto-deleted.* The gray zone routes to a human — the cost of silently blocking a legitimate email is higher than a 30-second analyst review.

---

## 11. SOC workflow

**Quarantine tab:** Confirmed phishing. SOC can inspect (headers, AI tactics explanation, sandbox screenshot) and confirm or release.

**Pending Review tab:** Suspicious / gray-zone mail held for analyst decision.
- **Approve** → delivers to inbox
- **Reject** → stays blocked, logged to audit trail

**Audit log:** Every action (verdict, approve, reject, export) is written to the audit log with timestamp and actor.

---

## 12. Elasticsearch verdict storage

Every email processed produces a verdict document in `phishguard-verdicts-YYYY.MM.DD`. As of 2026-07-02 there are 3,135+ documents across 13 daily indices.

**Each document contains:**
```json
{
  "@timestamp": "...",
  "verdict": "phishing",
  "confidence": 0.499,
  "blocked_at": "layer2",
  "sender": "docusign@secure-esign-doc.com",
  "sender_domain": "secure-esign-doc.com",
  "sender_ip": "...",
  "subject": "You have a document waiting for signature",
  "url_count": 1,
  "attachment_count": 0,
  "l1_hits": [],
  "l1_verdict": "suspicious",
  "l2_engine_scores": { "nlp": 0.9, "behavioral": 0.246, "structural": 0.0 },
  "l2_verdict": "phishing",
  "l2_confidence": 0.499,
  "l3_verdict": null,
  "l3_score": null,
  "ml_score": 0.4,
  "ml_label": "phishing",
  "ml_available": true
}
```

Access via Kibana at `http://localhost:5601`. Create a data view on `phishguard-verdicts-*`.

---

## 13. Demo script — how it works

**File:** `scripts/demo_phishing_15.py`

Two-phase design so the demo never misfires:

**Phase 1 — Calibrate (always runs):**
POSTs each candidate email to `/analyze` (no delivery). Reads the real verdict from the live engine. Buckets candidates by actual verdict (clean/suspicious/phishing). This means the demo always sends emails that *actually* score in the right tier.

**Phase 2 — Send (requires `--send` flag):**
Picks the first 5 from each calibrated bucket and injects via SMTP :8025. Each email goes to a **distinct recipient** (`user1@company.com`, `user2@company.com`, etc.) so it never trips the bombing detector.

```bash
# Dry run (calibrate only, no delivery):
docker exec -w /app phishguard-app python3 demo_phishing_15.py

# Calibrate + send 5 of each:
docker exec -w /app phishguard-app python3 demo_phishing_15.py --send

# Skip calibration, send the pre-verified curated set:
docker exec -w /app phishguard-app python3 demo_phishing_15.py --send --no-calibrate
```

**Where emails land:**
- `clean` → Gmail inbox (label: `PhishGuard-Delivered`)
- `suspicious` → Dashboard → Pending Review (held, never reaches inbox)
- `phishing` → Dashboard → Quarantine

---

## 14. Candidate email pools

### CLEAN pool (7 samples — all reliably score 0.02–0.09)
```
rohan.mehta@infosys.com          — "Re: Q3 partnership review"
priya.sharma@company.com         — "Notes from this morning's standup"
orders@bigbasket.com             — "Your order #BB48213 has been delivered"
hr@company.com                   — "Reminder: submit your timesheet by Friday"
newsletter@morningbrew.com       — "The Morning Brew: markets, tech, and a good read"
arjun.k@company.com              — "Lunch tomorrow?"
status@projecthub.company.com    — "Weekly project status: Phoenix"
```

### SUSPICIOUS pool (8 samples — 5-6 reliably score 0.43–0.61)
```
rewards@survey-prize.co          — "You're eligible for a $50 reward"             (0.43)
info@parcel-customs.net          — "Customs fee required to release your parcel"   (0.43–0.54)
claims@prize-hub.net             — "You've been selected — claim your gift"        (0.57)
alert@account-notice.co          — "Important: your account requires attention"    (0.53–0.61)
notify@parcel-release.net        — "Your delivery is on hold — action needed"      (0.43–0.55)
offers@lucky-winner.co           — "Exclusive: you qualify for a special reward"   (0.43)
billing@renew-service.info       — "Subscription payment failed — update now"      (0.43)
noreply@delivery-notice.net      — "Your package could not be delivered"           (0.43)
```

> **Note on suspicious stability:** These samples sit at 0.43–0.61. Run-to-run variance of ±0.15 is expected because the NLP engine uses non-zero API temperature. The two-phase calibration design means only samples that *actually* scored suspicious in this run are sent. Fix for production: set `temperature=0` in `app/llm/client.py`.

### PHISHING pool (7 samples — all reliably score 0.49–1.00)
```
security@paypa1-secure.com           — "Your account is suspended - verify now"           (1.00)
alert@hdfc-bank-secure.com           — "Unusual login - confirm your identity immediately" (0.78–0.81)
it-helpdesk@office365-reset.com      — "Your password expires TODAY - reset required"      (1.00)
rewards@amaz0n-giftcard.com          — "Congratulations! You've won a $1000 gift card"    (0.74)
docusign@secure-esign-doc.com        — "You have a document waiting for signature"         (0.49–0.51)
appleid@apple-id-locked.com          — "Your Apple ID has been locked"                    (1.00)
accounts@wire-payment-update.com     — "URGENT: update vendor payment details"            (0.49–0.50)
```

---

## 15. Known limitations

**Suspicious tier volatility:** Samples near the 0.42 boundary drift across it run-to-run. The calibration phase handles this for demos. Fix for production: `temperature=0`.

**ML training data:** The classifier was trained on a fixed older corpus. Novel BEC/spear-phishing may score low in ML — which is why L2 (AI) is the primary decider and ML is only a blended supplement with floors.

**Sandbox off by default:** `enable_sandbox=false`. Must be enabled per-environment.

**No real Workspace ingestion:** Mail arrives via SMTP :8025. Real deployment needs a Workspace routing rule (admin config only, no code change).

**VirusTotal rate limits:** Free tier limits repeated URL scans. Use fresh demo samples each run.

---

## 16. All configurable thresholds

Set via env vars or `app/config.py`. No rebuild required.

| Setting | Default | What it controls |
|---|---|---|
| `l2_nlp_weight` | 0.40 | NLP engine weight in composite |
| `l2_behavioral_weight` | 0.35 | Behavioral engine weight |
| `l2_structural_weight` | 0.25 | Structural engine weight |
| `l2_critical_threshold` | 0.90 | Any single engine ≥ this → phishing |
| `l2_composite_threshold` | 0.65 | Composite ≥ this → phishing |
| `l1_domain_age_days` | 30 | Domains younger than this are suspect |
| `l1_virustotal_threshold` | 3 | VT detections to count as a hit |
| `l1_abuseipdb_threshold` | 25 | AbuseIPDB confidence to count as a hit |
| `l1_misp_threat_levels` | High,Medium | MISP threat levels treated as hits |
| `l3_trigger_threshold` | 0.35 | Min L2 confidence to fire the sandbox |
| `enable_sandbox` | false | Master switch for L3 detonation |
| `anthropic_model` | claude-opus-4-7 | NLP model |

---

## 17. For management — one paragraph

> *"Modern phishing is not spam — it is a targeted email that impersonates a trusted brand or colleague to steal a credential or redirect a payment. The dangerous ones pass every authentication check and often contain no link or attachment at all. No single tool catches this, so PhishGuard layers four: it first checks the sender and any links against live threat databases; then three AI engines read the email for malicious intent, anomalies versus the sender's normal behaviour, and lookalike-domain tricks; suspicious links are opened in a disposable sandbox and screenshotted; and a machine-learning model gives a final calibrated score. Confirmed phishing is quarantined and never reaches the inbox; clearly safe mail is delivered; and anything in the gray zone is held for a 30-second analyst review. On our standard demo set it catches phishing and passes clean mail with full reliability; the gray-zone tier is intentionally routed to a human because it is, by design, a judgment call."*
