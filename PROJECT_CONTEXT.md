# PhishGuard — Complete Project Context

**Version:** 1.5  
**Developer:** Yeshwanth (yeshwanthlb0@gmail.com)  
**Stack:** Python · FastAPI · Claude AI · Docker · SQLite · Elasticsearch · Slack · MISP · OpenCTI  

---

## What is PhishGuard?

PhishGuard is an **end-to-end email security gateway** that scans every incoming email through 8 detection layers — from OSINT threat databases to AI analysis to sandbox detonation — and routes each email to one of three outcomes: deliver, hold for SOC review, or quarantine.

It is designed to sit in front of a mail server, intercept emails at the SMTP layer, analyse them using multiple AI engines, and give a Security Operations Centre (SOC) team a full forensic breakdown before any suspicious email reaches a user's inbox.

---

## Why was it built?

Traditional spam filters use rule-based or keyword approaches and miss modern threats like:
- **Business Email Compromise (BEC)** — an attacker impersonating the CEO asking for a wire transfer. No malicious link, no malware, just convincing language.
- **Spear phishing** — targeted attacks crafted for a specific person, bypassing generic spam rules.
- **Brand impersonation** — emails using typosquat domains like `paypa1-verify.com` instead of `paypal.com`.

PhishGuard addresses these by using Claude (Anthropic's AI) as the primary detection engine, understanding intent not just patterns, and layering 8 independent detection methods so no single failure point exists.

---

## Architecture — 8 Detection Layers

Every email passes through these layers in sequence. Each layer can independently block the email. If all pass, the email is delivered.

```
Email arrives at port 8025 (SMTP)
        │
        ▼
┌───────────────────────────────────────────────────────┐
│  LAYER 0 — Trivial-Clean Pre-filter          < 5ms   │
│  SPF pass + DKIM pass + no URLs + short body?         │
│  YES → clean, skip all AI layers (saves API cost)     │
│  NO  → continue                                       │
└───────────────────┬───────────────────────────────────┘
                    ▼
┌───────────────────────────────────────────────────────┐
│  LAYER 1 — OSINT Pre-filter                 < 50ms   │
│  Query 9 threat databases simultaneously:             │
│  VirusTotal · AbuseIPDB · URLhaus · Google Safe       │
│  Browsing · PhishTank · MISP · Spamhaus · WHOIS       │
│  · Internal Denylist                                  │
│  Any hit → immediate quarantine                       │
│  Trusted sender (LinkedIn, Google, etc.)? → fast exit │
└───────────────────┬───────────────────────────────────┘
                    ▼
┌───────────────────────────────────────────────────────┐
│  LAYER 2 — AI Consensus Engine              < 5sec   │
│  3 engines run in parallel:                           │
│                                                       │
│  ① NLP Intent Analyst (Claude primary)               │
│    Reads the email like a human analyst.              │
│    Detects: BEC fraud, credential harvesting,         │
│    urgency manipulation, executive impersonation,     │
│    brand impersonation. Returns intent + score.       │
│                                                       │
│  ② Behavioral Anomaly Detector                       │
│    Compares this email against the sender's history.  │
│    New sender = cold start (Isolation Forest).        │
│    Known sender = per-sender Gaussian model.          │
│    Is this email statistically unusual for them?      │
│                                                       │
│  ③ Structural Forensics                              │
│    Checks: typosquatting (Levenshtein distance),      │
│    Unicode homoglyphs, domain age (< 7 days = red),   │
│    Reply-To mismatch, DMARC alignment, macro          │
│    attachments, double extensions, tracking pixels.   │
│                                                       │
│  Verdict thresholds:                                  │
│    Single engine ≥ 0.90  → phishing  (Tier 1)        │
│    Composite   ≥ 0.70  → phishing  (Tier 2)          │
│    Composite   ≥ 0.42  → suspicious (Tier 3)         │
│    Below all           → clean                       │
└───────────────────┬───────────────────────────────────┘
                    │
        ┌───────────┴───────────┐
        │ L2 = phishing?        │
        YES → quarantine        NO → continue
                    ▼
┌───────────────────────────────────────────────────────┐
│  LAYER 3 — Sandbox Detonation             < 30sec    │
│  Only fires when: L2=suspicious AND URLs present      │
│  AND confidence ≥ 0.45                               │
│  Spawns an isolated Docker container running          │
│  headless Chrome. Visits every URL in the email,      │
│  captures a screenshot, looks for:                    │
│  credential forms · JS redirects · page title         │
│  Screenshot saved → visible in SOC scan report        │
└───────────────────┬───────────────────────────────────┘
                    ▼
┌───────────────────────────────────────────────────────┐
│  LAYER 4 — SOAR (fires async for all detections)     │
│  7 integrations fired simultaneously:                 │
│  · Elasticsearch  → index verdict for Kibana/search  │
│  · Slack          → instant SOC alert message        │
│  · MISP           → export IoCs to threat intel DB   │
│  · OpenCTI        → strategic threat intel platform  │
│  · Jira           → create incident ticket           │
│  · Email alert    → notify SOC team                  │
│  · Internal denylist → auto-block repeat offenders   │
└───────────────────┬───────────────────────────────────┘
                    ▼
┌───────────────────────────────────────────────────────┐
│  LAYER 5 — ML Classifier (augments L2)               │
│  ExtraTreesClassifier (300 trees) wrapped in          │
│  CalibratedClassifierCV (isotonic, 3-fold CV)         │
│  24 features: url_count, nlp_score, structural_score, │
│  behavioral_score, urgent_word_count, brand_spoof,    │
│  domain_age, reply_to_mismatch, etc.                  │
│  Blends: final = 0.60 × L2 + 0.40 × ML               │
│  Floor protection: ML cannot lower L2's verdict.     │
│  Retrained on real scan data + SOC feedback.          │
└───────────────────┬───────────────────────────────────┘
                    ▼
┌───────────────────────────────────────────────────────┐
│  LAYER 6 — Security                                  │
│  JWT (HS256) · RBAC (admin/analyst/readonly)          │
│  Rate limiter (120 req/min) · Audit log               │
│  Input sanitiser · Privacy: email body never exposed  │
└───────────────────┬───────────────────────────────────┘
                    ▼
┌───────────────────────────────────────────────────────┐
│  LAYER 7 — Email Routing Decision                    │
│  CLEAN      → Gmail API inject → real inbox          │
│               label: PhishGuard-Delivered             │
│  SUSPICIOUS → Hold in SOC Pending Review queue       │
│               SOC approves → inbox                   │
│               SOC rejects  → quarantine              │
│  PHISHING   → RCPT rewritten to quarantine address   │
│               Never reaches recipient                 │
└───────────────────────────────────────────────────────┘
```

---

## Key Design Decisions

### Why Claude as the primary AI?
Traditional ML models (including PhishGuard's own Layer 5) are trained on historical data — mostly 2006-era SpamAssassin emails. They don't understand modern BEC attacks because those didn't exist in 2006. Claude reads the email like a human analyst and understands intent: "this is trying to trick someone into sending money" vs "this is a legitimate business email."

### Why 8 layers instead of just Claude?
Any single detection method can be fooled or fail. A well-crafted BEC email might fool Claude but trigger the structural engine (because the sender domain is 2 days old). Layering creates defence-in-depth — an attacker would need to simultaneously defeat OSINT databases, the AI NLP engine, behavioral analysis, structural forensics, AND the ML classifier.

### Why hold suspicious emails instead of delivering/blocking?
Phishing is binary (block). But suspicious emails sit in a grey zone — maybe it's a real vendor using a new domain, or maybe it's an attacker. Rather than risking a false positive (blocking legitimate email) or false negative (delivering phishing), suspicious emails go to a SOC queue where a human makes the final call with full forensic context.

### Why a feedback loop?
Every time a SOC analyst clicks "Mark Wrong" on a misclassified email, that correction is saved. When the ML model retrains, it uses those corrections as ground truth, overriding the original prediction. Over time, the model learns from the organization's specific email patterns.

---

## The SOC Dashboard

A full-featured Single Page Application at `localhost:8000` with 9 tabs:

### Overview
Live stats: total scanned, phishing blocked, suspicious held, clean delivered. Recent activity feed.

### Scan
Paste any raw email text → instant analysis → verdict with full layer breakdown.

### Pending Review
The SOC queue. Suspicious emails held here. For each email:
- **📊 View Analysis** → full forensic breakdown showing every layer's score, threshold decision matrix (exactly why it scored where it did), Claude's reasoning, structural red flags with severity
- **✅ Approve** → email is delivered to the recipient's Gmail inbox
- **🔒 Reject** → email is quarantined
- Panel stays open during the 5-second auto-refresh (state preserved)

### Reports
Full audit trail of every scanned email. Click any row for a visual scan report showing all 8 layers. **📄 Export PDF** generates a clean light-themed professional report suitable for incident reports or management briefings.

### Quarantine
All blocked phishing emails. View, release, or delete.

### Campaigns
**Automatically detects coordinated attacks.** Groups emails by normalised sender domain (strips year/number suffixes so `payment-hub-2026.com` and `payment-hub-2027.com` cluster together) and NLP intent. Any cluster with 3+ emails = campaign. Shows severity (critical/high/medium), active status, and deep-links to the individual emails in Reports.

### ML Ops
Current model metrics (F1, ROC-AUC, confusion matrix, feature importances). Retrain button. Shows how many SOC feedback corrections fed into the last training run.

### SOAR
Integration status for all 7 threat response tools. **Weekly Threat Digest** — posts a Slack summary (scan counts, top attackers, top attack types, active campaigns) either manually or automatically every Monday at 09:00.

### Settings
Trusted Sender Domains management — add/remove domains without touching code or rebuilding the container.

---

## MISP — Dual Role

MISP (Malware Information Sharing Platform) serves two roles:

**Incoming (Layer 1):** Every email's sender IP is queried against MISP's IoC database. If it appears in any existing threat event → immediate block.

**Outgoing (Layer 4):** Every detected phishing email creates a new MISP event with the technical indicators (sender domain, malicious URLs, sender IP) tagged TLP:AMBER. These events sync to OpenCTI automatically via the connector container. Over time, PhishGuard builds a local threat intelligence database of every attack it has seen.

---

## Campaign Detection

```
Input: Last 7 days of phishing/suspicious scans

Step 1: Normalise sender domains
  payment-hub-2026.com  →  payment-hub
  payment-hub-2027.com  →  payment-hub    ← same cluster!
  account-portal-01.net →  account-portal

Step 2: Group by normalised domain
  "payment-hub" → [email1, email2, email3, email4]  ← 4 emails = CAMPAIGN

Step 3: Group by NLP intent
  "bec_fraud" → [emailA, emailB, emailC]  ← 3 emails = CAMPAIGN
  (only if not already captured by domain cluster)

Step 4: Apply severity
  10+ emails or BEC/exec_impersonation → CRITICAL
  5–9 emails                           → HIGH
  3–4 emails                           → MEDIUM

Output: Campaign list with pattern, email count, first/last seen, active flag
```

---

## Tech Stack

| Component | Technology | Purpose |
|---|---|---|
| API server | FastAPI (Python) | REST API + SMTP gateway |
| AI NLP | Anthropic Claude | Primary phishing intent detection |
| AI NLP fallback | OpenAI GPT / Gemini / heuristic | If Claude unavailable |
| ML model | scikit-learn ExtraTrees + CalibratedCV | Statistical pattern detection |
| Anomaly detection | scikit-learn Isolation Forest | Behavioral baseline (global) |
| Per-sender model | Gaussian / GMM (numpy) | Behavioral baseline (per sender) |
| Database | SQLite | Scans, pending review, trusted domains, feedback |
| Search/Analytics | Elasticsearch 8.13 | Verdict indexing for Kibana dashboards |
| Visualisation | Kibana | Threat dashboards |
| Metrics | Prometheus + Grafana | System health, error rates, latency |
| Object storage | MinIO (S3-compatible) | Raw .eml evidence files |
| Threat intel | MISP | IoC database (incoming + outgoing) |
| Threat platform | OpenCTI | Strategic threat intelligence |
| Ticketing | Jira | Incident ticket creation |
| Alerting | Slack | Real-time phishing alerts + weekly digest |
| Experiment tracking | MLflow | ML model versioning and metrics |
| Cache | Redis | L1 OSINT result caching (avoids API rate limits) |
| Message broker | RabbitMQ | OpenCTI internal |
| Sandbox | Docker + Chromium | URL detonation |
| Email transport | aiosmtpd | SMTP gateway (port 8025) |
| Gmail delivery | Gmail API (OAuth) | Inject clean emails into real inbox |
| Containerisation | Docker Compose | 13 services orchestrated |

---

## Live Numbers (as of 2026-06-22)

| Metric | Value |
|---|---|
| Total emails scanned | 1,361 |
| Phishing blocked | 167 |
| Suspicious held for SOC review | 232 |
| Clean delivered | 962 |
| ML model F1 score | 0.894 |
| ML model ROC-AUC | 0.974 |
| Test suite | 147 passing, 0 failing |
| Running services | 13 / 13 healthy |
| Elasticsearch docs indexed | 2,100+ |
| MISP threat events exported | 80+ |
| Campaigns detected (last 30 days) | 33 total, 7 active |
| Behavioral baseline files | 15+ (persisted) |

---

## How to Run the Demo

### Prerequisites
- Docker Desktop running
- All 13 containers healthy: `docker compose ps`

### Send test emails (unique every run)
```bash
python3 scripts/test_smtp_gateway.py
```

Generates 3 clean + 3 suspicious + 3 phishing emails with randomly generated names, domains, amounts, and phrasing. Every run is different.

### What to show
1. **Gmail inbox** — search `label:PhishGuard-Delivered` → 3 clean emails arrived
2. **Dashboard → Pending Review** (press F5 first) → 3 suspicious held
   - Click **📊 View Analysis** → see exactly why each email was flagged
   - Click **✅ Approve** → email arrives in Gmail with SOC-approved label
3. **Dashboard → Quarantine** → 3 phishing blocked
4. **Dashboard → Reports** → click any scan → visual report → **📄 Export PDF**
5. **Dashboard → Campaigns** → coordinated attacks grouped automatically
6. **Kibana** (`localhost:5601`) → phishing trend charts
7. **Grafana** (`localhost:3000`) → system metrics
8. **MISP** (`localhost:8888`) → 80+ exported threat events
9. **MLflow** (`localhost:5000`) → model training history

### Test with a real email
```bash
# Download from Gmail: ⋮ menu → Show original → Download Original
python3 scripts/send_eml.py ~/Downloads/email.eml
```

---

## What Makes This Different

1. **AI that understands intent, not just patterns** — Claude reads BEC fraud the same way a human analyst would, catching attacks that have no malicious URLs or attachments.

2. **8-layer defence** — No single engine can be tricked. An attacker must simultaneously fool OSINT databases, Claude NLP, behavioral analysis, structural forensics, AND the ML classifier.

3. **SOC-first design** — The system doesn't just block/allow. Suspicious emails go to a human analyst with full forensic context — every score, every threshold, Claude's reasoning, structural red flags — so the human makes an informed decision, not just "this got a high score."

4. **Continuous learning** — Every SOC decision (approve/reject/mark-wrong) feeds back into the ML model. The system gets smarter from the organization's own email patterns.

5. **Full threat intelligence integration** — Every detected phishing attack is automatically exported as IoCs to MISP and OpenCTI, building a local threat intelligence database that also benefits the broader security community.

6. **Campaign detection** — The system thinks across emails, not just individually, detecting when multiple emails are part of a coordinated attack before a human analyst would notice the pattern.
