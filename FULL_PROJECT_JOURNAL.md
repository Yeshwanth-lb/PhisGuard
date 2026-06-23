# PhishGuard — Complete Project Journal
**Everything built, every decision made, every bug fixed across all sessions.**

---

## What PhishGuard Is

PhishGuard is a production-grade email security gateway built from scratch. It sits in front of a mail server, intercepts every incoming email, runs it through 8 detection layers, and makes a routing decision: deliver to inbox, hold for human review, or quarantine.

It was built to solve the gaps in traditional spam filters:
- Traditional filters block based on keywords and rules — they miss Business Email Compromise (BEC) because BEC emails have no malicious links or attachments, just convincing language
- They miss spear-phishing because it's crafted for one person
- They miss subscription bombing because every individual email is legitimate
- They can't explain why they made a decision — a SOC analyst gets "blocked" with no context

PhishGuard addresses all of these by using Claude AI as the primary detection engine (understands intent, not just patterns), layering 8 independent methods, and giving the SOC team a full forensic breakdown for every email.

---

## Session 1 — Building the Core (2026-06-21)

### What was built

The entire 7-layer detection pipeline, Docker infrastructure, and SOC dashboard were built from scratch. The foundation everything else builds on.

**The 7 layers:**

**Layer 1 — OSINT Pre-Filter**
Queries 9 threat databases simultaneously using `asyncio.gather()`:
- VirusTotal — sender IP + each URL vs 70+ antivirus engines
- AbuseIPDB — sender IP abuse confidence score
- URLhaus — malware distribution URLs
- Google Safe Browsing — URL threat database
- PhishTank — verified phishing pages
- MISP — community threat intelligence IoCs
- Spamhaus — IP/domain blocklist
- WHOIS domain age — domains < 7 days old are critical risk
- Internal denylist — auto-populated SQLite blocklist

Any hard hit = immediate quarantine. Results cached in Redis (avoids API rate limits on repeat senders).

**Trusted sender fast-exit:** A hardcoded set of ~70 domains (LinkedIn, Google, Microsoft, Amazon, GitHub, Indian banks, etc.) bypass ALL OSINT if SPF+DKIM pass. If they fail → spoofing detected → suspicious. Why: LinkedIn URLs appear in VirusTotal because attackers abuse them, causing false positives on job notifications.

**Layer 2 — AI Consensus**
Three engines run concurrently via `asyncio.gather()`:

*NLP Intent Analyst:* Claude (primary) → OpenAI → Gemini → heuristic fallback. Reads the email like a human analyst. Detects BEC fraud, credential harvesting, urgency manipulation, executive impersonation. Heuristic fallback works with zero API keys (keyword scoring). Claude uses `cache_control: {"type":"ephemeral"}` on the system prompt for 90% cost reduction on repeated calls.

*Behavioral Anomaly Detector:* 3-tier cold start based on emails seen from that sender:
- Tier 0 (new sender): Context Scorer + Global Isolation Forest
- Tier 1 (1-5 emails): 50/50 blend
- Tier 2 (6-19 emails): ISO Forest + simplified Gaussian
- Tier 3 (20+ emails): full per-sender GMM

The Global Isolation Forest was pre-trained on 186 real email feature vectors. Per-sender baselines are stored as JSON files.

*Structural Forensics:* Inline Levenshtein (no external dependency) for typosquatting detection, Unicode homoglyph map for domains using Cyrillic/Greek chars, WHOIS domain age (24h cache), Reply-To mismatch detection, DMARC alignment checks, macro-capable attachment detection (.docm, .xlsm, .js, etc.), double extension detection, tracking pixel detection.

Three-tier verdict logic:
- Single engine ≥ 0.90 → Tier 1: phishing immediately
- Composite ≥ 0.62 → Tier 2: phishing (later raised to 0.70)
- Composite ≥ 0.42 → Tier 3: suspicious
- Below all → clean

**Layer 3 — Sandbox Detonation**
Only fires when L2=suspicious AND URLs present AND confidence ≥ 0.45. Spawns an isolated Docker container running headless Chromium via puppeteer. Visits each URL, captures a screenshot, checks for credential forms, JS redirects, suspicious patterns.

Uses Python Docker SDK (`docker.DockerClient`, `containers.run()`) — NOT the CLI. The CLI is not present in the app container. Docker socket mounted at `/var/run/docker.sock`.

**Layer 4 — SOAR**
Seven integrations fired concurrently via `asyncio.gather()`:
- Elasticsearch — verdict indexed for Kibana dashboards
- Slack — real-time webhook alert
- MISP — IoC export (sender domain, IPs, malicious URLs) as MISP event, TLP:AMBER, no email body content
- OpenCTI — STIX2 threat intelligence (auto-synced from MISP via connector)
- Jira — incident ticket (optional)
- Email alert — Gmail SMTP notification to SOC
- Internal denylist — auto-block repeat offenders

MISP is special: it serves two roles. **Incoming:** L1 queries MISP to check if sender IP is a known IoC. **Outgoing:** L4 exports newly detected phishing as MISP events. Every phishing email detected builds the local threat intelligence database.

Evidence store: every phishing/suspicious email saved to MinIO as raw `.eml` + `report.json` at `YYYY/MM/DD/<uuid>/email.eml`. Falls back to `data/evidence/` if MinIO unreachable.

**Layer 5 — ML Classifier**
ExtraTreesClassifier (300 trees, class_weight='balanced') wrapped in CalibratedClassifierCV (isotonic, 3-fold cross-validation). 24 features extracted from each email including L2 AI scores as features.

Blending: `final = 0.60 × L2_composite + 0.40 × ML_score`

**Floor protection:** ML cannot downgrade L2's verdict:
- L2=suspicious → final score floored at 0.43
- L2=phishing → final score floored at 0.65

Why: model trained on 2006 SpamAssassin data, doesn't know BEC patterns. Claude's NLP decision must not be overridden by an ML model that has never seen those attack patterns.

**Layer 6 — Security**
JWT HS256 auth, RBAC (admin/analyst/readonly), rate limiter (120 req/min per IP), audit middleware logging every API call to `data/audit.jsonl`, input sanitiser.

**Layer 7 — Email Ingestion**
Three paths:
1. SMTP gateway (port 8025) — main path, `aiosmtpd` receives emails, runs pipeline, routes
2. Gmail OAuth historical scanner — scans existing inbox with SQLite checkpoint
3. REST API `/analyze` — manual paste in dashboard

SMTP routing uses L2 verdict (not blended final) to prevent ML floor from pushing L2-suspicious to blended-phishing and bypassing SOC review.

Gmail API delivery: `users.messages.import_()` followed by explicit `addLabelIds: ["INBOX", label_id]`. Without the INBOX label, emails go to All Mail but don't appear in the inbox.

**Docker infrastructure:** 13 services via docker-compose — the app, Elasticsearch, Kibana, Redis, MLflow, MinIO, MISP, MySQL (MISP), OpenCTI, connector-misp, RabbitMQ (OpenCTI broker), Prometheus, Grafana.

**SOC Console:** Single Page Application at port 8000, dark theme, 9 navigation tabs. Built in vanilla JS with no framework.

---

## Session 2 — Fixes, Features, Privacy (2026-06-22 morning)

### Fixes

**Behavioral baselines not persisting across Docker restarts**
`ml/baselines/` was not mounted as a named Docker volume. Every container restart wiped per-sender behavioral models, meaning the behavioral engine always ran in cold-start mode. Fixed by adding `phishguard_ml_baselines` named volume in docker-compose.yml.

**Docker socket permissions reset on every restart**
After every `docker compose restart app`, the Docker socket inside the container lost write permission, silently breaking the Layer 3 sandbox. Fixed by setting `user: "0"` (root) on the app service in docker-compose. App now always runs as root so socket is always accessible.

**L2 threshold causing too many escalations**
`HIGH_CONF_THRESHOLD = 0.62` was pushing borderline suspicious emails (scoring 0.62–0.68) straight to phishing/quarantine instead of Pending Review for SOC review. Domain-age signals alone were crossing 0.62. Raised to 0.70.

**Sandbox tests using wrong mock**
Three unit tests mocked `asyncio.create_subprocess_exec` (the old CLI approach) but the code had been switched to the Python Docker SDK. Tests passed when SDK was unavailable but the real sandbox ran during testing. Fixed by rewriting tests to mock `docker.DockerClient.containers.run()` instead. Also restored the `_make_mock_proc` helper that the `test_sandbox_no_docker_image_uses_node` test still needed for the CLI fallback path.

### New features

**Layer 0 — Trivial-clean pre-filter**
New file `app/layer0/pre_filter.py`. Before L1 OSINT even runs, checks 5 conditions — all must pass:
- SPF = "pass"
- DKIM = "pass"
- 0 extracted URLs
- 0 attachments
- Body ≤ 600 characters
- No urgency keywords

If all pass → returns `confidence: 0.02`, `fast_path: "layer0_trivial_clean"`. A short conversational email like "Hi, can you join the 3pm call?" takes this path and skips Claude entirely. Saves API cost and reduces latency for obviously-clean emails. Any single failure → falls through to L1+L2 as normal.

**Trusted domains dynamic at runtime**
Previously `TRUSTED_SENDER_DOMAINS` was a hardcoded Python set requiring code changes and Docker rebuilds to update. Now user-added domains are stored in a SQLite `trusted_domains` table. L1 loads them at runtime with a 60-second cache: `_get_all_trusted()` returns `TRUSTED_SENDER_DOMAINS | set(dynamic_domains)`. Added full CRUD API (`GET/POST/DELETE /api/trusted-domains`) and a management UI in the Settings tab.

**SOC forensic breakdown panel**
The most important UX improvement. Each email in the Pending Review tab now has a "📊 View Analysis" button. Clicking it expands an inline panel showing:
- SPF/DKIM/DMARC authentication badges (green/red/gray)
- L1 OSINT: checks run count, hard hits, weak signals
- L2 score bars for NLP (50% weight), Structural (30%), Behavioral (20%) with threshold markers at 0.42/0.70/0.90
- Threshold Decision Matrix: for each tier (0.90, 0.70, 0.42), shows "▲ EXCEEDED" or "▽ not reached" with actual score vs threshold side by side
- NLP intent label, tactics pills, Claude's reasoning excerpt
- Structural red flags with critical/high/medium severity badges
- Behavioral tier (Cold start / Learning / Developing / Established) and emails seen from this sender
- ML score, blended final score, floor protection note

The panel survives the 5-second polling re-render that refreshes the list. Before fixing this, clicking "View Analysis" showed the panel for 2-3 seconds then it disappeared. Fix: save HTML of open panels before re-render, restore after.

**Visual scan reports in Reports tab**
The Reports tab scan detail view was a raw JSON dump. Replaced with a structured visual report (`renderScanReport()`) showing: colour-coded verdict banner, metadata + auth badges, L1 stat boxes, L2 score bars with threshold matrix, NLP card, structural red flag cards with severity, behavioral stats, sandbox screenshot inline, ML stat boxes, SOAR integration chips (green/red per integration).

**PDF export**
"📄 Export PDF" button in the scan report detail. Opens a new window with a clean light-themed version of the report (white background, proper typography) and auto-triggers the browser print dialog. User selects "Save as PDF". The export builds fresh HTML from the scan data rather than trying to convert the dark-theme UI (which would require overriding 100+ inline styles).

**Reports search/filter**
Filter bar above the reports table: text search by sender, dropdown filter by verdict (all/phishing/suspicious/clean). Client-side filtering on the already-loaded 200 scans.

**False positive feedback**
"Mark Wrong" button per row in Reports. Shows a prompt to select the corrected verdict. Saves to SQLite `feedback` table: `{scan_id, original_verdict, corrected_verdict, notes, submitted_at, submitted_by}`. Wired into ML retraining: `_load_feedback_records()` reads corrections, uses corrected label, excludes the original scan from DB load (so wrong label doesn't compete with human correction). `n_feedback_corrections` reported in MLflow metrics.

**Browser push notifications**
Polling loop (every 5 seconds) now also calls `/api/stats` and `/api/campaigns`. When phishing count increases → desktop notification: "🚨 PhishGuard Alert: N new phishing blocked". When pending count increases → "⚠️ PhishGuard: N new email(s) held for review". Requests permission 3 seconds after page load.

**Privacy hardening**
Critical security issue identified: the Reports scan detail was returning raw `body_text` and `body_html` from the email, allowing SOC analysts to read the full email content. Fixed at two levels:
1. Server-side: `GET /api/scan/{id}` now strips `body_text`, `body_html`, `body_plain`, `body_preview` before returning
2. `body_preview` removed from the `list_scans` SELECT query (was fetched but not shown)
3. "Read Email" button removed from Pending Review tab
4. `GET /api/pending/{id}/body` endpoint deleted entirely

SOC analysts see all scores, metadata, and AI analysis — they don't see the raw email body.

**Campaign detection tab**
New `app/layer4_soar/campaign_detector.py`. Clusters phishing/suspicious emails into attack campaigns using two dimensions:
1. Normalised sender domain: strips TLD and year/number suffixes (`payment-hub-2026.com` → `payment-hub`) then groups domains with the same base. `payment-hub-2026.com` and `payment-hub-2027.com` are the same campaign.
2. NLP intent: groups emails with the same attack type (bec_fraud, credential_harvesting, etc.)

Any cluster with ≥ 3 emails in the detection window = campaign. Severity: critical (10+ or BEC/exec-impersonation), high (5-9), medium (3-4). Active flag: last seen within 24 hours.

New Campaigns tab in dashboard. Each campaign shows as a severity-coloured card with stat boxes, domain list, "View N Scans in Reports →" button. Campaign badge in nav updates every 5 seconds via polling.

**Important bug in Campaigns tab:** The "View Scans" button originally used `${JSON.stringify(c.scan_ids)}` inline in the `onclick` attribute. JSON.stringify produces double-quoted arrays which break the HTML attribute (the first `"` closes the attribute). Fixed by using `data-scan-ids='...'` attribute (single-quoted) and reading via `this.dataset.scanIds`. Also the navigation had a race condition: calling `showSection('reports')` triggered `loadReports()` async which overwrote `_allReportItems` after the campaign filter was set. Fixed by fetching scan data first, then manually switching tabs without `showSection()`.

**Weekly Slack digest**
New `app/layer4_soar/digest.py`. Builds a Slack Block Kit message with scan volume breakdown, top attacker addresses, top NLP attack types, active campaigns. Posts via webhook. Manual trigger: `POST /api/digest/send`. Auto-scheduler: daemon thread fires every Monday at 09:00 local time. "Send Digest to Slack Now" button in SOAR tab.

**Procedural email generator**
The demo script previously used a fixed set of 9 emails, causing the ML model to see identical feature vectors on every test run. Replaced with a procedural generator that randomises names, companies, domains, amounts, urgency levels, phrasing on every run:
- Clean (5 tactics): meeting invite, deployment notice, infra alert, HR event, maintenance notice
- Suspicious (7 tactics): account verify, backup notification, billing, subscription renewal, IT password expiry, survey, reward points — all with randomised service names and year-suffixed domains
- Phishing (6 tactics): brand typosquat (8 brands × multiple typo variants), BEC wire fraud (randomised bank/exec/amount), credential harvest, IRS refund, IT helpdesk, payroll bank update
- `--seed N` for reproducible runs, `--count N` for emails per category

**Real email testing utility**
`scripts/send_eml.py` — download any email from Gmail (three-dot menu → Show original → Download Original) and pipe it through port 8025 for analysis. Auto-detects From address from headers if not specified.

**Dead code removal**
- `app/layer1/verdicts.py.bak` — stale editor backup
- `app/layer1_osint/__init__.py` — empty stub superseded by `app/layer1/`
- `app/google_workspace/__init__.py` — empty placeholder never implemented
- `app/smtp_server/__init__.py` — empty stub

---

## Session 3 — More Dashboard Features, ML Feedback (2026-06-22 afternoon)

### Tests written

**`tests/test_layer0.py` (12 tests)**
Covers: happy path returns correct verdict, all 5 failure criteria (SPF fail/unknown, DKIM fail/unknown, URLs present, attachments present, long body), body exactly at limit passes, urgency in body, urgency in subject, non-urgent body passes.

**`tests/test_campaigns.py` (13 tests)**
Covers: empty DB, below threshold, domain pattern cluster, year-variant domains cluster, intent cluster, clean emails excluded, active/inactive flags, sorted by count, email count correct, BEC severity critical, window_days boundary.

**`tests/test_smtp_rate_limiter.py` (17 tests)**
Covers: per-IP limit, per-domain limit, per-recipient limit, global limit, burst alert fires for IP+domain, alert suppressed on second burst, domain extraction, tarpit on blocked, zero tarpit on allowed, stats structure.

### Privacy fix
`body_preview` was being selected in `list_scans` SQL and returned via `/api/scans`. Not displayed in the UI table but present in the API response. Removed from the SELECT statement.

### Feedback loop into ML
`_assemble_corpus()` in `training_pipeline.py` now:
1. Calls `_load_feedback_records()` first — reads from `feedback` table, joins with original scan's feature vector, uses `corrected_verdict` as label, excludes those scan IDs from the raw DB load
2. When multiple corrections exist for same scan → latest `submitted_at` wins (SQL subquery)
3. `n_feedback_corrections` added to metrics output

### SESSION_HANDOFF and PROJECT_CONTEXT documents
`PROJECT_CONTEXT.md` — comprehensive explanation of what PhishGuard is, why it was built, the 8-layer architecture with ASCII flowchart, key design decisions with reasoning, full tech stack table, live metrics, demo script, what makes it different.

`RECONSTRUCTION_PROMPT.md` — 678-line master prompt for rebuilding the exact system, covers every layer's exact implementation, all design decisions, all gotchas.

---

## Session 4 — Email Bombing Protection (2026-06-22 evening / 2026-06-23)

### The threat

Email bombing (specifically subscription bombing) is a real attack where the attacker signs the victim's email address up to hundreds of legitimate services. Within minutes, the inbox fills with emails from Amazon, GitHub, Mailchimp, LinkedIn — all legitimate, all passing SPF/DKIM/DMARC. The goal is not phishing — it is to bury a critical alert (new device login notification, bank OTP, password reset confirmation) so the attacker can act before the victim notices.

Traditional security cannot detect this because every individual email is completely legitimate.

### SMTP Rate Limiter (`app/security/smtp_rate_limiter.py`)

Protects against direct SMTP flooding of port 8025. Four sliding-window counters checked before every email enters the pipeline:

- **Per-IP:** 10 emails/minute — stops single-source flooding
- **Per-sender-domain:** 20 emails/hour — stops domain-based campaigns
- **Per-recipient:** 30 emails/minute — the critical one: stops distributed attacks where 500 different IPs all target the same inbox
- **Global:** 60 emails/minute — total throughput cap

Returns SMTP 421 (temporary failure) — sending MTA retries later, no legitimate email permanently lost.

**Tarpit:** sleeps `TARPIT_SECS=2` before returning 421. An automated tool sending 500 emails/minute is slowed to ~30/minute because each rejected connection waits 2 seconds.

**Burst detection:** 5+ emails from same IP, domain, or recipient within 10 seconds → Slack alert (suppressed 5 minutes per source to avoid fatigue).

All 4 limits configurable via env vars: `SMTP_RATE_PER_IP`, `SMTP_RATE_PER_DOMAIN`, `SMTP_RATE_PER_RCPT`, `SMTP_RATE_GLOBAL`.

### Inbox Bombing Detector (`app/security/bombing_detector.py`)

Detects subscription bombs. The key insight: the attacker can rotate infinite IPs and domains but **cannot change who the victim is**. The recipient address is the invariant.

**Three signals measured per recipient in a 5-minute window:**

*Signal 1 — Volume (40 points):*
Gate signal — if ≤ 19 emails, score = 0 regardless. At 20+ emails, score += 40.

*Signal 2 — Sender Diversity (graduated, 0/20/40 points):*
Fraction of window emails from domains never seen before for this recipient.
- ≥ 70% new domains → +40 (strong signal, language-independent)
- 50–70% new domains → +20 (moderate signal)
- < 50% new domains → +0

Cold-start protection: if recipient has seen fewer than 10 sender domains historically, diversity is downweighted (new employees safe).

*Signal 3 — Subject Pattern (optional, 0/10/20 points):*
Fraction of emails matching subscription/welcome/verify subjects (12 English regex patterns).
- ≥ 60% match → +20
- 30–60% match → +10
- < 30% → +0

**This is NOT a hard gate** — it is a confidence booster. Volume + diversity alone = 80 points, which exceeds the detection threshold of 60. Non-English bombs are caught by volume + diversity without the pattern signal.

**Detection threshold:** score ≥ 60.

| Scenario | V | D | P | Score | Result |
|---|---|---|---|---|---|
| English subscription bomb | +40 | +40 | +20 | 100 | DETECTED |
| Non-English bomb | +40 | +40 | 0 | 80 | DETECTED |
| Company newsletter blast (one domain) | +40 | 0 | 0 | 40 | Not detected |
| Company all-hands (diverse senders) | +40 | +40 | 0 | 80 | DETECTED |

The company all-hands case is genuinely detected (score 80). However this is safe because of the smart routing response: all-hands email subjects ("CEO announcement", "Q4 update") are neither high-signal nor subscription → they surface/deliver by default. The false positive is harmless.

**Early velocity path (fires at email 5, not email 20):**
If 5+ subscription-pattern emails arrive within 30 seconds → bot speed (no human subscribes to 5 services in 30 seconds) → hold fires immediately.

In a real attack: bombing tool sends 500 emails → velocity fires at email 5 → hold active before email 6 → remaining 494 captured. The OTP or bank alert arrives after the flood is established and the hold is already active.

**Memory safety:**
`seen_domains` is append-only set per recipient, capped at `MAX_SEEN_DOMAINS=500`. Once at 500 it freezes — existing entries are never evicted. A bombing flood of 500 novel domains cannot overwrite genuine history. Arrivals deque is pruned on every `record()` call.

All 11 thresholds configurable via `BOMBING_*` env vars.

### Smart routing during a bombing hold

The critical design decision. Holding ALL mail during an attack actively helps the attacker — the bomb exists to bury critical alerts. Three explicit branches:

```python
if _under_attack:
    if is_high_signal(subject):
        routing_verdict = "clean"   # SURFACE — overrides even phishing verdict
    elif is_subscription_pattern(subject) and routing_verdict == "clean":
        routing_verdict = "suspicious"  # HOLD
    elif routing_verdict == "clean":
        pass  # SURFACE — default, unmatched subjects deliver
```

**High-signal subjects (always surface):**
"Your one-time password is...", "Password reset request", "New device login detected", "Security alert: unusual sign-in", "Your payment of USD N processed", "Unusual activity on your account", "New device login", etc.

**Subscription noise subjects (hold):**
"Confirm your email address", "Welcome to [service]", "Thanks for signing up", "Activate your subscription", "Please verify your account", etc.

**Unmatched/unknown subjects (surface by default):**
"Team meeting Thursday", "Q3 update", "Confirmez votre adresse" (French), any non-English subject, empty subject.

**Why high-signal overrides phishing verdict:**
A genuine bank OTP email from an unknown domain scores "phishing" at L2 — new domain + banking OTP content = classic phishing pattern to Claude. During a bombing attack this is exactly the email to surface. L1 OSINT (VirusTotal, URLhaus) already ran — if those found actual malicious history, the email was quarantined before reaching this code. L2 uncertainty during bombing context yields to delivery. The `pipeline_was` field is logged so analysts can audit every override.

### Dashboard integration

Orange warning banner on the Overview tab when any inbox is under attack:
```
🌊 Inbox Bombing Attack In Progress
victim@company.com — 47 emails in last 5 min · hold expires in 18.3 min
[Clear Hold]
```

Updates every 5 seconds via polling. "Clear Hold" button calls `POST /api/bombing/{rcpt}/clear`. Auto-expires after 20 minutes.

API endpoints: `GET /api/bombing/status`, `POST /api/bombing/{rcpt}/clear`. Stats visible in `GET /health` → `bombing_detector`.

### Demo script (`scripts/demo_bombing.py`)

Sends 20 emails concurrently using threads (one thread per email, 0.3s stagger between thread launches). The concurrent approach is critical — serial sending would wait for each email's pipeline completion (~15 seconds) before the next, so emails would arrive 15 seconds apart and never hit the velocity threshold. Concurrent sending means all 20 connections open within 6 seconds (20 × 0.3s), satisfying the velocity check.

Contents: 15 subscription noise emails from 15 different new domains, 1 OTP email ("Your one-time password is: 847291"), 1 normal business email ("Can we reschedule Thursday's call?"), 3 more subscription noise.

Expected log sequence:
- Email 5–7: `inbox_bombing_detected` (velocity trigger, 100% pattern)
- Multiple: `smtp_bombing_subscription_held`
- OTP email: `smtp_bombing_high_signal_delivered` with `pipeline_was=phishing`
- Normal email: `smtp_bombing_unmatched_surfaced`

**Demo setup:** `.env` must have `SMTP_RATE_PER_IP=200 SMTP_RATE_GLOBAL=200` (already set) so the per-IP rate limiter (10/min default) doesn't fire at email 11 and mask the bombing detection.

### Full explanation document

`EMAIL_BOMBING_EXPLANATION.md` — lead-ready document covering: what email bombing is, the exact attack sequence (bombing hides new-login alerts not OTPs), why traditional security can't stop it, the three detection signals with worked examples, the smart routing decision with explicit before/after table, SOC workflow, the scoring math, a demo guide, and a one-paragraph management summary.

Three inconsistencies fixed after review:
1. Diversity scoring was described as binary in some sections and graduated in others — code is graduated, all sections now consistent
2. Company all-hands scenario contradicted itself across two tables — honest answer: it detects (score 80) but all-hands subjects are unmatched → surface by default → harmless
3. OTP attack narrative was inaccurate — bombing doesn't let attacker intercept OTPs; it hides the new-login/account-change notifications so victim doesn't react while attacker (who already has the password) acts

### Tests

**`tests/test_bombing_detector.py` (21 tests)**
Covers: all 12 English subscription patterns match, non-subscription subjects don't match, below volume threshold no detection, low diversity no detection, low pattern no detection, all-three-signals detection, single-fire behaviour (newly_detected=True once), under_attack persists, different recipients independent, SOC clear, active_attacks list, stats structure, velocity fires before volume threshold, velocity requires pattern.

---

## Running System Snapshot

**13 Docker containers, all healthy**

| Service | Port | Purpose |
|---|---|---|
| PhishGuard app | 8000 (HTTP), 8025 (SMTP) | Main gateway + SOC console |
| Elasticsearch | 9200 | Verdict indexing, 2100+ docs |
| Kibana | 5601 | Phishing trend dashboards |
| MLflow | 5000 | Model registry + retrain history |
| MinIO | 9000/9001 | Evidence .eml storage |
| MISP | 8888 | Threat intelligence, 80+ events |
| OpenCTI | 8080 | Strategic threat intel platform |
| Grafana | 3000 | System health metrics |
| Prometheus | 9090 | Scrapes /metrics every 15s |
| Redis | 6379 | L1 OSINT result cache |
| MySQL | internal | MISP database |
| RabbitMQ | internal | OpenCTI message broker |

**SQLite tables (4):**
- `scans` — every email analysed, full result JSON (body stripped before API returns)
- `pending_review` — suspicious emails held for SOC, raw email blob stored
- `trusted_domains` — user-added trusted senders (runtime, no rebuild)
- `feedback` — SOC false-positive corrections (fed into ML retraining)

**Named Docker volumes (5):**
- `phishguard_app_data` — SQLite DB, ML model, screenshots, audit log
- `phishguard_ml_baselines` — per-sender behavioral baselines (survives restarts)
- `phishguard_es_data` — Elasticsearch indices
- `phishguard_mlflow_data` — experiment history
- `phishguard_minio_data` — evidence files

**Test suite:** 186 passing, 3 skipped (live Slack), 0 failing

---

## All Design Decisions and Why

**Why Claude as primary NLP?** Traditional ML models trained on historical email corpora don't know BEC patterns because BEC didn't exist when SpamAssassin was collecting spam in 2006. Claude reads intent like a human analyst. It understands "please wire $87,500 immediately, do not tell anyone" as fraud even if every word individually is clean.

**Why 8 layers instead of just Claude?** Any single detection method can be evaded. A well-crafted BEC email might fool Claude but trigger the structural engine (sender domain is 3 days old). Layering creates defence-in-depth.

**Why hold suspicious instead of deliver/block?** Phishing is binary — block. But suspicious emails sit in a grey zone. Rather than risk a false positive (blocking real email) or false negative (delivering phishing), suspicious emails go to a human SOC analyst with full forensic context.

**Why L2 verdict for SMTP routing, not blended final?** The ML floor can push L2-suspicious to blended-phishing. Using the blended verdict for routing would send those emails to quarantine, bypassing SOC review entirely. L2 verdict preserves the human-in-the-loop.

**Why does the bombing detector override phishing verdicts for high-signal emails?** A genuine bank OTP from an unknown domain scores phishing at L2 (new domain + banking OTP = classic phishing pattern). During a bombing attack that's exactly the email the attacker wants to bury. L1 hard-evidence checks (VirusTotal, URLhaus) already ran — if those found actual malicious history the email was quarantined before reaching this code. L2 uncertainty during bombing context yields to delivery.

**Why append-only `seen_domains` cap?** If we used FIFO eviction, a bombing flood of 500 new domains would fill the cap and push out the recipient's genuine known-good history, making everything look novel afterward. Append-only with freeze means: genuine history is preserved, and once full, new domains (both bombing and legitimate) just don't get recorded — which means they count as "new" in the diversity check, keeping the detector sensitive.

**Why default to SURFACE for unmatched subjects during bombing?** A held real bank alert is the worst possible failure. The system cannot enumerate every language and every subject format of legitimate critical emails. When uncertain, deliver. Only positively-identified subscription noise is held.

**Why concurrent threads in demo_bombing.py?** Serial `sendmail()` blocks until the SMTP server returns "250 OK", which only happens after the full pipeline completes (~15 seconds). Serial sending means emails arrive 15 seconds apart — never within the velocity window. Concurrent threads mean all SMTP connections open within 6 seconds, satisfying the velocity threshold.

---

## What Is NOT Yet Built

**Gmail Workspace real-time ingestion with `INBOX_INGESTION_ENABLED` flag:**
For PhishGuard to intercept emails on a real Google Workspace domain without routing them manually through port 8025, you need a service account with domain-wide delegation approved by a Workspace admin. The code infrastructure exists (`pubsub_watcher.py`, `historical_scanner.py`). What's missing: the credentials and a feature flag. For a real deployment, the Workspace admin can add a Gmail routing rule (Admin → Gmail → Routing → copy all incoming to port 8025) without any code changes.

**Default passwords:**
All services (Elasticsearch, Kibana, MinIO, OpenCTI, Grafana, MISP) still use `changeme`/`changeme123`. Fine for local demo, must be changed for any real deployment.

**CORS lockdown:**
`allow_origins=['*']` in `app/main.py`. Should be locked to specific origin for production.

**Per-recipient behavioral baselines for shared inboxes:**
Shared role inboxes (support@, sales@) legitimately receive high diverse volume. The bombing detector's defaults would trigger on these. Should have per-inbox configurable thresholds or per-recipient baseline profiling (same concept as the behavioral Layer 2 uses for sender analysis).

---

*This document covers all 5 sessions from 2026-06-21 through 2026-06-23.*
