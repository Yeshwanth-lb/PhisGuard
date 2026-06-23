# PhishGuard — Session Handoff Document
**Last updated:** 2026-06-23 (session 6)  
**Project root:** `/Users/intern4/Desktop/phishguard`  
**Developer:** Yeshwanth (yeshwanthlb0@gmail.com)  
**Purpose:** End-to-end email security gateway with 7-layer AI detection

---

## 1. Current System State

### Tests
- **186 passing, 3 skipped, 0 failing**
- Run with: `python3 -m pytest tests/ -q --ignore=tests/locustfile.py --ignore=tests/test_layer4_smtp_live.py --ignore=tests/test_layer2_claude_live.py`
- 3 skipped: live Slack tests (no webhook in env)
- Test files: `test_layer0.py` (12), `test_campaigns.py` (13), `test_smtp_rate_limiter.py` (17), `test_bombing_detector.py` (21), `test_layer1/2/3/4/5/6/7.py`

### Git Status
- Branch: `master` — all changes committed, working tree clean
- Latest commits:
  - `531f3e1` fix: Grafana dashboard metric names and datasource UID
  - `045cc6f` fix: MISP nginx redirect includes port 8443, remove HSTS
  - `c3b7f14` fix: MISP serves HTTP directly (reverted — secure cookies issue)
  - `bfd9298` fix: expose MISP HTTPS on port 8443, fix connector-misp URL
  - `15edfed` docs: add FULL_PROJECT_JOURNAL.md

### Database State (as of 2026-06-23)
- **Total scans stored:** 1,445
- **Phishing:** 182 | **Suspicious:** 240 | **Clean:** 1,023
- SQLite at `data/phishguard.db` (Docker volume: `phishguard_app_data`)
- 4 tables: `scans`, `pending_review`, `trusted_domains`, `feedback`
- **IMPORTANT:** Local `data/phishguard.db` and Docker volume DB can drift if you run Python scripts directly. Fix:
  ```bash
  docker cp data/phishguard.db phishguard-app:/app/data/phishguard.db
  docker exec --user root phishguard-app chmod -R 777 /app/data/
  ```

### ML Model
- Algorithm: `ExtraTreesClassifier` (300 trees, class_weight='balanced')
- Wrapped in: `CalibratedClassifierCV` (isotonic, 3-fold)
- F1: **0.894** | ROC-AUC: **0.974**
- Saved at: `data/model.pkl` (1.3 MB)
- Training data: `data/training/spamassassin_corpus.jsonl` (5,772 emails) + `data/training/gmail_clean_corpus.jsonl` (307 real clean emails)
- **DO NOT** use `data/training/huggingface_phishing_corpus.jsonl` — degrades F1 from 0.89→0.62 (feature mismatch: no pipeline scores)
- Feedback corrections from the `feedback` table are folded in at retrain time — human-corrected labels override original scan verdicts

### Global Isolation Forest
- Seeded at: `models/global_iso_v1.pkl`
- Trained on: 186 real email feature vectors
- Behavioral baselines persist in named Docker volume `phishguard_ml_baselines` → survive container restarts

---

## 2. Architecture — 8 Layers

### Layer 0 — Trivial-Clean Pre-Filter (< 5ms)
**File:** `app/layer0/pre_filter.py`  
Fast-exit for short, URL-free, SPF+DKIM-pass emails. All 5 must pass: SPF=pass, DKIM=pass, 0 URLs, 0 attachments, body ≤ 600 chars, no urgency keywords. Returns `confidence: 0.02`, `fast_path: "layer0_trivial_clean"`.

### Layer 1 — OSINT Pre-Filter (< 50ms cached)
**File:** `app/layer1/verdicts.py`  
9 threat databases: VirusTotal, AbuseIPDB, URLhaus, Google Safe Browsing, PhishTank, MISP, Spamhaus, WHOIS (domain age), internal denylist.  
**Trusted domains now dynamic:** ~70 built-in + user-added via SQLite `trusted_domains` table. Add from Settings tab — no rebuild needed. 60s cache.

### Layer 2 — AI Consensus (< 5 seconds)
**File:** `app/layer2_ai/orchestrator.py`  
**Thresholds (current):** Tier 1 ≥ 0.90 (phishing) | Tier 2 ≥ **0.70** (phishing) | Tier 3 ≥ 0.42 (suspicious)  
3 engines: NLP (Claude→OpenAI→Gemini→heuristic), Behavioral (ISO forest + per-sender GMM), Structural (typosquatting, domain age, macros).

### Layer 3 — Sandbox Detonation
**File:** `app/layer3_sandbox/sandbox_runner.py`  
Fires when L2=suspicious AND URLs present AND confidence ≥ 0.45. Uses Python Docker SDK. App runs as root (`user: "0"` in docker-compose) so socket always accessible — no manual chmod needed.

### Layer 4 — SOAR
**File:** `app/layer4_soar/soar_orchestrator.py`  
7 integrations concurrent: ES, Slack, MISP, OpenCTI, Jira (unconfigured), email alerts, denylist.  
**Campaign detector:** `app/layer4_soar/campaign_detector.py` — clusters emails by normalised domain and NLP intent. API: `GET /api/campaigns?days=N`.  
**Weekly digest:** `app/layer4_soar/digest.py` — Slack Block Kit summary. Auto-sends Monday 09:00. Manual: `POST /api/digest/send` or SOAR tab button.

### Layer 5 — ML Classifier
**Files:** `app/layer5_ml/classifier.py`, `app/layer5_ml/training_pipeline.py`  
Blends: `final = 0.60 × L2_composite + 0.40 × ML_score`. Floor: suspicious ≥ 0.43, phishing ≥ 0.65.  
**Feedback loop wired:** `_load_feedback_records()` reads `feedback` table, excludes corrected scans from raw DB load, uses human labels. `n_feedback_corrections` shown in retrain metrics.  
**Retrain:** Dashboard → ML Ops tab. Also visible in MLflow at `localhost:5000`.

### Layer 6 — Security
JWT (HS256), RBAC (admin/analyst/readonly), rate limiter (120 req/min), audit log, input sanitiser.  
**Privacy:** `GET /api/scan/{id}` strips body_text/body_html server-side. `body_preview` removed from `/api/scans` list. Email content never surfaces via API.

### SMTP Rate Limiter — Email Bombing Protection
**File:** `app/security/smtp_rate_limiter.py`  
Four sliding-window counters checked before every email enters the pipeline. All configurable via env vars:

| Counter | Limit | Env var | Stops |
|---|---|---|---|
| Per-IP | 10/min | `SMTP_RATE_PER_IP` | Single-source flooding |
| Per-sender-domain | 20/hour | `SMTP_RATE_PER_DOMAIN` | Domain campaigns |
| **Per-recipient** | **30/min** | `SMTP_RATE_PER_RCPT` | **Distributed bombing (rotating IPs/domains)** |
| Global | 60/min | `SMTP_RATE_GLOBAL` | Total throughput cap |

**Tarpit:** 2s sleep before 421 — slows automated tools from 500/min to ~30/min.  
**Burst alert:** 5+ emails from same source in 10s → Slack alert.  
**421 = temporary** — MTA retries, no legitimate email permanently lost.  
Stats: `GET /health` → `smtp_rate_limiter`.  
**Demo:** Set `SMTP_RATE_PER_IP=200` in `.env` before running `demo_bombing.py` (current `.env` already has this set).

### Inbox Bombing Detector — Subscription Bomb Detection
**File:** `app/security/bombing_detector.py`  
Detects subscription bombs (attacker signs victim up to hundreds of legitimate services to bury critical alerts). Watches the RECIPIENT, not the sender — attacker can rotate infinite domains but can't change who the victim is.

**Two detection paths:**
1. **Velocity (fires email 5):** 5+ subscription subjects in 30s = bot speed → hold immediately
2. **Scoring (fires email 20):** `volume(40) + diversity(40) + pattern(20) ≥ 60`
   - Diversity is graduated: ≥70% new domains → +40, 50–70% → +20 (language-independent)
   - Pattern (English subscription subjects) is optional +20 booster — not a hard gate
   - Volume + diversity alone = 80 → detected (non-English bombs caught)

**Smart 3-way routing during hold:**
- `is_high_signal(subject)` (OTP, reset, bank alert, new-device) → **SURFACE — overrides even phishing verdict**. L1 OSINT already ran; bombing context means delivery is right.
- `is_subscription_pattern(subject)` → **HOLD** for SOC Pending Review
- Neither (unmatched) → **SURFACE** (default — err toward delivery)

**Why high-signal overrides phishing verdict:** A genuine bank OTP from an unknown domain scores "phishing" at L2 (new domain + banking subject = phishing pattern to Claude). During a bombing attack that's exactly the email to surface. L1 hard hits (VirusTotal/URLhaus) still quarantine before reaching this code.

**Cold-start:** < 10 known sender domains → diversity downweighted (protects new employees).  
**Memory:** `seen_domains` append-only, capped at 500 — no eviction.  
**All 11 thresholds** configurable via `BOMBING_*` env vars.  
**API:** `GET /api/bombing/status`, `POST /api/bombing/{rcpt}/clear`  
**Dashboard:** Orange banner on Overview tab, "Clear Hold" button, auto-expires after 20 min.  
**Demo:** `python3 scripts/demo_bombing.py` — 20 concurrent emails, velocity fires at email 5–7, OTP surfaces with `smtp_bombing_high_signal_delivered` log.  
**Full explanation:** `EMAIL_BOMBING_EXPLANATION.md`

### Layer 7 — Email Ingestion
3 paths: SMTP gateway (port 8025), Gmail OAuth historical scanner, REST `/analyze`.  
SMTP routing uses **L2 verdict** (not blended) to prevent ML floor from bypassing SOC review.

---

## 3. Running Services and Ports

| Service | URL | Login | Notes |
|---|---|---|---|
| **PhishGuard SOC Console** | `localhost:8000` | `dev-key` (any role) | ✅ Fully working |
| **Elasticsearch** | `localhost:9200` | `elastic / changeme` | ✅ 2,100+ docs |
| **Kibana** | `localhost:5601` | `elastic / changeme` | ✅ Working |
| **MLflow** | `localhost:5000` | none | ✅ Working |
| **MinIO API** | `localhost:9000` | `phishguard / changeme123` | ✅ Working |
| **MinIO UI** | `localhost:9001` | `phishguard / changeme123` | ✅ Working |
| **MISP** | `http://localhost:8888` → redirects to `https://localhost:8443` | `admin@admin.test / changeme123` | ⚠️ Accept SSL cert warning. 287 events exported. connector-misp version mismatch so no OpenCTI sync. |
| **OpenCTI** | `localhost:8080` | `admin@phishguard.local / changeme123` | ⚠️ Platform runs but 0 objects (connector broken) |
| **Grafana** | `localhost:3000` | `admin / changeme` | ✅ 4/8 panels showing (other 4 correctly empty — no errors, no /analyze traffic) |
| **Prometheus** | `localhost:9090` | none | ✅ Scraping every 15s |
| **Redis** | `localhost:6379` | password: `redispassword` | ✅ Working |
| **SMTP Gateway** | `localhost:8025` | none | ✅ Working |

### Docker Commands
```bash
docker compose up -d                   # start all 13 services
docker compose ps                      # check status
docker compose build app               # rebuild after code changes
docker compose up -d --no-deps app     # restart app only
# No manual chmod needed — app runs as root (user: "0" in docker-compose)
```

### Named Docker Volumes
| Volume | Contents |
|---|---|
| `phishguard_app_data` | SQLite DB, ML model, screenshots, audit log |
| `phishguard_ml_baselines` | Per-sender behavioral baselines |
| `phishguard_es_data` | Elasticsearch indices |
| `phishguard_mlflow_data` | MLflow experiment history |
| `phishguard_minio_data` | Evidence .eml files |

---

## 4. Demo Numbers (as of 2026-06-23 session 6)

| Metric | Value |
|---|---|
| Total emails scanned | 1,445 |
| Phishing blocked | 182 |
| Suspicious held for SOC | 240 |
| Clean delivered | 1,023 |
| Tests passing | 186 / 189 (3 skipped) |
| Running containers | 13/13 |
| Campaigns detected (30d) | 33+ |
| MISP threat events | 287 |
| Elasticsearch docs | 2,100+ |
| Behavioral baseline files | 15+ (persisted) |

---

## 5. Demo Script — Procedural Generator

**Script:** `scripts/test_smtp_gateway.py`  
**Generates unique emails every run** — no two runs produce the same email. Uses word banks + randomised amounts, names, domains, phrasing.

```bash
python3 scripts/test_smtp_gateway.py              # random run
python3 scripts/test_smtp_gateway.py --seed 42    # reproducible
python3 scripts/test_smtp_gateway.py --count 5    # 5 per category
```

**Clean tactics (5):** meeting invite, deployment notice, infra alert, HR event, maintenance notice  
**Suspicious tactics (7):** account verify, backup notification, billing, subscription renewal, IT password, survey, reward points  
**Phishing tactics (6):** brand typosquat (8 brands × multiple typo variants), BEC wire fraud, credential harvest, IRS refund, IT helpdesk, payroll  

### Demo Flow
1. `python3 scripts/test_smtp_gateway.py`
2. **Press F5** in browser (IDs are fresh each run)
3. Gmail → search `label:PhishGuard-Delivered` → clean emails
4. Dashboard → **Pending Review** tab → suspicious held
   - Click **📊 View Analysis** → forensic breakdown + threshold decision matrix
   - Click **📄 Export PDF** (in Reports tab scan detail) → light-themed PDF report
   - Click **✅ Approve** → delivered with `PhishGuard-SOC-Approved` label
5. Dashboard → **Quarantine** tab → phishing blocked
6. Dashboard → **Campaigns** tab → active campaigns auto-detected
7. Dashboard → **SOAR** tab → "Send Digest to Slack Now" → weekly summary

### Testing with Real Emails
```bash
# Download from Gmail: ⋮ → Show original → Download Original
python3 scripts/send_eml.py ~/Downloads/email.eml
```

---

## 6. SOC Dashboard — All Features

### Overview Tab
- Stats: total / phishing / suspicious / clean counts
- Recent activity feed

### Scan Tab
- Paste raw email → manual scan → verdict with layer breakdown

### Pending Review Tab
- **📊 View Analysis** — forensic breakdown: auth badges, L1 checks, L2 score bars, threshold decision matrix (Tier 1/2/3), NLP intent + tactics + reasoning, structural red flags, behavioral tier, ML score
- Panel survives 5s polling re-render
- **✅ Approve** → delivered to Gmail inbox with `PhishGuard-SOC-Approved` label
- **🔒 Reject** → quarantined

### Reports Tab
- Click any row → **visual scan report** (not raw JSON):
  - Verdict banner (colour-coded, confidence %, scan ID)
  - Email metadata + auth badges
  - L1 OSINT stat boxes
  - L2 score bars + threshold decision matrix
  - NLP analysis card, structural red flags, behavioral stats, ML scores, SOAR chips
  - **📄 Export PDF** → opens clean light-themed PDF in new window, auto-triggers print dialog
- **Search/filter** by sender, verdict
- **Mark Wrong** → saves feedback to `feedback` table for next ML retrain

### Quarantine Tab
- All phishing emails blocked

### Campaigns Tab ← NEW
- Detects coordinated attacks by normalised sender domain + NLP intent clustering
- Active campaign badge in nav (updates every 5s)
- Severity: critical/high/medium with colour coding
- **"View N Scans in Reports →"** deep-links to Reports filtered to campaign scans
- Window: 7/14/30 days configurable

### ML Ops Tab
- F1, ROC-AUC, confusion matrix, feature importances
- `n_feedback_corrections` — shows how many human corrections fed into last retrain
- Retrain button, bootstrap button

### SOAR Tab
- **Weekly Threat Digest** card — "Send Digest to Slack Now" button
- Integration status (ES, Slack, MISP, OpenCTI, Jira)
- Sender denylist management
- Recent SOAR actions audit

### Settings Tab
- Provider configuration (API keys)
- Detection thresholds
- **Trusted Sender Domains** — add/remove domains without code changes

---

## 7. Critical Gotchas

### Pending Review Stale Items
After each demo run press **F5** before clicking buttons — IDs are fresh per run.

### L2 Threshold Is 0.70
`HIGH_CONF_THRESHOLD = 0.70` in `app/layer2_ai/orchestrator.py`. Emails scoring 0.42–0.70 = suspicious (held for review). Above 0.70 = phishing (quarantine). Below 0.42 = clean.

### HuggingFace Dataset — Do NOT Use for Training
`data/training/huggingface_phishing_corpus.jsonl` degrades F1 from 0.89→0.62. Only train on data processed through the full pipeline.

### Behavioral Baselines Persisted
`ml/baselines/` is now in named volume `phishguard_ml_baselines`. Baselines survive restarts. New senders still start at Tier 0.

### Feedback Loop
`feedback` table accumulates SOC corrections (Mark Wrong button). At next retrain, corrections override original labels. Multiple corrections for same scan → latest wins.

### Email Bombing — Rate Limiter Tuning
Default limits (in `app/security/smtp_rate_limiter.py`): per-IP=10/min, per-domain=20/hr, per-recipient=30/min, global=60/min, tarpit=2s, burst=5/10s. Adjust constants at the top of the file — no rebuild needed if running locally (Python reimports). In Docker, rebuild after changing.

The per-recipient limit is the most important for real-world attacks — online bombing tools use rotating IPs/domains so only the recipient counter catches them.

### Privacy — Email Body Never Exposed
`GET /api/scan/{id}` strips body fields server-side. `body_preview` removed from list endpoint. No email body content accessible via any API.

### Campaign Detection Algorithm
Normalises sender domains by stripping TLD + year/number suffixes (`payment-hub-2026.com` → `payment-hub`). Groups with ≥ 3 emails = campaign. Intent campaigns exclude scan IDs already in domain campaigns to avoid double-counting.

### Gmail Daily Sending Limit
Alert emails use Gmail SMTP — 500/day free tier. After many runs alerts stop. Slack alerts have no limit.

### MISP SSL Certificate
Cert is for hostname `misp` not `localhost`. Do not restart MISP without cert files mounted.

---

## 8. Known Issues

### MISP web UI (⚠️ not blocking demo)
- `http://localhost:8888` redirects to `https://localhost:8443`
- Browser shows SSL cert warning (cert issued for hostname `misp`, not `localhost`) — click **Advanced → Proceed**
- Once logged in, nav links may redirect to `https://localhost/` (strips port) — manually type `https://localhost:8443/events/index`
- Login: `admin@admin.test` / `changeme123` (password reset via PHP bcrypt in session 6)
- **MISP still works for PhishGuard** — L1 queries it, L4 exports to it (287 events). Web UI is cosmetic for demo.

### connector-misp (⚠️ not blocking demo)
- connector-misp v6.2.18 uses GET `/events/restSearch` but MISP v2.5.40 requires POST → API mismatch
- OpenCTI has 0 objects — MISP→OpenCTI sync never completed
- Fix would require upgrading connector-misp image to a version compatible with MISP 2.5.40

### Grafana empty panels (✅ correct behaviour)
- Error Rate, 5xx Total show no data → **correct**, there are no 5xx errors
- `/analyze` panels show no data → **correct**, emails go via SMTP (port 8025) not the REST `/analyze` endpoint
- To populate `/analyze` panels: paste an email manually in the dashboard Scan tab

## 9. Immediate Next Steps

1. **Default passwords** — ES, Kibana, MinIO, OpenCTI, Grafana, MISP still use `changeme`/`changeme123`
2. **CORS lockdown** — `allow_origins=['*']` in `app/main.py` ~line 77
3. **Retrain ML** — 1,445 real scan records in DB, retrain from ML Ops tab
4. **PhishTank key** — registration may be re-enabled at phishtank.org/api_register.php
5. **Jira** — add `JIRA_BASE_URL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY` to .env
6. **SMTP rate limiter** — `.env` has `SMTP_RATE_PER_IP=200 SMTP_RATE_GLOBAL=200` set for bombing demo. Revert to defaults (10/60) for production: remove those lines from `.env`
7. **connector-misp upgrade** — upgrade to version compatible with MISP 2.5.40 to restore OpenCTI sync
8. **Gmail Workspace ingestion** — `INBOX_INGESTION_ENABLED` flag not yet built; needs service account + Workspace admin

---

## 9. API Keys Configured (in .env)

| Key | Status |
|---|---|
| `JWT_SECRET` | ✅ Set |
| `ANTHROPIC_API_KEY` | ✅ Set (Claude — primary NLP) |
| `VIRUSTOTAL_API_KEY` | ✅ Set |
| `ABUSEIPDB_API_KEY` | ✅ Set |
| `GOOGLE_SAFE_BROWSING_API_KEY` | ✅ Set |
| `SLACK_WEBHOOK_URL` | ✅ Set |
| `MISP_API_KEY` | ✅ Set |
| `GMAIL_OAUTH_TOKEN_FILE` | ✅ Set |
| `ALERT_SMTP_HOST` | ✅ Set (Gmail SMTP) |
| `PHISHTANK_API_KEY` | ❌ Not set |
| `JIRA_*` | ❌ Not set |
| `GOOGLE_SERVICE_ACCOUNT_JSON` | ❌ Not set |

---

## 10. Key Files

```
phishguard/
├── app/
│   ├── main.py                         # 35+ API endpoints
│   ├── pipeline.py                     # L0→L1→L2→L3→L4→L5 orchestrator
│   ├── storage.py                      # SQLite: scans, pending_review, trusted_domains, feedback
│   ├── layer0/pre_filter.py            # Trivial-clean fast-exit
│   ├── layer1/verdicts.py              # OSINT + dynamic trusted sender + denylist
│   ├── layer2_ai/orchestrator.py       # 3-tier verdict (0.90 / 0.70 / 0.42)
│   ├── layer2_ai/behavioral.py         # ISO forest + per-sender GMM
│   ├── layer2_ai/structural.py         # Typosquatting, domain age, macros
│   ├── layer2_ai/nlp_engine.py         # Claude → OpenAI → Gemini → heuristic
│   ├── layer3_sandbox/sandbox_runner.py # Docker SDK sandbox
│   ├── layer4_soar/soar_orchestrator.py # 7 SOAR integrations
│   ├── layer4_soar/campaign_detector.py # Domain+intent campaign clustering
│   ├── layer4_soar/digest.py           # Weekly Slack digest + scheduler
│   ├── layer5_ml/training_pipeline.py  # ExtraTrees + feedback loop
│   ├── layer5_ml/feature_extractor.py  # 24 ML features
│   ├── security/smtp_rate_limiter.py   # Direct flooding protection (4 counters + tarpit)
│   ├── security/bombing_detector.py   # Subscription bomb detection (velocity + scoring)
│   ├── layer7_gmail/smtp_receiver.py   # SMTP gateway routing
│   └── templates/index.html            # SOC Console SPA (~1,800 lines)
├── scripts/
│   ├── test_smtp_gateway.py            # Procedural 9-email demo (unique every run)
│   ├── send_eml.py                     # Pipe real .eml files through port 8025
│   └── fake_mail_server.py             # Fake downstream (port 1025)
├── tests/
│   ├── scripts/demo_bombing.py         # Concurrent subscription bomb demo (20 emails)
│   ├── EMAIL_BOMBING_EXPLANATION.md   # Lead-ready explanation of bombing protection
│   ├── test_layer0.py                  # 12 pre-filter tests
│   ├── test_campaigns.py               # 13 campaign detection tests
│   ├── test_smtp_rate_limiter.py       # 17 rate limiter + tarpit tests
│   ├── test_bombing_detector.py       # 21 subscription bomb detection tests
│   └── test_layer1/2/3/4/5/6/7.py     # Layer-specific tests
├── data/
│   ├── phishguard.db                   # SQLite (4 tables)
│   ├── model.pkl                       # ExtraTrees ML model (1.3 MB)
│   └── training/                       # spamassassin + gmail_clean only
├── docker-compose.yml                  # 13 services, 5 named volumes
├── RUNBOOK.md                          # Incident playbook
└── BRINGUP.md                          # Deployment guide
```

---

*Resume: read this file → `docker compose ps` (verify 13 containers healthy) → `python3 scripts/test_smtp_gateway.py` → press F5.*
