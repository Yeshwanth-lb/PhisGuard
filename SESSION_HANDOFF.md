# PhishGuard — Session Handoff Document
**Last updated:** 2026-06-22  
**Project root:** `/Users/intern4/Desktop/phishguard`  
**Developer:** Yeshwanth (yeshwanthlb0@gmail.com)  
**Purpose:** End-to-end email security gateway with 7-layer AI detection

---

## 1. Current System State

### Tests
- **109 passing, 3 skipped, 0 failing**
- Run with: `python3 -m pytest tests/ -q --ignore=tests/locustfile.py --ignore=tests/test_layer4_smtp_live.py --ignore=tests/test_layer2_claude_live.py`
- 3 skipped: live Slack tests (no webhook in env)

### Git Status
- Branch: `master` — all changes committed, working tree clean
- Latest commits:
  - `d1a6ad5` feat: wire SOC feedback corrections into ML retraining pipeline
  - `03358a7` fix: update sandbox tests to mock Docker SDK and remove dead code
  - `1d3570b` feat: randomised email pool to prevent ML overfitting
  - `25696be` feat: visual scan report and real-email testing utility
  - `dc393f5` feat: SOC dashboard improvements, privacy hardening, detection fixes

### Database State (as of 2026-06-22)
- **Total scans stored:** ~1,340+
- **Phishing:** ~152 | **Suspicious:** ~229 | **Clean:** ~953
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
- **DO NOT** use `data/training/huggingface_phishing_corpus.jsonl` — degraded F1 from 0.89→0.62 (feature mismatch: no pipeline scores)
- Feedback corrections from the `feedback` table are now folded in at retrain time (human-corrected labels override the original scan verdict)

### Global Isolation Forest
- Seeded at: `models/global_iso_v1.pkl`
- Trained on: 186 real email feature vectors
- Behavioral baselines now persist in named Docker volume `phishguard_ml_baselines` → survive container restarts

---

## 2. Architecture — 8 Layers (Layer 0 added this session)

### Layer 0 — Trivial-Clean Pre-Filter (< 5ms) ← NEW
**File:** `app/layer0/pre_filter.py`

Fast-exit for obviously safe emails — skips L1 OSINT and L2 AI entirely. All 5 must pass:
- SPF = "pass" AND DKIM = "pass"
- 0 extracted URLs
- 0 attachments
- Body ≤ 600 characters
- No urgency keywords (urgent, verify your, act now, wire transfer, etc.)

Returns `confidence: 0.02`, `fast_path: "layer0_trivial_clean"`. Conversational emails ("Hi, can you join the 3pm call?") take this path. Any failure → falls through to L1.

### Layer 1 — OSINT Pre-Filter (< 50ms cached)
**File:** `app/layer1/verdicts.py`

Checks 9 threat databases simultaneously. Any single hit = immediate block.

| Database | What it checks |
|---|---|
| VirusTotal | File hashes + URLs vs 70+ antivirus engines |
| AbuseIPDB | Sender IP abuse confidence score |
| URLhaus | Malware distribution URLs |
| Google Safe Browsing | URL threat database |
| PhishTank | Verified phishing pages |
| MISP | Community threat intelligence IoCs |
| Spamhaus | IP/domain blocklist |
| WHOIS | Domain age (< 7 days = critical) |
| Internal Denylist | Auto-populated SQLite blocklist |

**Trusted sender fast-exit:** Known platforms bypass ALL OSINT if SPF+DKIM pass. SPF/DKIM fail for trusted domain → spoofing detected → suspicious.

**Trusted domains now dynamic:** `TRUSTED_SENDER_DOMAINS` is hardcoded (~70 domains) but user-added domains are stored in the `trusted_domains` SQLite table and loaded at runtime (60s cache). Add/remove from Settings tab in the dashboard — no code change or rebuild needed.

**Key gotcha:** Auth `unknown` (no header) = clean for trusted domains (common with Gmail API historical emails). Only explicit `fail` = spoofing.

### Layer 2 — 4-Engine AI Consensus (< 5 seconds)
**File:** `app/layer2_ai/orchestrator.py`

**Three-tier verdict thresholds (updated this session):**
- Single engine ≥ **0.90** (SINGLE_ENGINE_THRESHOLD) → **Tier 1: phishing immediately**
- Composite ≥ **0.70** (HIGH_CONF_THRESHOLD) → **Tier 2: phishing** ← raised from 0.62
- Composite ≥ **0.42** (MED_CONF_THRESHOLD) → **Tier 3: suspicious**
- Below all → **fallback: clean**

**Why threshold raised 0.62→0.70:** Domain-age signals were pushing borderline suspicious emails across 0.62, sending them straight to Quarantine instead of Pending Review for SOC review. Now they correctly hold at 0.42–0.70 range.

**Engine 1 — Orchestrator** (`orchestrator.py`): Dispatches engines 2/3/4 via `asyncio.gather()`, applies tier logic.

**Engine 2 — NLP Intent Analyst** (`nlp_engine.py`): Claude (primary) → Gemini → OpenAI → heuristic fallback.

**Engine 3 — Behavioral Anomaly Detector** (`behavioral.py`): 3-tier cold start:
- Tier 0 (new sender): Context Scorer + ISO Forest
- Tier 1 (1-5 emails): 50/50 blend
- Tier 2 (6-19): ISO + per-sender Gaussian
- Tier 3 (20+): Full per-sender GMM
Baselines now persisted in `phishguard_ml_baselines` named Docker volume.

**Engine 4 — Structural Forensic** (`structural.py`): Typosquatting, homoglyphs, domain age, Reply-To mismatch, DMARC alignment, macro attachments, tracking pixels.

### Layer 3 — Sandbox Detonation (< 30 seconds)
**Files:** `app/layer3_sandbox/sandbox_runner.py`, `app/layer3_sandbox/page_analyzer.py`

Fires when L2 = "suspicious" AND URLs present AND confidence ≥ 0.45. Uses Python Docker SDK (not CLI). Screenshots saved to `data/screenshots/<scan_id>.png`.

**Docker socket:** App now runs as `user: "0"` (root) in docker-compose — socket is always accessible, no manual `chmod` needed after restart.

### Layer 4 — SOAR (async, all 7 fire simultaneously)
**File:** `app/layer4_soar/soar_orchestrator.py`

| Integration | Status | Config |
|---|---|---|
| Elasticsearch | ✅ Working | ES_URL in docker-compose |
| Slack | ✅ Working | SLACK_WEBHOOK_URL in .env |
| MISP | ✅ Working | MISP_URL=https://misp, MISP_API_KEY in .env |
| OpenCTI | ✅ Working | OPENCTI_URL, OPENCTI_TOKEN in docker-compose |
| Jira | ❌ Not configured | Needs JIRA_BASE_URL, JIRA_API_TOKEN |
| Email alerts | ✅ Working | Gmail SMTP (hits rate limit after ~500/day) |
| Denylist | ✅ Working | Auto-populates on L1 OSINT hits only |

**MISP API key:** `keugWnClooY4yPB7vItEnfVikSRxUeUH5TY7DO7z` (in .env and docker-compose)

### Layer 5 — ML Classifier
**Files:** `app/layer5_ml/classifier.py`, `app/layer5_ml/training_pipeline.py`

Blends with L2: `final = 0.60 × L2_composite + 0.40 × ML_score`

**ML floor protection:** ML cannot downgrade L2's verdict:
- L2 = suspicious → final score floored at 0.43
- L2 = phishing → final score floored at 0.65

**Feedback loop (new this session):** `training_pipeline._load_feedback_records()` reads from the `feedback` SQLite table, uses human-corrected labels, and excludes the original scan record so wrong labels don't compete. `n_feedback_corrections` now appears in retrain metrics.

**Retrain:** Dashboard → ML Ops tab → "Retrain on Current Data". Also visible in MLflow at `localhost:5000`.

**24 features:** url_count, has_http_url, has_ip_url, l1_hit_count, structural_score, nlp_score, behavioral_score, l2_confidence, urgent_word_count, brand_spoof_count, subject_len, spf_fail, dkim_fail, attachment_count, body_length, html_only, distinct_url_domains, shortener_url_count, body_brand_count, reply_to_mismatch, subject_uppercase_ratio, subject_exclamation_count, subject_non_ascii_count, anchor_text_href_mismatch.

### Layer 6 — Security
JWT (HS256) + RBAC (admin/analyst/readonly) + rate limiter (120 req/min) + audit log + input sanitiser.

**Privacy hardening (this session):**
- `GET /api/scan/{id}` strips `body_text`, `body_html`, `body_plain` server-side — raw email content never leaves the API
- `GET /api/pending/{id}/body` endpoint removed entirely
- "Read Email" button removed from Pending Review tab

### Layer 7 — Email Ingestion
Three paths:
1. **SMTP Gateway (port 8025):** Main demo path. Routes: clean→Gmail API inject, suspicious→pending_review hold, phishing→quarantine RCPT rewrite.
2. **Gmail OAuth scanner:** Historical inbox scan.
3. **REST API `/analyze`:** Manual scan via dashboard.

**SMTP routing uses L2 verdict** (not final blended) to prevent ML floor from pushing suspicious to phishing and bypassing SOC review.

---

## 3. Running Services and Ports

| Service | URL | Login | Notes |
|---|---|---|---|
| **PhishGuard SOC Console** | `localhost:8000` | `dev-key` (any role) | Main dashboard |
| **Elasticsearch** | `localhost:9200` | `elastic / changeme` | 2,100+ docs indexed |
| **Kibana** | `localhost:5601` | `elastic / changeme` | Phishing dashboards |
| **MLflow** | `localhost:5000` | none | Model registry + retrain history |
| **MinIO API** | `localhost:9000` | `phishguard / changeme123` | S3 API |
| **MinIO UI** | `localhost:9001` | `phishguard / changeme123` | Browse evidence .eml files |
| **MISP** | `localhost:8888` | `admin@admin.test` / `changeme123` | 80+ threat events |
| **OpenCTI** | `localhost:8080` | `admin@phishguard.local / changeme123` | v6.2.18 |
| **Grafana** | `localhost:3000` | `admin / changeme` | 8 metric panels |
| **Prometheus** | `localhost:9090` | none | Scrapes /metrics every 15s |
| **Redis** | `localhost:6379` | password: `redispassword` | L1 cache |
| **SMTP Gateway** | `localhost:8025` | none | Receives emails for analysis |

### Docker Compose Quick Commands
```bash
docker compose up -d          # start all 13 services
docker compose ps             # check status
docker compose build app      # rebuild after code changes
docker compose up -d --no-deps app  # restart app only (preferred — keeps other services up)
# NOTE: No chmod needed — app runs as root, Docker socket always accessible
```

### Named Docker Volumes (data that survives restarts)
| Volume | What it holds |
|---|---|
| `phishguard_app_data` | SQLite DB, ML model, screenshots, audit log |
| `phishguard_ml_baselines` | Per-sender behavioral baselines (NEW) |
| `phishguard_es_data` | Elasticsearch indices |
| `phishguard_mlflow_data` | MLflow experiment history |
| `phishguard_minio_data` | Evidence .eml files |

---

## 4. Demo Numbers (as of 2026-06-22)

| Metric | Value |
|---|---|
| Total emails scanned | 1,340+ |
| Phishing blocked | 152+ |
| Suspicious held for review | 229+ |
| Clean delivered | 953+ |
| ML model F1 | 0.894 |
| ML model ROC-AUC | 0.974 |
| Tests passing | 109/112 (3 skipped — live Slack) |
| Running containers | 13/13 healthy |
| Elasticsearch docs | 2,100+ |
| Behavioral baseline files | 15+ (persisted across restarts) |

---

## 5. The Demo Script — Randomised Pool

**Script:** `scripts/test_smtp_gateway.py`  
**Recipient:** `yeshwanthlb0@gmail.com`

Script now draws **randomly** from a pool of 30 emails (10 clean, 10 suspicious, 10 phishing) to prevent ML overfitting to a fixed set. A different 9 emails are selected each run.

```bash
python3 scripts/test_smtp_gateway.py           # random selection
python3 scripts/test_smtp_gateway.py --seed 42 # reproducible run
```

**Clean pool covers:** business sync, HR announcements, DevOps alerts, GitHub notifications, Notion/Stripe/LinkedIn notifications, newsletter, calendar reminders.

**Suspicious pool covers:** account verification from unknown domains, backup services, billing portals, doc shares, reward schemes, tax refunds, HR benefits portals, subscription renewals.

**Phishing pool covers:** PayPal/Microsoft/Apple/Netflix/Amazon typosquats, BEC wire fraud, IRS impersonation, DocuSign fake, payroll credential harvest, IT helpdesk impersonation.

### Demo Flow
```bash
# Send 9 emails
python3 scripts/test_smtp_gateway.py

# IMPORTANT: Press F5 in browser before clicking anything — IDs are fresh each run
```

1. Gmail inbox → search `label:PhishGuard-Delivered` → clean emails arrived
2. Dashboard → **Pending Review** tab (orange badge) → suspicious emails held
   - Click **📊 View Analysis** → see full forensic breakdown with threshold decision matrix
   - Click **✅ Approve** → email delivered to Gmail with `PhishGuard-SOC-Approved` label
   - Click **🔒 Reject** → moves to Quarantine tab
3. Dashboard → **Quarantine** tab → phishing blocked
4. Dashboard → **Reports** tab → click any row → visual scan report (not JSON)

### Testing with Real Emails
```bash
# Download any email from Gmail: three-dot menu → Show original → Download Original
python3 scripts/send_eml.py ~/Downloads/email.eml
```

---

## 6. SOC Dashboard Features (added this session)

### Pending Review Tab
- **📊 View Analysis** button per email — shows full forensic breakdown:
  - Email auth (SPF/DKIM/DMARC) colour badges
  - L1 OSINT: checks run, hard hits, weak signals
  - L2 score bars (NLP 50%, Structural 30%, Behavioral 20%) with threshold markers
  - **Threshold Decision Matrix** — shows each threshold (0.90 / 0.70 / 0.42) vs actual score with EXCEEDED / not reached labels
  - NLP intent chip + tactics pills + Claude's reasoning quote
  - Structural red flags with critical/high/medium severity
  - Behavioral tier + emails seen from sender
  - ML blended score + floor protection note
- Panel survives the 5-second polling re-render (state saved before, restored after)

### Reports Tab
- **Visual scan report** when clicking any row — replaces raw JSON with structured cards:
  - Colour-coded verdict banner (large confidence %, timestamp, scan ID)
  - Email metadata + auth badges side by side
  - L1 stat boxes (checks / hard hits / weak signals)
  - L2 score bars + threshold decision matrix
  - NLP analysis card
  - Structural red flags severity cards
  - Behavioral stat boxes
  - Sandbox screenshot (if fired)
  - ML classifier stat boxes
  - SOAR integration chips (green/red per integration)
- **Search/filter bar** — filter by sender, verdict (all/phishing/suspicious/clean)
- **Mark Wrong** button per row — saves SOC correction to `feedback` table for next retrain

### Settings Tab
- **Trusted Sender Domains** card — lists all 70 built-in domains (collapsed) + user-added domains with Remove button. Add any domain without touching code or rebuilding.

### Browser Notifications
- Requests permission on first load
- Desktop notification fires when new phishing blocked or new pending review arrives (even if tab is in background)

---

## 7. Critical Decisions and Gotchas

### DB Sync Issue (most common problem)
Running `python3 scripts/...` directly writes to LOCAL `data/phishguard.db`. Docker reads from volume. Fix:
```bash
docker cp data/phishguard.db phishguard-app:/app/data/phishguard.db
docker exec --user root phishguard-app chmod -R 777 /app/data/
```

### Pending Review Stale Items
After each demo run press **F5** before clicking Approve/Reject — IDs are fresh per run.

### L2 Threshold Tuned to 0.70
`HIGH_CONF_THRESHOLD` was raised from 0.62 to 0.70 (`app/layer2_ai/orchestrator.py`). Domain-age signals alone were pushing borderline emails to phishing. If you want tighter detection, lower it back — but expect more suspicious emails escalating to quarantine.

### Gmail Daily Sending Limit
Alert emails use Gmail SMTP. Free tier = 500/day. After many demo runs, alerts stop. Slack alerts have no limit.

### MISP SSL Certificate
MISP cert is for hostname `misp` (not `localhost`). Do not restart MISP without cert files mounted — reverts to localhost cert and breaks connector.

### HuggingFace Dataset — Do NOT Use for Training
`data/training/huggingface_phishing_corpus.jsonl` exists but degraded F1 from 0.89→0.62. Root cause: no L2 pipeline features (all zeros). Only train on data processed through the pipeline.

### Behavioral Baselines Now Persisted
`ml/baselines/` is now mounted as named volume `phishguard_ml_baselines`. Baselines survive restarts. Tier 0 (new sender) is still the starting tier for any sender not yet seen.

### Feedback Loop
`feedback` table accumulates SOC corrections. At next retrain, these override original scan labels. Multiple corrections for the same scan → latest wins. Visible in MLflow as `n_feedback_corrections` metric.

### Privacy — Email Body Never Exposed
`GET /api/scan/{id}` strips body_text/body_html server-side. The "Read Email" button and `/api/pending/{id}/body` endpoint have been removed. SOC analysts see metadata + analysis scores only.

---

## 8. Immediate Next Steps

1. **Change default passwords** for production: ES, Kibana, MinIO, OpenCTI, Grafana, MISP all use `changeme`/`changeme123`
2. **Lock CORS** — `allow_origins=['*']` in `app/main.py` line ~77, change to specific origin for production
3. **Remove empty stub** — `app/smtp_server/` still has an empty `__init__.py`, should be deleted
4. **PhishTank key** — phishtank.org/api_register.php (was disabled, worth re-checking)
5. **Jira** — Add `JIRA_BASE_URL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY` to .env
6. **Retrain ML** with accumulated feedback once SOC has flagged a batch of wrong verdicts

---

## 9. API Keys Configured (in .env)

| Key | Status |
|---|---|
| `JWT_SECRET` | ✅ Set (32-byte random hex) |
| `ANTHROPIC_API_KEY` | ✅ Set (Claude — primary NLP) |
| `VIRUSTOTAL_API_KEY` | ✅ Set |
| `ABUSEIPDB_API_KEY` | ✅ Set |
| `GOOGLE_SAFE_BROWSING_API_KEY` | ✅ Set |
| `SLACK_WEBHOOK_URL` | ✅ Set |
| `MISP_API_KEY` | ✅ Set |
| `GMAIL_OAUTH_TOKEN_FILE` | ✅ Set (credentials/gmail_oauth_token.json) |
| `ALERT_SMTP_HOST` | ✅ Set (Gmail SMTP) |
| `PHISHTANK_API_KEY` | ❌ Not set (registration was disabled) |
| `JIRA_*` | ❌ Not set |
| `GOOGLE_SERVICE_ACCOUNT_JSON` | ❌ Not set (Workspace SA, needs admin) |

---

## 10. File Locations — Key Files

```
phishguard/
├── app/
│   ├── main.py                         # 35+ API endpoints, Prometheus metrics, OTel
│   ├── pipeline.py                     # L0→L1→L2→L3→L4→L5 orchestrator
│   ├── storage.py                      # SQLite: scans, pending_review, trusted_domains, feedback
│   ├── config.py                       # All settings
│   ├── llm/client.py                   # Unified LLM client (Claude/OpenAI/Gemini/heuristic)
│   ├── layer0/pre_filter.py            # NEW: trivial-clean fast-exit
│   ├── layer1/verdicts.py              # OSINT + dynamic trusted sender + denylist
│   ├── layer2_ai/orchestrator.py       # 3-tier verdict, thresholds (0.90/0.70/0.42)
│   ├── layer2_ai/behavioral.py         # 3-tier cold start, ISO forest, Gaussian
│   ├── layer2_ai/structural.py         # Typosquatting, domain age, macros
│   ├── layer2_ai/nlp_engine.py         # Multi-provider NLP + heuristic fallback
│   ├── layer3_sandbox/sandbox_runner.py # Docker SDK sandbox (not CLI)
│   ├── layer4_soar/soar_orchestrator.py # 7 SOAR integrations concurrent
│   ├── layer5_ml/training_pipeline.py  # ExtraTrees + CalibratedCV + feedback loop
│   ├── layer5_ml/feature_extractor.py  # 24 ML features
│   ├── layer7_gmail/smtp_receiver.py   # SMTP gateway routing
│   ├── layer7_gmail/gmail_client.py    # Gmail API delivery
│   └── templates/index.html            # SOC Console SPA (~1,500 lines)
├── scripts/
│   ├── test_smtp_gateway.py            # Randomised 9-email demo (10×10×10 pool)
│   ├── send_eml.py                     # NEW: pipe real .eml files through port 8025
│   ├── fake_mail_server.py             # Fake downstream server (port 1025)
│   └── setup_kibana.py                 # Provisions Kibana dashboard
├── data/
│   ├── phishguard.db                   # SQLite (4 tables: scans, pending_review, trusted_domains, feedback)
│   ├── model.pkl                       # ExtraTrees ML model (1.3 MB)
│   ├── training/                       # spamassassin + gmail_clean (DO NOT add HF corpus)
│   ├── verdicts/                       # Live prediction logs (NOT training data)
│   └── evidence/                       # Local fallback for MinIO
├── docker/
│   ├── misp-cert.pem / misp-key.pem / misp-ca.pem
│   └── grafana/provisioning/
├── ml/
│   ├── baselines/                      # Per-sender behavioral baselines (now in named volume)
│   └── pretrain_global_baseline.py
├── models/
│   └── global_iso_v1.pkl               # Isolation Forest (186 emails)
├── RUNBOOK.md                          # Incident playbook + alert routing
├── BRINGUP.md                          # Deployment guide
└── docker-compose.yml                  # 13 services, 5 named volumes
```

---

*Resume by reading this file first, then `docker compose ps` to verify all 13 containers are healthy, then `python3 scripts/test_smtp_gateway.py` to verify the pipeline end-to-end.*
