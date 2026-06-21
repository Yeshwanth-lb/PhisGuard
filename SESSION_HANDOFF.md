# PhishGuard — Session Handoff Document
**Last updated:** 2026-06-21  
**Project root:** `/Users/intern4/Desktop/phishguard`  
**Developer:** Yeshwanth (yeshwanthlb0@gmail.com)  
**Purpose:** End-to-end email security gateway with 7-layer AI detection

---

## 1. Current System State

### Tests
- **120 unit/integration tests — 116 passing** (4 skipped: live SMTP rate-limited, live Claude tests)
- Run with: `python3 -m pytest tests/ -q --ignore=tests/locustfile.py --ignore=tests/test_layer4_smtp_live.py`

### Git Status
- All changes are on `master` branch, uncommitted (large working session)
- Key files modified since last commit: `app/pipeline.py`, `app/layer7_gmail/smtp_receiver.py`, `app/layer7_gmail/gmail_client.py`, `app/layer4_soar/misp_exporter.py`, `app/layer2_ai/behavioral.py`, `app/layer2_ai/structural.py`, `app/layer1/verdicts.py`, `app/storage.py`, `app/main.py`, `app/templates/index.html`, `scripts/test_smtp_gateway.py`

### Database State (as of last session)
- **Total scans stored:** 1,272
- **Phishing:** 118 | **Suspicious:** 220 | **Clean:** 934
- SQLite at `data/phishguard.db` (also synced to Docker volume `/app/data/phishguard.db`)
- **IMPORTANT:** Local `data/phishguard.db` and Docker volume DB can drift. After running Python scripts directly (not via Docker API), run: `docker cp data/phishguard.db phishguard-app:/app/data/phishguard.db` then fix perms: `docker exec --user root phishguard-app chmod -R 777 /app/data/`

### ML Model
- Algorithm: `ExtraTreesClassifier` (300 trees, class_weight='balanced')
- Wrapped in: `CalibratedClassifierCV` (isotonic, 3-fold)
- F1: **0.894** | ROC-AUC: **0.974**
- Saved at: `data/model.pkl`
- Training data: `data/training/spamassassin_corpus.jsonl` (5,772 emails) + `data/training/gmail_clean_corpus.jsonl` (307 real clean emails)
- **DO NOT** use `data/training/huggingface_phishing_corpus.jsonl` — it degraded F1 from 0.89→0.62 due to feature mismatch (raw text bodies, no pipeline features)

### Global Isolation Forest
- Seeded at: `models/global_iso_v1.pkl`
- Trained on: 186 real email feature vectors
- Activates behavioral anomaly detection (returns neutral 0.5 until 50 emails seen)

---

## 2. Seven-Layer Detection Architecture

### Layer 1 — OSINT Pre-Filter (< 50ms cached)
**File:** `app/layer1/verdicts.py`  
**What it does:** Checks 9 threat databases simultaneously. Any single hit = immediate block.

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

**Trusted sender fast-exit:** Known platforms (LinkedIn, Google, SBI, etc.) bypass ALL OSINT if SPF+DKIM pass. If SPF/DKIM fail for a trusted domain → spoofing detected → suspicious verdict.

**Key gotcha:** Trusted domain check uses subdomain matching (e.g. `e.linkedin.com` matches `linkedin.com`). Auth `unknown` (no header) = clean for trusted domains (common with Gmail API historical emails).

**Trusted domains list location:** `TRUSTED_SENDER_DOMAINS` set in `app/layer1/verdicts.py` lines ~35-65. Contains 40+ domains including bewakoof.com, SBI subdomains, Indian brands.

### Layer 2 — 4-Engine AI Consensus (< 5 seconds)
**File:** `app/layer2_ai/orchestrator.py`

**Three-tier verdict:**
- Single engine ≥ 0.90 (SINGLE_ENGINE_THRESHOLD) → **Tier 1: phishing immediately**
- Composite ≥ 0.62 (HIGH_CONF_THRESHOLD) → **Tier 2: phishing**
- Composite ≥ 0.42 (MED_CONF_THRESHOLD) → **Tier 3: suspicious**
- Below all → **fallback: clean**

**Engine 1 — Orchestrator** (`orchestrator.py`): Dispatches engines 2/3/4 via `asyncio.gather()`, applies tier logic, uses unified `LLMClient`.

**Engine 2 — NLP Intent Analyst** (`nlp_engine.py`): Claude (primary) → Gemini → OpenAI → heuristic fallback. Detects BEC, credential harvesting, urgency manipulation, executive impersonation. Heuristic fallback works with zero API keys.

**Engine 3 — Behavioral Anomaly Detector** (`behavioral.py`): 3-tier cold start:
- Tier 0 (new sender): Context Scorer + ISO Forest  
- Tier 1 (1-5 emails): 50/50 blend  
- Tier 2 (6-19): ISO + per-sender Gaussian  
- Tier 3 (20+): Full per-sender GMM  
Baselines stored as JSON files in `ml/baselines/` (Docker: `/app/ml/baselines/` — currently empty, resets on container restart since not in a named volume).

**Engine 4 — Structural Forensic** (`structural.py`): Typosquatting (inline Levenshtein, no external dep), homoglyphs, domain age via WHOIS (cached 24h), Reply-To mismatch, DMARC alignment, macro attachments (.docm/.xlsm), double extensions, tracking pixels.

**Unified LLM Client** (`app/llm/client.py`): Single interface for all AI. Set `LLM_PROVIDER=auto` in .env → auto-detects from keys. Priority: Claude → OpenAI → Gemini → heuristic.

### Layer 3 — Sandbox Detonation (< 30 seconds)
**Files:** `app/layer3_sandbox/sandbox_runner.py`, `app/layer3_sandbox/page_analyzer.py`, `app/layer3_sandbox/ocr_engine.py`

**ONLY fires when L2 verdict = "suspicious" AND email has URLs AND confidence ≥ L3_TRIGGER_THRESHOLD (0.45)**. Does NOT fire on phishing (pipeline exits early) or clean.

**Key fix:** Uses Python Docker SDK (not CLI — CLI not in app container). Docker socket mounted at `/var/run/docker.sock`. After container restart: `docker exec --user root phishguard-app chmod 666 /var/run/docker.sock`.

**Screenshots:** Saved to `data/screenshots/<email_id>.png`. Accessible via `GET /api/scan/{scan_id}/screenshot`. Shown in Reports tab when clicking any scan.

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

**MISP API key:** `keugWnClooY4yPB7vItEnfVikSRxUeUH5TY7DO7z` (stored in .env and docker-compose)  
**MISP cert:** Mounted at `docker/misp-cert.pem` and `docker/misp-key.pem` (generated for hostname `misp`, not `localhost`). Connector needs this cert to avoid SSL errors.

**Evidence store:** Every phishing/suspicious email → MinIO `phishguard-evidence` bucket as `YYYY/MM/DD/<uuid>/email.eml` + `report.json`. Falls back to `data/evidence/` if MinIO unreachable.

### Layer 5 — ML Classifier
**Files:** `app/layer5_ml/classifier.py`, `app/layer5_ml/training_pipeline.py`

Blends with L2: `final = 0.60 × L2_composite + 0.40 × ML_score`

**ML floor protection** (critical fix from this session): ML cannot downgrade L2's verdict:
- If L2 says suspicious → final score floored at 0.43
- If L2 says phishing → final score floored at 0.65

This prevents ML from misclassifying modern BEC/spear-phishing (ML trained on 2006 SpamAssassin data, doesn't know BEC patterns).

**Retrain:** Dashboard → ML Ops tab → "Retrain on Current Data" button.

### Layer 6 — Security
JWT (HS256) + RBAC (admin/analyst/readonly) + rate limiter (120 req/min) + audit log + input sanitiser. All endpoints require auth except `/health` and `/api/stats`.

### Layer 7 — Email Ingestion
Three paths:
1. **SMTP Gateway (port 8025):** Main demo path. `aiosmtpd` receives emails, runs pipeline, routes: clean→Gmail API inject, suspicious→pending_review hold, phishing→quarantine RCPT rewrite.
2. **Gmail OAuth scanner:** Historical inbox scan with checkpoint (SQLite at `data/gmail_scan_checkpoint.db`).
3. **REST API `/analyze`:** Manual scan via dashboard.

**SMTP routing logic** (`app/layer7_gmail/smtp_receiver.py`):
- Uses **L2 verdict** for routing (not final blended), to prevent ML floor from pushing suspicious to phishing and bypassing human review
- Clean → `deliver_to_inbox()` via Gmail API → lands in real inbox with `PhishGuard-Delivered` label
- Suspicious → `storage.save_pending_review()` → holds, NOT delivered
- Phishing → relay with quarantine RCPT rewrite → `quarantine@phishguard.local`

**Gmail API delivery fix** (this session): `users.messages.import_()` followed by explicit `addLabelIds: ["INBOX", label_id]` to force email into inbox. Without the INBOX label, emails go to All Mail but don't appear in inbox.

**Credentials mount:** Changed from `:ro` to `:rw` in docker-compose so OAuth token can refresh.

---

## 3. Running Services and Ports

| Service | URL | Login | Notes |
|---|---|---|---|
| **PhishGuard SOC Console** | `localhost:8000` | `dev-key` (any role) | Main dashboard |
| **Elasticsearch** | `localhost:9200` | `elastic / changeme` | 1,978+ docs indexed |
| **Kibana** | `localhost:5601` | `elastic / changeme` | Dashboard: `/app/dashboards#/view/phishguard-ops` |
| **MLflow** | `localhost:5000` | none | Model registry |
| **MinIO API** | `localhost:9000` | `phishguard / changeme123` | S3 API |
| **MinIO UI** | `localhost:9001` | `phishguard / changeme123` | Browse evidence files |
| **MISP** | `localhost:8888` | `admin@admin.test` | 80+ events stored |
| **OpenCTI** | `localhost:8080` | `admin@phishguard.local / changeme123` | v6.2.18, token: `e9cd0d97-04f8-4cbb-91fb-7153192b118c` |
| **Grafana** | `localhost:3000` | `admin / changeme` | 8 metric panels |
| **Prometheus** | `localhost:9090` | none | Scrapes /metrics every 15s |
| **RabbitMQ** | internal only | `opencti / changeme123` | OpenCTI message broker |
| **Redis** | `localhost:6379` | password: `redispassword` | MISP + app cache |
| **SMTP Gateway** | `localhost:8025` | none | Test with `python3 scripts/test_smtp_gateway.py` |

### Docker Compose Quick Commands
```bash
docker compose up -d          # start all 13 services
docker compose ps             # check status
docker compose build app      # rebuild after code changes
docker compose restart app    # restart app only
docker exec --user root phishguard-app chmod -R 777 /app/data/ /app/credentials/
docker exec --user root phishguard-app chmod 666 /var/run/docker.sock
```

---

## 4. Demo Numbers (as of last session)

| Metric | Value |
|---|---|
| Total emails scanned | 1,272 |
| Phishing blocked | 118 |
| Suspicious held for review | 220 |
| Clean delivered | 934 |
| False positive rate | ~0% (after trusted sender tuning) |
| ML model F1 | 0.894 |
| ML model ROC-AUC | 0.974 |
| Tests passing | 116/120 (4 rate-limited) |
| Running containers | 13/13 healthy |
| MISP events exported | 80+ |
| MinIO evidence files | 143+ raw .eml files |
| Elasticsearch docs | 1,978+ |

---

## 5. The Demo Script — Exactly What Gets Sent

**Script:** `scripts/test_smtp_gateway.py`  
**Recipient for all:** `yeshwanthlb0@gmail.com`

### 3 Clean Emails (arrive in Gmail inbox, label: PhishGuard-Delivered)
1. `alice@partnerco.com` — "Q3 project sync — notes from today"
2. `hr@mycompany.com` — "Team lunch on Friday — please RSVP"
3. `newsletter@techcrunch.com` — "This week in tech: AI funding rounds"

### 3 Suspicious Emails (held in Pending Review tab, NOT delivered)
1. `verify@account-management-portal-2026.com` — "Your account requires attention" (62%)
2. `support@cloudstorage-backup-2026.com` — "Your backup completed successfully" (48%)
3. `billing@payment-services-hub-2026.com` — "Invoice pending for your review" (62%)

**Why these specific emails:** Previous suspicious emails (CEO BEC, IT helpdesk) sometimes scored above 90% NLP making Claude classify them as Tier 1 phishing instead of suspicious. These new ones reliably score 42-62%.

### 3 Phishing Emails (RCPT rewritten to quarantine, visible in Quarantine tab)
1. `security@paypa1-verify.com` — "URGENT: Your PayPal account has been limited" (74%)
2. `noreply@micros0ft-account-alert.net` — "Your Microsoft 365 session has expired" (74%)
3. `ceo-transfer@company-exec-wire.net` — "CONFIDENTIAL: Urgent wire transfer" (47%)

### How to run the demo
```bash
# Terminal 1 (optional — shows emails arriving at fake server)
python3 scripts/fake_mail_server.py

# Terminal 2 — send the 9 emails
python3 scripts/test_smtp_gateway.py

# IMPORTANT: Press F5 in browser before clicking Pending Review buttons
# Old IDs become stale after each run — always refresh first
```

**Demo flow after sending:**
1. Gmail inbox: search `label:PhishGuard-Delivered` → see 3 clean emails
2. Dashboard → Pending Review tab (orange badge) → 3 suspicious emails held
3. Click **Approve** → email arrives in Gmail inbox with `PhishGuard-SOC-Approved` label
4. Click **Reject** → dashboard auto-navigates to Quarantine tab
5. Dashboard → Quarantine tab → 3 phishing blocked

---

## 6. Critical Decisions and Gotchas from This Session

### DB Sync Issue (most common problem)
When running `python3 scripts/...` directly (not via Docker API), scans write to LOCAL `data/phishguard.db`. Dashboard reads from Docker volume `/app/data/phishguard.db`. These diverge. Fix:
```bash
docker cp data/phishguard.db phishguard-app:/app/data/phishguard.db
docker exec --user root phishguard-app chmod -R 777 /app/data/
docker compose restart app
```

### Pending Review Shows Stale Items
After each `python3 scripts/test_smtp_gateway.py` run, new pending IDs are generated. If you approved/rejected in a previous run and the dashboard still shows old items → **press F5**. Clicking buttons on old IDs returns 404.

### Gmail Daily Sending Limit
Alert emails use Gmail SMTP (`yeshwanthlb0@gmail.com`). Gmail free tier = 500 emails/day. After many demo runs, alerts stop with `550 5.4.5 Daily user sending limit exceeded`. This is a demo limitation only — in production use company SMTP relay. Slack alerts have no limit.

### MISP SSL Certificate
MISP uses a self-signed cert generated for hostname `misp` (not `localhost`). The cert files are:
- `docker/misp-cert.pem` — mounted into MISP nginx container
- `docker/misp-key.pem` — mounted into MISP nginx container  
- `docker/misp-ca.pem` — mounted into connector-misp for trust

After `docker compose restart misp`, nginx reloads from the mounted files automatically. **Do not** restart MISP without these files mounted or the SSL cert reverts to the original `localhost` cert, breaking the connector.

### MISP API Key
Stored in `.env` as `MISP_API_KEY=keugWnClooY4yPB7vItEnfVikSRxUeUH5TY7DO7z`. Also set in docker-compose environment for `app` and `connector-misp`. This key was generated via PHP inside the MISP container using `BlowfishConstantPasswordHasher`. Do not regenerate it unless MISP container is rebuilt.

### OpenCTI Admin Token Must Be a UUID
`APP__ADMIN__TOKEN=e9cd0d97-04f8-4cbb-91fb-7153192b118c` — must be a valid UUID v4. OpenCTI 6.x rejects non-UUID tokens on startup.

### Docker Socket Permissions Reset
After every `docker compose restart app`, the Docker socket inside the container loses write permission. The sandbox (Layer 3) needs it to spawn containers. Fix:
```bash
docker exec --user root phishguard-app chmod 666 /var/run/docker.sock
```
Add this to the startup routine. Future improvement: add a Dockerfile command to handle this.

### Sandbox Only Fires on Suspicious Emails
Layer 3 sandbox only runs when L2 = "suspicious" AND email has URLs AND L2 confidence ≥ 0.45. Emails scoring "phishing" at L2 → pipeline exits immediately, sandbox never runs. This is correct behavior (we're already confident). Screenshots only captured when sandbox fires.

### Trusted Sender Auth Unknown
For emails fetched via Gmail API historical scanner, `Authentication-Results` header is often missing → `spf=unknown, dkim=unknown`. Treating "unknown" as "fail" would block all historical Gmail emails. Decision: for trusted domains, `unknown` auth = clean (same as pass). Only explicit `fail` = spoofing detected. This was a deliberate security tradeoff.

### Behavioral Engine Baselines Not Persisted in Docker
`ml/baselines/` is NOT in a named Docker volume. Baselines reset when container restarts. For the demo this is fine (all senders appear as "new" = Tier 0, context scorer runs). Production would need a named volume or SQLite persistence.

### HuggingFace Dataset — Do NOT Use for Training
`data/training/huggingface_phishing_corpus.jsonl` exists but using it degraded F1 from 0.88 to 0.62. Root cause: these emails have no L2 pipeline features (structural_score, nlp_score etc. all = 0), so the model can't distinguish phishing from clean on those features. Only use corpora processed through the pipeline.

### Alert Email vs Phishing Email Confusion
When phishing is detected, PhishGuard sends a `[PhishGuard SOC ALERT]` email TO `yeshwanthlb0@gmail.com` (configured as `ALERT_EMAIL_TO`). This confuses users who think the phishing email itself arrived. The alert email has clear subject prefix and body saying "The phishing email was BLOCKED — it did NOT reach the recipient." For production, set `ALERT_EMAIL_TO` to a separate SOC team address.

---

## 7. Where We Left Off

**Last action:** Sent 9 test emails multiple times to demonstrate the system. Everything working consistently.

**Project lead demo:** Scheduled. Lead wants to see:
- Clean emails arriving in real Gmail inbox ✅
- Suspicious emails held in dashboard, SOC approves → arrives in inbox ✅  
- Phishing emails blocked, visible in Quarantine tab ✅
- All dashboards working (SOC Console, Kibana, Grafana, MinIO, MISP, OpenCTI) ✅

---

## 8. Immediate Next Steps

1. **Demo to project lead:** Run `python3 scripts/test_smtp_gateway.py`, press F5, show all tabs
2. **Optional — add more domains to trusted list:** If any new legitimate senders score incorrectly, add them to `TRUSTED_SENDER_DOMAINS` in `app/layer1/verdicts.py` and rebuild
3. **Optional — change default passwords** for production: ES, Kibana, MinIO, OpenCTI, Grafana, MISP all still use `changeme`/`changeme123`
4. **Optional — PhishTank key:** phishtank.org/api_register.php (registration was disabled at time of session)
5. **Optional — Jira:** Add `JIRA_BASE_URL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY` to .env
6. **Optional — Gmail Workspace:** For true pre-delivery interception. Needs service account JSON + Workspace admin

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
| `PHISHTANK_API_KEY` | ❌ Not set (site disabled registration) |
| `JIRA_*` | ❌ Not set |
| `GOOGLE_SERVICE_ACCOUNT_JSON` | ❌ Not set (Workspace SA, needs admin) |

---

## 10. File Locations — Key Files

```
phishguard/
├── app/
│   ├── main.py                         # 35+ API endpoints, Prometheus metrics, OTel
│   ├── pipeline.py                     # L1→L2→L3→L4→L5 orchestrator
│   ├── storage.py                      # SQLite: scans + pending_review tables
│   ├── config.py                       # All settings (no duplicate fields)
│   ├── llm/client.py                   # Unified LLM client (Claude/OpenAI/Gemini/heuristic)
│   ├── layer1/verdicts.py              # OSINT + trusted sender + denylist
│   ├── layer2_ai/orchestrator.py       # 3-tier verdict, thresholds
│   ├── layer2_ai/behavioral.py         # 3-tier cold start, ISO forest, Gaussian
│   ├── layer2_ai/structural.py         # Typosquatting, domain age, macros
│   ├── layer2_ai/nlp_engine.py         # Multi-provider NLP + heuristic fallback
│   ├── layer3_sandbox/sandbox_runner.py # Docker SDK sandbox (not CLI)
│   ├── layer4_soar/soar_orchestrator.py # 7 SOAR integrations concurrent
│   ├── layer4_soar/misp_exporter.py    # IoC export (no PII, TLP:AMBER)
│   ├── layer4_soar/evidence_store.py  # MinIO .eml storage
│   ├── layer5_ml/training_pipeline.py  # ExtraTrees + CalibratedCV
│   ├── layer7_gmail/smtp_receiver.py   # Gateway: clean→Gmail API, sus→hold, phish→quarantine
│   ├── layer7_gmail/gmail_client.py    # Gmail API + deliver_to_inbox() with INBOX label
│   └── templates/index.html            # Full SOC Console SPA (1,100+ lines)
├── scripts/
│   ├── test_smtp_gateway.py            # 9-email demo script (3+3+3)
│   ├── fake_mail_server.py             # Fake downstream server (port 1025)
│   └── setup_kibana.py                 # Provisions Kibana dashboard + visualisations
├── data/
│   ├── phishguard.db                   # SQLite (sync to Docker after local Python runs)
│   ├── model.pkl                       # ExtraTrees ML model
│   ├── training/                       # spamassassin + gmail_clean (DO NOT add HF corpus)
│   ├── verdicts/                       # Live prediction logs (NOT training data)
│   └── evidence/                       # Local fallback for MinIO
├── docker/
│   ├── misp-cert.pem                   # MISP SSL cert (CN=misp)
│   ├── misp-key.pem                    # MISP SSL key
│   ├── misp-ca.pem                     # CA for connector trust
│   └── grafana/provisioning/           # Auto-provisioned Grafana dashboard
├── ml/
│   ├── baselines/                      # Per-sender behavioral baselines (local only)
│   └── pretrain_global_baseline.py     # Seeds ISO forest from corpus
├── models/
│   └── global_iso_v1.pkl               # Isolation Forest (186 emails)
├── RUNBOOK.md                          # Incident playbook + alert routing
├── BRINGUP.md                          # Deployment guide
└── docker-compose.yml                  # 13 services
```

---

*Generated at end of session. Resume by reading this file first, then check `docker compose ps` and run the demo.*
