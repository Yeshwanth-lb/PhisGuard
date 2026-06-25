# PhishGuard — Complete Reconstruction Prompt

Use this prompt to rebuild PhishGuard from scratch, exactly as it exists now.
Paste it to an AI coding assistant and it will reproduce the full system.

---

## Master Prompt

Build **PhishGuard v1.5** — a production-grade, end-to-end email security gateway with 8-layer AI detection, a full SOC dashboard, and threat intelligence integration. Every design decision, architectural choice, and implementation detail is specified below.

---

## What to build

An email security gateway that:
1. Receives emails via SMTP on port 8025
2. Runs them through 8 detection layers (L0→L7)
3. Routes each email: clean → Gmail inbox, suspicious → SOC hold queue, phishing → quarantine
4. Exposes a full SOC Console web dashboard at port 8000
5. Integrates with Elasticsearch, Slack, MISP, OpenCTI, MLflow, MinIO, Grafana, Prometheus

---

## Tech stack (exact versions)

```
Python 3.12
FastAPI + uvicorn (2 workers)
aiosmtpd (SMTP gateway)
anthropic (Claude — primary NLP)
openai (fallback NLP)
scikit-learn (ExtraTreesClassifier + CalibratedClassifierCV)
structlog (JSON logging)
httpx (async HTTP)
docker Python SDK (sandbox)
sqlite3 (built-in — scans, pending_review, trusted_domains, feedback)
redis (L1 OSINT cache)
prometheus-fastapi-instrumentator (metrics)

Docker Compose services (13 total):
  app (FastAPI, port 8000 + 8025)
  elasticsearch:8.13.2 (port 9200)
  kibana:8.13.2 (port 5601)
  redis:7.2-alpine (port 6379)
  mlflow:v2.13.2 (port 5000)
  minio:RELEASE.2024-06-13T22-53-53Z (ports 9000, 9001)
  misp-core:latest (port 8888)
  mysql:8.0 (MISP database)
  opencti/platform:6.2.18 (port 8080)
  opencti/connector-misp:6.2.18
  rabbitmq:3.13-management (OpenCTI broker)
  prom/prometheus:v2.52.0 (port 9090)
  grafana/grafana:10.4.4 (port 3000)
```

---

## Project structure

```
phishguard/
├── app/
│   ├── main.py                          # FastAPI app, 35+ endpoints, lifespan
│   ├── pipeline.py                      # L0→L1→L2→L3→L4→L5 orchestrator
│   ├── storage.py                       # SQLite: 4 tables
│   ├── config.py                        # Pydantic settings from .env
│   ├── models.py                        # Pydantic request/response models
│   ├── layer0/pre_filter.py             # Trivial-clean fast-exit
│   ├── layer1/
│   │   ├── verdicts.py                  # OSINT aggregator + trusted sender
│   │   ├── osint_client.py              # VT, AbuseIPDB, URLhaus, MISP, Spamhaus
│   │   ├── osint_v2.py                  # PhishTank, GSB, WHOIS, SPF, DKIM, DMARC
│   │   └── cache.py                     # Redis sliding-window cache
│   ├── layer2_ai/
│   │   ├── orchestrator.py              # 3-engine parallel verdict
│   │   ├── nlp_engine.py                # Claude→OpenAI→Gemini→heuristic
│   │   ├── behavioral.py                # ISO Forest + per-sender GMM
│   │   ├── structural.py                # Typosquatting, domain age, macros
│   │   └── prompts/                     # NLP system prompts v1+v2
│   ├── layer3_sandbox/
│   │   ├── sandbox_runner.py            # Docker SDK + CLI fallback
│   │   ├── page_analyzer.py             # Credential forms, redirects
│   │   └── ocr_engine.py                # Tesseract screenshot analysis
│   ├── layer4_soar/
│   │   ├── soar_orchestrator.py         # 7 integrations concurrent
│   │   ├── campaign_detector.py         # Domain+intent clustering
│   │   ├── digest.py                    # Weekly Slack digest + scheduler
│   │   ├── es_exporter.py               # Elasticsearch
│   │   ├── slack_notifier.py            # Slack webhooks
│   │   ├── misp_exporter.py             # MISP IoC export (TLP:AMBER, no PII)
│   │   ├── opencti_exporter.py          # OpenCTI
│   │   ├── jira_exporter.py             # Jira (optional)
│   │   ├── email_alerter.py             # Gmail SMTP alerts
│   │   ├── evidence_store.py            # MinIO .eml storage
│   │   └── denylist.py                  # SQLite auto-block list
│   ├── layer5_ml/
│   │   ├── classifier.py                # Inference
│   │   ├── training_pipeline.py         # ExtraTrees + feedback loop
│   │   ├── feature_extractor.py         # 24 features
│   │   ├── retrain.py                   # Public retrain API
│   │   ├── bootstrap.py                 # Synthetic bootstrap
│   │   ├── mlflow_tracker.py            # MLflow logging
│   │   └── storage_exporter.py          # Verdict → training JSONL
│   ├── layer7_gmail/
│   │   ├── smtp_receiver.py             # aiosmtpd handler + routing
│   │   ├── gmail_client.py              # Gmail API inject + INBOX label
│   │   ├── historical_scanner.py        # OAuth inbox scan
│   │   └── pubsub_watcher.py            # Pub/Sub pull subscriber
│   ├── llm/client.py                    # Unified LLM: Claude/OpenAI/Gemini/heuristic
│   ├── security/
│   │   ├── auth.py                      # JWT HS256, token pairs
│   │   ├── rbac.py                      # admin/analyst/readonly
│   │   ├── rate_limiter.py              # HTTP rate limiter (120 req/min)
│   │   ├── smtp_rate_limiter.py         # SMTP bombing protection (4 counters)
│   │   ├── audit.py                     # Audit middleware + JSONL log
│   │   └── token_store.py               # Refresh token store
│   └── templates/index.html             # SOC Console SPA (~1,800 lines)
├── scripts/
│   ├── test_smtp_gateway.py             # Procedural 9-email demo generator
│   ├── send_eml.py                      # Pipe real .eml files through port 8025
│   └── fake_mail_server.py              # Fake downstream (port 1025)
├── tests/
│   ├── test_layer0.py                   # 12 tests
│   ├── test_layer1.py
│   ├── test_layer2.py
│   ├── test_layer3.py                   # 8 tests (Docker SDK mocks)
│   ├── test_layer4.py
│   ├── test_layer5.py
│   ├── test_layer6.py
│   ├── test_layer7.py
│   ├── test_campaigns.py                # 13 tests
│   ├── test_smtp_rate_limiter.py        # 17 tests
│   └── test_parser.py
├── ml/
│   ├── baselines/                       # Per-sender behavioral baselines (named volume)
│   └── pretrain_global_baseline.py
├── models/
│   └── global_iso_v1.pkl                # Global Isolation Forest (186 emails)
├── data/
│   ├── training/
│   │   ├── spamassassin_corpus.jsonl    # 5,772 emails
│   │   └── gmail_clean_corpus.jsonl     # 307 real clean emails
│   └── [runtime: phishguard.db, model.pkl, screenshots/, evidence/, verdicts/]
├── docker/
│   ├── misp-cert.pem / misp-key.pem / misp-ca.pem  # CN=misp (not localhost)
│   ├── grafana/provisioning/            # Auto-provisioned dashboard
│   ├── prometheus/prometheus.yml
│   └── sandbox/                         # Chromium sandbox image
├── docker-compose.yml                   # 13 services, 5 named volumes
├── Dockerfile                           # Multi-stage, user:root override
├── requirements.txt
├── SESSION_HANDOFF.md
├── PROJECT_CONTEXT.md
└── RUNBOOK.md
```

---

## Layer 0 — Trivial-Clean Pre-Filter

**File:** `app/layer0/pre_filter.py`

Fast-exit before OSINT and AI. ALL must pass:
- `spf_result == "pass"`
- `dkim_result == "pass"`
- `len(urls) == 0`
- `len(attachment_hashes) == 0`
- `len(body_text.strip()) <= 600`
- No urgency regex match in body or subject

Urgency regex catches: `urgent`, `verify your`, `account suspended/limited/blocked/compromised`, `click here`, `confirm your password`, `wire transfer`, `unusual sign-in`, `reset your password`, `act now`, `expires in N`, `last chance`, `final notice`, `action required`, `failure to act/respond`, `account will be`.

Returns `{"verdict":"clean","confidence":0.02,"fast_path":"layer0_trivial_clean","l0":{...}}` or `None`.

---

## Layer 1 — OSINT Pre-Filter

**File:** `app/layer1/verdicts.py`

Run 9 threat database checks concurrently via `asyncio.gather()`:

**Hard quarantine sources** (any hit → immediate block):
- VirusTotal — sender IP + each URL
- URLhaus — each URL
- PhishTank — each URL
- Google Safe Browsing — each URL
- MISP — sender IP
- Spamhaus — sender IP

**Aux sources** (soft signals, accumulate score):
- AbuseIPDB — sender IP (≥80% abuse confidence → quarantine, ≥50% → suspicious)
- WHOIS domain age — sender domain + URL domains (< 30 days → suspicious, score = max(20, 100-days×3))
- SPF/DKIM/DMARC DNS checks

**Trusted sender fast-exit:**
`TRUSTED_SENDER_DOMAINS` set (~70 domains including LinkedIn, Google, Microsoft, Apple, GitHub, Stripe, SBI, Indian e-commerce, etc.) plus user-added domains from SQLite `trusted_domains` table (60s cache). Check uses subdomain matching (`e.linkedin.com` matches `linkedin.com`).
- SPF=pass AND DKIM=pass → clean fast-exit (skip L2/L3/L5)
- SPF=fail OR DKIM=fail → suspicious (spoofing detected)
- SPF/DKIM=unknown → clean (missing Auth-Results header, common for Gmail API historical emails — treat as clean not fail)

**Internal denylist:** checked first, before OSINT API calls.

**Result:** `{"verdict":"quarantine"|"suspicious"|"clean","hits":[],"weak_hits":[],"detail_list":[]}`

---

## Layer 2 — AI Consensus

**File:** `app/layer2_ai/orchestrator.py`

Three engines run via `asyncio.gather()`. Single shared `LLMClient` per request.

**Thresholds:**
```python
SINGLE_ENGINE_THRESHOLD = 0.90   # Tier 1: any single engine → phishing
HIGH_CONF_THRESHOLD     = 0.70   # Tier 2: composite → phishing  
MED_CONF_THRESHOLD      = 0.42   # Tier 3: composite → suspicious
```

**Weights:** NLP=0.50, Structural=0.30, Behavioral=0.20

**Engine 1 — NLP Intent Analyst** (`nlp_engine.py`):
- Provider chain: Claude (primary, with prompt caching `cache_control: ephemeral`) → OpenAI → Gemini → heuristic
- LLM_PROVIDER=auto in .env — auto-detects from keys
- Returns: `{score, intent, tactics[], reasoning, provider, model}`
- Heuristic fallback: keyword scoring for urgency, credential harvesting, BEC, exec impersonation, brand names, suspicious links, PII requests — always available, no API key needed

**Engine 2 — Behavioral** (`behavioral.py`):
- 3-tier cold start based on email count from sender:
  - Tier 0 (0 emails): 0.60×context_score + 0.40×iso_score
  - Tier 1 (1-5): 0.50×context + 0.50×iso
  - Tier 2 (6-19): 0.40×iso + 0.60×simplified_gmm
  - Tier 3 (20+): per-sender GMM
- Global Isolation Forest at `models/global_iso_v1.pkl` (186 email vectors)
- Baselines stored as JSON in `ml/baselines/` (named Docker volume — persists across restarts)
- 8-feature vector: body_length, url_count, attachment_count, has_html, has_reply_to, auth_fail_rate, subject_len, has_return_path

**Engine 3 — Structural** (`structural.py`):
- Inline Levenshtein (no external dep) — typosquatting vs HIGH_VALUE_BRANDS set
- Unicode homoglyph map (Cyrillic/Greek chars → Latin equivalents)
- WHOIS domain age (cached 24h) — < 7 days = critical (score 0.90), < 30 days = high
- Reply-To domain mismatch vs From domain
- DMARC alignment check
- Macro-capable attachments: .docm, .xlsm, .pptm, .doc, .xls, .js, .vbs, .hta, .exe, .bat, .cmd, .ps1, .scr
- Double extension regex: `(pdf|doc|xls|png|jpg|txt)\.(exe|bat|cmd|vbs|js|ps1)$`
- Tracking pixels (1×1 img tags)
- Returns: `{score, findings[], red_flags[{flag, severity}], domain_age_days, auth_alignment, attachment_risk}`

**Unified LLM Client** (`app/llm/client.py`):
- Single interface: `await client.complete(system, user, max_tokens)`
- Claude uses `cache_control: {"type":"ephemeral"}` on system prompt — 90% cost reduction
- Property `is_ai_powered` — False when heuristic, True for real AI

---

## Layer 3 — Sandbox Detonation

**File:** `app/layer3_sandbox/sandbox_runner.py`

**Only fires when:** L2=suspicious AND urls present AND L2 confidence ≥ 0.45

**Implementation:**
- Python Docker SDK (`docker.DockerClient`, `containers.run()`) — not CLI (CLI absent in container)
- Docker socket mounted at `/var/run/docker.sock`
- App runs as root (`user: "0"` in docker-compose) so socket always accessible — no manual chmod
- Falls back to `asyncio.create_subprocess_exec` node CLI if SDK unavailable
- Container: `phishguard-sandbox:latest` — headless Chromium + puppeteer
- Security flags: `remove=True, cap_drop=["ALL"], security_opt=["no-new-privileges"], read_only=True, mem_limit="1g", pids_limit=256`
- Timeout: `SANDBOX_TIMEOUT_SECS=30`, asyncio.wait_for with `SANDBOX_TIMEOUT_SECS+5`
- Screenshots saved to `data/screenshots/<scan_id>.png`

**Page analyzer** (`page_analyzer.py`): credential form fields, redirect chains, malicious JS patterns.

**Important:** Tests mock `docker.DockerClient`, NOT `asyncio.create_subprocess_exec`. The `test_sandbox_no_docker_image_uses_node` test still mocks `create_subprocess_exec` because it tests the CLI fallback path (no `docker_image` arg). Maintain `_make_mock_proc` helper in test file.

---

## Layer 4 — SOAR

**File:** `app/layer4_soar/soar_orchestrator.py`

7 integrations fired via `asyncio.gather()`:

1. **Elasticsearch** — index verdict as daily rolling index `phishguard-verdicts-YYYY.MM.DD`
2. **Slack** — webhook notification for phishing/suspicious
3. **MISP** — export IoCs: sender domain, sender IP, malicious URLs as MISP event (TLP:AMBER, no email body/content, only technical IoCs)
4. **OpenCTI** — STIX2 threat intel
5. **Jira** — incident ticket (optional, needs JIRA_BASE_URL etc.)
6. **Email alert** — Gmail SMTP to `ALERT_EMAIL_TO`
7. **Denylist** — auto-add sender/domain/IP on L1 hard hits

**Evidence store** (`evidence_store.py`): MinIO bucket `phishguard-evidence`, path `YYYY/MM/DD/<uuid>/email.eml` + `report.json`. Falls back to `data/evidence/` if MinIO unreachable.

**MISP setup:**
- Self-signed cert for hostname `misp` (not `localhost`) — mounted at `docker/misp-cert.pem`
- API key: `keugWnClooY4yPB7vItEnfVikSRxUeUH5TY7DO7z` (in .env + docker-compose)
- connector-misp auto-syncs to OpenCTI

**Campaign Detector** (`campaign_detector.py`):
- Sliding window (default 7 days), min 3 emails = campaign
- Two cluster dimensions:
  1. Normalised sender domain: strip TLD + year/number suffix (`payment-hub-2026.com` → `payment-hub`)
  2. NLP intent: group emails with same attack type
- Intent campaigns exclude scan IDs already in domain campaigns (avoid double-count)
- Severity: critical (10+ or bec_fraud/executive_impersonation), high (5-9 or credential_harvesting), medium (3-4)
- Active flag: last seen within 24h
- API: `GET /api/campaigns?days=N`

**Weekly Digest** (`digest.py`):
- Slack Block Kit format: scan counts, top attacker addresses, top NLP intents, active campaigns
- Manual trigger: `POST /api/digest/send`
- Auto-scheduler: daemon thread, fires every Monday 09:00 local time (skips if no webhook)

---

## Layer 5 — ML Classifier

**File:** `app/layer5_ml/training_pipeline.py`

**Algorithm:** `ExtraTreesClassifier(n_estimators=300, class_weight='balanced', n_jobs=-1)` wrapped in `CalibratedClassifierCV(method='isotonic', cv=min(5, n_pos, n_neg))`

**24 features:**
```python
FEATURE_KEYS = [
    "url_count", "has_http_url", "has_ip_url",
    "l1_hit_count", "structural_score", "nlp_score",
    "behavioral_score", "l2_confidence", "urgent_word_count",
    "brand_spoof_count", "subject_len", "spf_fail",
    "dkim_fail", "attachment_count",
    "body_length", "html_only", "distinct_url_domains",
    "shortener_url_count", "body_brand_count", "reply_to_mismatch",
    "subject_uppercase_ratio", "subject_exclamation_count",
    "subject_non_ascii_count", "anchor_text_href_mismatch",
]
```

**Blending:** `final = 0.60 × L2_composite + 0.40 × ML_score`

**Floor protection (critical):** ML cannot downgrade L2's verdict:
- L2=suspicious → final floor at 0.43
- L2=phishing → final floor at 0.65
Reason: model trained on 2006 SpamAssassin, doesn't know BEC patterns.

**Training corpus assembly** (`_assemble_corpus`):
1. `_load_feedback_records()` — reads `feedback` SQLite table, uses `corrected_verdict` as label, excludes original scan from DB load (latest correction wins if multiple)
2. `_load_jsonl_records()` — SpamAssassin + Gmail clean JSONL
3. `_load_db_records(exclude_scan_ids)` — live scans from SQLite minus corrected ones
4. Deduplicate by SHA1(features+label)

**DO NOT** use `data/training/huggingface_phishing_corpus.jsonl` — degrades F1 from 0.89→0.62 (no pipeline feature scores).

**MLflow:** logs metrics, confusion matrix, feature importances per retrain.

---

## Layer 6 — Security

**Files:** `app/security/`

- **JWT:** HS256, access+refresh token pair, 30min/7day TTL
- **RBAC:** admin > analyst > readonly, permission decorators (`require_permission("scan")` etc.)
- **HTTP rate limiter:** 120 req/min per IP, sliding window, 429 on exceed
- **Audit middleware:** every request logged to `data/audit.jsonl` with request_id, IP, method, path, status, latency
- **Input sanitiser:** on email text before pipeline

**SMTP Rate Limiter** (`smtp_rate_limiter.py`) — email bombing protection:
```
Per-IP:        10 emails/60s    — stops single-source flooding
Per-domain:    20 emails/3600s  — stops domain campaigns  
Per-recipient: 30 emails/60s    — stops distributed bombing (rotating IPs/domains)
Global:        60 emails/60s    — total throughput cap
Burst:         5/10s → Slack alert (suppressed 5min per source)
Tarpit:        sleep 2s before 421 — slows automated tools
```
Returns SMTP 421 (temporary failure) — MTA retries, no legitimate email permanently lost.

**Privacy:** `GET /api/scan/{id}` strips `body_text`, `body_html`, `body_plain` server-side. `body_preview` removed from list endpoint. Email body content never accessible via API.

---

## Layer 7 — Email Ingestion

**File:** `app/layer7_gmail/smtp_receiver.py`

**SMTP routing (uses L2 verdict, NOT blended final):**
- `clean` → `deliver_to_inbox()` via Gmail API → `users.messages.import_()` + explicit `addLabelIds: ["INBOX", label_id]`
- `suspicious` → `storage.save_pending_review()` — NOT delivered, held for SOC
- `phishing` → relay with RCPT rewritten to quarantine address + subject tagged

**Why L2 not blended:** ML floor can push suspicious→phishing, bypassing SOC review. Use L2 verdict for routing so all L2-suspicious emails go to Pending Review.

**Gmail API delivery:** must call `import_()` then explicitly add INBOX label. Without INBOX label, emails go to All Mail but don't appear in inbox.

**Credentials:** mounted `:rw` (not `:ro`) so OAuth token can refresh.

---

## SQLite Schema (4 tables)

```sql
scans (
    id TEXT PRIMARY KEY,
    ts REAL, verdict TEXT, confidence REAL, blocked_at TEXT,
    sender TEXT, subject TEXT, body_preview TEXT,
    data_json TEXT,  -- full result dict, body fields stripped before returning via API
    released INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0
)

pending_review (
    id TEXT PRIMARY KEY, scan_id TEXT, ts REAL,
    verdict TEXT, confidence REAL, sender TEXT, subject TEXT,
    original_rcpt TEXT, raw_email BLOB,
    status TEXT DEFAULT 'pending',  -- pending/approved/rejected
    reviewed_by TEXT, reviewed_at REAL
)

trusted_domains (
    domain TEXT PRIMARY KEY, added_at REAL,
    added_by TEXT, note TEXT
)

feedback (
    id TEXT PRIMARY KEY, scan_id TEXT NOT NULL,
    original_verdict TEXT, corrected_verdict TEXT,
    notes TEXT, submitted_at REAL, submitted_by TEXT
)
```

---

## Pipeline flow (`app/pipeline.py`)

```python
async def analyze_email(raw_eml, settings):
    parsed = parse_email(raw_eml)
    urls = await resolve_shortened_urls(extract_urls(...))
    spf, dkim, dmarc = parsed.get("spf_result"), ...

    # L0: trivial clean check
    l0 = run_layer0(parsed, urls, spf, dkim)
    if l0: return await _post_actions(l0, settings, raw_eml)

    # L1: OSINT
    l1 = await run_layer1(sender_ip, urls, att_hashes, ..., spf, dkim, dmarc)
    if l1["verdict"] == "quarantine":
        return await _post_actions({"verdict":"phishing","blocked_at":"layer1",...})
    if l1.get("trusted_sender"):
        return await _post_actions({"verdict":"clean","confidence":0.02,...})

    # L2: AI consensus
    l2 = await run_layer2(parsed, settings)
    if l2["verdict"] == "phishing":
        return await _post_actions({"verdict":"phishing","blocked_at":"layer2",...})

    # L3: sandbox (only if L2=suspicious AND urls AND confidence≥0.45)
    l3 = await run_layer3(urls, settings) if sb_conditions else None
    if l3 and l3["verdict"] == "phishing":
        return await _post_actions({"blocked_at":"layer3",...})

    # L5: ML blend
    l5 = predict(verdict_doc, model_path)
    blended = 0.60 * l2_conf + 0.40 * l5_score
    # Apply floors
    if l2_verdict == "phishing": blended = max(blended, 0.65)
    if l2_verdict == "suspicious": blended = max(blended, 0.43)
    # Final verdict from blended score
    final_verdict = "phishing" if blended >= 0.65 else "suspicious" if blended >= 0.40 else "clean"

    # L4 + evidence + training record (async, always fires)
    return await _post_actions({...}, settings, raw_eml)
```

---

## Docker Compose key decisions

- `user: "0"` on app service — runs as root so Docker socket always accessible for sandbox
- Named volumes: `app_data`, `ml_baselines`, `es_data`, `mlflow_data`, `minio_data`
- `ml_baselines` must be a named volume (not bind mount) so behavioral baselines survive restarts
- MISP cert mounted as `:ro`, credentials as `:rw`
- OpenCTI `APP__ADMIN__TOKEN` must be valid UUID v4
- ES single-node: `discovery.type=single-node`, `xpack.security.enabled=true`

---

## SOC Dashboard (`app/templates/index.html`)

Single Page Application, ~1,800 lines. Dark theme (#0a0d14 bg, #141925 cards).

**9 Nav tabs:** Overview, Scan, Quarantine, Reports, Pending Review, ML Ops, Campaigns, SOAR, Audit Log, Gmail, Settings

**Key behaviours:**
- 5-second polling interval (`setInterval`) refreshes stats + pending badge + campaign badge
- Polling calls `Promise.all([pending, stats, campaigns])` for efficiency
- Analysis panels in Pending Review survive re-render: save open panel HTML → re-render list → restore open panels

**Pending Review tab:**
- `📊 View Analysis` — inline forensic breakdown: auth badges, L1 checks, L2 score bars with threshold markers at 0.42/0.70/0.90, threshold decision matrix (`▲ EXCEEDED / ▽ not reached` per tier), NLP intent+tactics+reasoning, structural red flags (critical/high/medium), behavioral tier, ML score
- `✅ Approve` → delivers to Gmail via `POST /api/pending/{id}/approve`
- `🔒 Reject` → quarantines via `POST /api/pending/{id}/reject`

**Reports tab:**
- Visual scan report (`renderScanReport`) replaces raw JSON dump
- Components: verdict banner, metadata+auth, L1 stat boxes, L2 score bars+threshold matrix, NLP card, structural red flags cards, behavioral stats, sandbox screenshot, ML stat boxes, SOAR chips
- `📄 Export PDF` → `buildPrintHTML(scan)` opens clean light-themed print window, auto-triggers print
- Search/filter by sender + verdict dropdown (client-side on loaded data)
- `Mark Wrong` → `POST /api/scan/{id}/feedback` → saved to `feedback` table

**Campaigns tab:**
- `loadCampaigns()` calls `GET /api/campaigns?days=N`
- Severity-coloured cards (red/orange/yellow)
- `View N Scans in Reports →` — fetch scans, filter by scan IDs, manually switch tab WITHOUT calling `showSection('reports')` (which would trigger `loadReports()` and race-overwrite `_allReportItems`)
- Uses `data-scan-ids='...'` attribute (single-quoted) + `JSON.parse(this.dataset.scanIds)` in onclick — NOT inline `${JSON.stringify(ids)}` (breaks HTML double-quote attribute)

**Settings tab:**
- Trusted Sender Domains card — CRUD via `/api/trusted-domains` endpoints
- Built-ins collapsed in `<details>`, user-added with Remove button

---

## Demo Script (`scripts/test_smtp_gateway.py`)

Procedural generator — unique emails every run:

**Clean (5 tactics):** meeting invite, deployment notice, resolved infra alert, HR event, maintenance notice

**Suspicious (7 tactics):** account verify, backup notification, billing notice, subscription renewal, IT password expiry, survey, reward points
- All use randomised service names, year-suffixed domains (`{service}-{2024-2027}.{com/net/io/org/biz}`)

**Phishing (6 tactics):** brand typosquat (8 brands × multiple variants), BEC wire fraud, credential harvest, IRS refund, IT helpdesk deactivation, payroll bank update
- Randomised amounts, bank names, exec titles, urgency hours, portal domains

`--seed N` for reproducibility, `--count N` for emails per category (default 3).

---

## Key gotchas and decisions

1. **Threshold at 0.70 not 0.62** — domain-age signals alone push borderline emails over 0.62; raised to 0.70 to keep them in Pending Review

2. **L2 verdict for SMTP routing** — ML floor can push L2-suspicious to blended-phishing; use L2 verdict for routing so all L2-suspicious go to SOC queue

3. **Trusted sender auth=unknown = clean** — Gmail API historical emails lack Authentication-Results header; treat unknown as clean (not fail) to avoid blocking all historical emails

4. **HuggingFace corpus destroys F1** — emails have no pipeline feature scores (all zeros for nlp_score, structural_score etc.), model can't distinguish; NEVER use it

5. **Docker socket needs root** — app runs as `user: "0"` in docker-compose. Removing this breaks L3 sandbox on every restart

6. **MISP cert is for hostname `misp`** — do not restart MISP without cert files mounted, reverts to localhost cert

7. **Behavioral baselines need named volume** — `ml/baselines/` must be mounted as named volume `phishguard_ml_baselines` else baselines reset on restart

8. **viewCampaignScans race condition** — must fetch scan data FIRST, then manually switch tab (without calling `showSection('reports')` which triggers `loadReports()` async race)

9. **onclick with JSON** — never use `onclick="fn(${JSON.stringify(array)})"` — double quotes in JSON break HTML attribute. Use `data-` attribute with single quotes

10. **_make_mock_proc in tests** — `test_sandbox_no_docker_image_uses_node` tests CLI fallback path and needs this helper even though the 3 Docker SDK tests don't; keep it

11. **Per-recipient rate limit** — most critical for real email bombing tools that use rotating IPs/domains; only the recipient counter catches distributed attacks

12. **Tarpit before 421** — `await asyncio.sleep(TARPIT_SECS)` in smtp_receiver before returning 421; slows automated tools

---

## API endpoints

```
GET  /health                              # system health + smtp_rate_limiter stats
POST /token                               # get JWT (api_key + role)
POST /api/auth/refresh                    # refresh token exchange
GET  /api/auth/whoami
DELETE /api/auth/revoke
POST /analyze                             # manual email scan
GET  /api/scans?limit&offset&verdict&hours
GET  /api/scan/{id}                       # stripped of body fields
GET  /api/scan/{id}/screenshot
POST /api/scan/{id}/release
DELETE /api/scan/{id}
POST /api/scan/{id}/feedback              # mark wrong → feedback table
GET  /api/stats?hours
GET  /api/quarantine
GET  /api/pending                         # list pending_review (status=pending)
POST /api/pending/{id}/approve
POST /api/pending/{id}/reject
GET  /api/campaigns?days
POST /api/digest/send                     # manual weekly digest trigger
GET  /api/denylist?kind&only_active&limit
POST /api/denylist
DELETE /api/denylist/{id}
GET  /api/trusted-domains
POST /api/trusted-domains
DELETE /api/trusted-domains/{domain}
GET  /api/soar/status
GET  /api/ml/status
POST /api/ml/retrain
POST /api/ml/bootstrap
GET  /api/audit/logs?limit
GET  /api/gmail/status
POST /api/gmail/watch
POST /api/gmail/stop
POST /api/gmail/scan
GET  /api/settings
PATCH /api/settings
GET  /metrics                             # Prometheus (no auth)
```

---

## Environment variables (.env)

```
JWT_SECRET=<32-byte hex>
API_KEY=dev-key

# NLP
ANTHROPIC_API_KEY=sk-ant-...
LLM_PROVIDER=auto               # auto|claude|openai|gemini|heuristic
LLM_MODEL=                      # optional override
ANTHROPIC_MAX_TOKENS=1024

# OSINT
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
PHISHTANK_API_KEY=              # optional
MISP_API_KEY=keugWnClooY4yPB7vItEnfVikSRxUeUH5TY7DO7z
MISP_URL=https://misp

# SOAR
SLACK_WEBHOOK_URL=
JIRA_BASE_URL=                  # optional
JIRA_API_TOKEN=                 # optional
JIRA_PROJECT_KEY=               # optional
ALERT_EMAIL_TO=yeshwanthlb0@gmail.com
ALERT_SMTP_HOST=smtp.gmail.com
ALERT_SMTP_PORT=587
ALERT_SMTP_USER=yeshwanthlb0@gmail.com
ALERT_SMTP_PASSWORD=<app_password>

# Gmail
GMAIL_OAUTH_TOKEN_FILE=credentials/gmail_oauth_token.json
GMAIL_QUARANTINE_ADDRESS=quarantine@phishguard.local
GMAIL_QUARANTINE_LABEL=PhishGuard-Quarantine
GMAIL_SCANNED_LABEL=PhishGuard-Scanned
SMTP_LISTEN_HOST=0.0.0.0
SMTP_LISTEN_PORT=8025
SMTP_RELAY_HOST=localhost
SMTP_RELAY_PORT=1025

# ML
ML_MODEL_PATH=data/model.pkl
ML_LOCAL_DATA_DIR=data/training
ML_VERDICT_LOG_DIR=data/verdicts
ML_BOOTSTRAP_ON_STARTUP=true

# Storage
PHISHGUARD_DB_PATH=data/phishguard.db
```

---

## What NOT to do

- Do NOT use `allow_origins=['*']` in production — lock to specific domain
- Do NOT change default passwords (`changeme`, `changeme123`) without updating all configs
- Do NOT add HuggingFace phishing corpus to training data
- Do NOT remove `user: "0"` from app service in docker-compose — breaks sandbox
- Do NOT use inline `JSON.stringify` in onclick attributes — use `data-` attributes
- Do NOT call `showSection('reports')` from `viewCampaignScans` — causes race condition
- Do NOT remove `_make_mock_proc` from test_layer3.py — needed by CLI fallback test
- Do NOT treat DKIM/SPF=unknown as fail for trusted domains — breaks historical Gmail scanner
- Do NOT restart MISP without cert files mounted — reverts SSL cert to localhost

---

## Session 6 additions (2026-06-23)

**MISP web UI fix:**
Two custom nginx configs mounted into the MISP container:
- `docker/misp-nginx-http.conf` → `/etc/nginx/sites-enabled/misp80` — redirects `http://localhost:8888` to `https://localhost:8443` (hardcoded port, not `$host` which strips port)
- `docker/misp-nginx-https.conf` → `/etc/nginx/sites-enabled/misp443` — serves HTTPS without HSTS header (HSTS on localhost breaks other local services)

MISP ports in docker-compose: `8888:80` + `8443:443`. Access via `http://localhost:8888` → browser redirects to `https://localhost:8443` → accept SSL cert warning → login `admin@admin.test` / `changeme123`.

MISP admin password was reset via PHP bcrypt: `docker exec phishguard-misp php -r "echo password_hash('changeme123', PASSWORD_BCRYPT, ['cost'=>12]);"` then UPDATE in MySQL.

connector-misp `MISP_URL` changed from `https://misp` to `http://misp` — port 443 wasn't ready at container startup time, port 80 always is.

**Grafana dashboard fixed:**
`docker/grafana/provisioning/dashboards/phishguard.json` had wrong metric names:
- `http_request_duration_seconds_bucket` → `http_request_duration_highr_seconds_bucket`
- `status_code=~"5.."` → `status="5xx"` (label name mismatch)
- `http_requests_in_progress` → `sum(rate(http_requests_total[30s]))` (metric doesn't exist)
- Datasource UID `PBFA97CFB590B2093` wired into all 8 panels

**Known issues (not fixed):**
- connector-misp v6.2.18 incompatible with MISP 2.5.40 API (GET vs POST on /events/restSearch) → OpenCTI has 0 objects
- MISP web UI: internal nginx redirects strip port (nav links go to `https://localhost/` not `https://localhost:8443/`) — workaround: manually type `https://localhost:8443/events/index`

**SMTP rate limiter demo override:**
`.env` has `SMTP_RATE_PER_IP=200` and `SMTP_RATE_GLOBAL=200` for the email bombing demo (prevents per-IP limit from firing before bombing detector). Revert these for production.

*This prompt fully specifies PhishGuard v1.5 as it exists after sessions 1-6 (2026-06-21 to 2026-06-23).*

---

# Session 7 (2026-06-24/25) — ThreatLens: Layer 8 Threat Intelligence & Adversary Profiling

PhishGuard v1.5 → v1.6. A new offline, read-only, cadence-driven intelligence
layer (`app/threatlens/`) that consumes the `scans` table, clusters scans into
candidate adversaries, enriches each cluster via 11 parallel agents, maps to
MITRE ATT&CK + the Skylo NTN attack surface, and synthesizes structured
`AdversaryProfile` records surfaced in a new Profiling dashboard tab.

Behind `INTEL_ENABLED` (default false). Never touches the email-delivery path.

## Module layout — `app/threatlens/`
```
config.py            # ThreatLensSettings — all env vars + API keys
models.py            # IoCSet, ActorCluster, Finding, TTP, CorroboratedClaim,
                     #   AdversaryProfile, OrgThreatAssessment, TTPObservation, Rollup
store.py             # SQLite DAO — 5 tables + profile_feedback
actor_clusterer.py   # scans → candidate clusters (composite signature, stable hash id)
fusion_engine.py     # deterministic confidence math (Python, NOT the LLM)
profiler.py          # Claude synthesis → AdversaryProfile + feedback application
org_assessor.py      # leadership-facing OrgThreatAssessment (Skylo-contextualized)
ttp_mapper.py        # ATT&CK dedup + Skylo surface-zone keyword mapping
sector_rollup.py     # sector / org-team / network-surface aggregations
scheduler.py         # daemon-thread cadence runner (daily, overlap-guarded)
orchestrator.py      # run_cycle: dirty clusters → agents → fusion → profile → neo4j → slack
neo4j_writer.py      # pushes cluster graph to Neo4j after each cycle
slack_notifier.py    # smart escalation alerts (critical surface / confirmed / high-sev)
agents/
  base_agent.py      # timeout + isolation + TTL cache + not_configured + sanitize_text
  registry.py        # pluggable agent registry
  osint_report_agent.py    attack_mapper_agent.py    misp_opencti_agent.py
  ioc_reputation_agent.py  cve_agent.py              compromise_intel_agent.py
  telecom_ntn_agent.py     network_intel_agent.py    greynoise_agent.py
  urlscan_agent.py         darkweb_agent.py
scraper/
  fetcher.py         # THE chokepoint — allowlist + robots + rate-limit + honest UA
  crawl4ai_client.py scrapling_client.py text_extract.py feeds_client.py discovery.py
  allowlist.yaml     # 43 approved OSINT domains
data/
  attack_techniques.json   attack_surface.yaml   # Skylo NTN surface zones
```

## The 11 agents (all run in parallel via asyncio.gather per cluster)
1. OSINT Report — CISA/Unit42/SANS via Crawl4AI → Claude extraction
2. ATT&CK Mapper — local MITRE JSON, intent → technique IDs (no network)
3. MISP/OpenCTI — queries existing MISP; **only path to `confirmed` confidence**
4. IoC Reputation — abuse.ch (URLhaus/ThreatFox) + AlienVault OTX + Pulsedive
5. CVE — NVD + CISA KEV + EPSS, filtered to NTN/5G/telecom/cloud
6. Compromise Intel — ransomware.live + RansomLook + HIBP (signals only, no PII)
7. Telecom/NTN — NCSC UK + SANS ISC (Skylo-specific)
8. Network Intel — Shodan InternetDB + BGPView (NO KEY, always on)
9. GreyNoise — noise-vs-targeted IP classification (free key)
10. URLScan — community URL scan verdicts (free key)
11. Dark Web — IntelligenceX + CIRCL PassiveDNS + LeakIX (clearnet only, no Tor)

## Fusion confidence rules (deterministic Python, tested)
- agent=='misp' hard match → `confirmed` (ONLY path)
- ≥2 independent root domains → `high`
- 1 source → `moderate`
- internal-only → `low`
- nothing → `speculative`
The profiler can LOWER but never RAISE the fusion-assigned ceiling.

## SQLite tables added (all `CREATE TABLE IF NOT EXISTS`, init in main.py lifespan)
actor_clusters (+ last_profiled_at), actor_profiles, intel_sources,
ttp_observations, org_threat_assessment, profile_feedback (+ cluster_id)

## API endpoints
```
POST /api/intel/run                    GET /api/intel/profiles[/{id}]
GET  /api/intel/clusters               GET /api/intel/rollup/sectors|org|network
GET  /api/intel/assessment             POST /api/intel/assessment/export
POST /api/intel/profiles/{id}/export   POST /api/intel/profiles/{id}/feedback
GET  /api/intel/graph                  POST /api/intel/graph/sync
GET  /api/intel/status
```

## Dashboard — Profiling tab
Stats bar · filter chips · Strategic Assessment banner · 3 rollup panels ·
Neo4j relationship graph (Neovis.js + Cypher bar) · ranked profile cards with
3-tab evidence panel (Intelligence Sources per-agent / ATT&CK & Surface / Profile Info).
Gotchas preserved: data-* onclick, panel survives 5s re-render.

## Phase 5 hardening
- Dirty-flag skip: only clusters with `updated_at > last_profiled_at` re-profiled
- Provenance: every finding with a source URL logged to intel_sources
- Retention: prune_old_intel_sources(90d); bounded concurrency semaphore

## Feedback loop (Option D)
"Mark Incorrect" → saved against cluster_id (survives re-profiling) → next cycle
lowers confidence ceiling one tier + injects analyst note into Claude prompt.

## Smart Slack alerts (Option C)
Fires on: critical surface (ground_station_ingress/ntn_5g_core) · confirmed
match · high-severity on gcp_infra/supply_chain. Block Kit cards. corporate_it
alone does NOT alert (too common).

## Infrastructure changes
- docker-compose: +opencti-worker, +neo4j (5.20-community, ports 7474/7687)
- Dockerfile: separate pip step for crawl4ai/scrapling/trafilatura (|| true)
- requirements-threatlens.txt: heavy scraper deps (avoid version conflicts)
- MISP fixes: BASE_URL=https://localhost:8443 (not MISP_BASEURL), misp-nginx-php.conf
  with `fastcgi_param HTTPS on`, misp_exporter publishes events on creation
- MISP→OpenCTI sync working: 306 events → 213 OpenCTI objects, 80 reports

## API keys (.env)
Active: ANTHROPIC, VIRUSTOTAL, ABUSEIPDB, GOOGLE_SAFE_BROWSING, GEMINI, SLACK,
MISP, ABUSECH_AUTH, OTX, PULSEDIVE, GREYNOISE, URLSCAN, INTELX, LEAKIX.
INTEL_ENABLED=true.

## Tests
~107 ThreatLens tests across: store, clusterer, scraper_guard, agents, fusion,
profiler, feeds, ttp_mapper, rollup, org_assessor, scheduler, api, hardening,
slack, feedback. Plus the original 186. All green.

*Session 7 specifies ThreatLens (Layer 8) as built 2026-06-24/25. Branch: feature/threatlens.*
