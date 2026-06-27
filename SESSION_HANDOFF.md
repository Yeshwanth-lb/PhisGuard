# PhishGuard — Session Handoff Document
**Last updated:** 2026-06-24 (session 7 — continued)  
**Project root:** `/Users/intern4/Desktop/phishguard`  
**Developer:** Yeshwanth (yeshwanthlb0@gmail.com)  
**Purpose:** End-to-end email security gateway with 8-layer AI detection + ThreatLens threat intelligence layer

---

## 1. Current System State

### Tests
- **165+ passing, 3 skipped, 0 failing**
- Run with: `python3 -m pytest tests/ -q --ignore=tests/locustfile.py --ignore=tests/test_layer4_smtp_live.py --ignore=tests/test_layer2_claude_live.py`
- 3 skipped: live Slack tests (no webhook in env)
- ThreatLens tests: `test_threatlens_store`, `test_threatlens_clusterer`, `test_threatlens_scraper_guard`, `test_threatlens_agents`, `test_threatlens_fusion`, `test_threatlens_profiler`, `test_threatlens_feeds`, `test_threatlens_ttp_mapper`, `test_threatlens_rollup`, `test_threatlens_org_assessor`, `test_threatlens_scheduler`, `test_threatlens_api`, `test_threatlens_hardening`

### Git Status
- Branch: `feature/threatlens` — all changes committed, working tree clean
- Main branch `master` untouched — merge when ready
- Latest commits:
  - `53ace44` fix: include crawl4ai/scrapling/trafilatura in Docker image
  - `f18a586` feat: ThreatLens Phase 5 — hardening, dirty flag, provenance, retention
  - `4d2dc19` fix: MISP baseurl permanently correct on every container restart
  - `b5e0349` fix: permanent fixes for MISP/OpenCTI/Docker stability
  - `54bdbe8` fix: MISP→OpenCTI sync now fully working
  - `af146b2` feat: ThreatLens Phase 4 — rollups, org assessor, scheduler, full dashboard
  - `4922545` feat: ThreatLens Phase 3 — full agent fleet, scraper routing, TTP mapper

### Database State (as of 2026-06-24)
- **Total scans stored:** 1,445+
- **Phishing:** 189 | **Suspicious:** 244 | **Clean:** 1,041
- SQLite at `data/phishguard.db` (Docker volume: `phishguard_app_data`)
- **9 tables** now: `scans`, `pending_review`, `trusted_domains`, `feedback`, `actor_clusters`, `actor_profiles`, `intel_sources`, `ttp_observations`, `org_threat_assessment`
- **IMPORTANT:** Local `data/phishguard.db` and Docker volume DB can drift. Fix:
  ```bash
  docker cp phishguard-app:/app/data/phishguard.db data/phishguard.db
  ```

### ThreatLens State (as of 2026-06-24 session 7)
- **Active clusters:** 126 (grouped from 1,445 scans)
- **Profiles generated:** 126 (first full cycle completed with confirmed confidence)
- **TTP observations:** 132
- **INTEL_ENABLED:** `true` — live and running
- **Cycle cadence:** daily (scheduler running as daemon thread)

### ML Model
- Algorithm: `ExtraTreesClassifier` (300 trees, class_weight='balanced')
- Wrapped in: `CalibratedClassifierCV` (isotonic, 3-fold)
- F1: **0.894** | ROC-AUC: **0.974**
- Saved at: `data/model.pkl` (1.3 MB)

---

## 2. Architecture — PhishGuard L0–L7

### Layer 0–7 (unchanged from session 6)
See session 6 handoff for full L0–L7 documentation. No changes to the core pipeline.

### Key thresholds:
- L2: Tier 1 ≥ 0.90 (phishing) | Tier 2 ≥ 0.70 (phishing) | Tier 3 ≥ 0.42 (suspicious)
- SMTP rate limits: per-IP=200, global=200 (demo mode — revert to 10/60 for production)

---

## 3. ThreatLens — Threat Intelligence Layer (NEW in session 7)

**Module:** `app/threatlens/`  
**Status:** All 5 phases complete and live  
**Flag:** `INTEL_ENABLED=true` in `.env`

### Architecture
```
Scans table → Actor Clusterer → 10 parallel agents → Fusion Engine → Claude Profiler → Dashboard
```

### Five phases built
| Phase | What | Status |
|---|---|---|
| 1 — Foundation | Actor clustering from scan data | ✅ Done |
| 2 — Vertical slice | Scraper chokepoint + 2 agents + fusion + profiler | ✅ Done |
| 3 — Breadth | Full 10-agent fleet + TTP mapper + Skylo surface zones | ✅ Done |
| 4 — Product | Rollups + org assessor + scheduler + full Profiling tab | ✅ Done |
| 5 — Hardening | Dirty-flag skip + provenance + retention + cost guardrails | ✅ Done |

### The 10 agents
| Agent | Source | Key needed |
|---|---|---|
| OSINT Report | CISA, Unit42, SANS (via Crawl4AI) | None |
| ATT&CK Mapper | Local MITRE JSON | None |
| MISP/OpenCTI | Existing MISP integration | Already configured |
| IoC Reputation | abuse.ch + AlienVault OTX + Pulsedive | ✅ Set |
| CVE/Vuln | NVD + CISA KEV + EPSS | None |
| Compromise Intel | ransomware.live + RansomLook + HIBP | None |
| Telecom/NTN | NCSC UK + SANS ISC (Skylo-specific) | None |
| Network Intel | Shodan InternetDB + BGPView | None |
| GreyNoise | IP noise vs targeted classification | ❌ Not set (dormant) |
| URLScan | Community URL scan verdicts | ❌ Not set (dormant) |

### Confidence model
- `confirmed` — ONLY via MISP hard IoC match
- `high` — 2+ independent OSINT sources agree
- `moderate` — 1 credible source
- `low/speculative` — weak or internal-only evidence

### Dirty-flag (Phase 5)
- Clusters only re-profiled when `updated_at > last_profiled_at`
- Unchanged clusters skipped → 0 LLM calls for clean clusters
- `clusters_skipped` and `llm_calls` in every cycle summary

### Key files
```
app/threatlens/
├── config.py              # ThreatLensSettings (all env vars)
├── models.py              # All Pydantic models
├── store.py               # SQLite DAO (9 tables)
├── actor_clusterer.py     # Incremental clustering
├── fusion_engine.py       # Deterministic confidence math
├── profiler.py            # Claude synthesis + fallback
├── ttp_mapper.py          # ATT&CK + Skylo surface zones
├── sector_rollup.py       # 3 aggregation views
├── org_assessor.py        # Leadership-facing strategic assessment
├── orchestrator.py        # Cycle runner (dirty flag + provenance)
├── scheduler.py           # Daemon thread (daily/hourly/on_campaign)
├── agents/                # 10 agent files
├── scraper/               # fetcher.py chokepoint + crawl4ai + scrapling + trafilatura
└── data/                  # attack_techniques.json, attack_surface.yaml
```

### API endpoints added
```
POST /api/intel/run                    # trigger cycle (admin)
GET  /api/intel/profiles               # list profiles
GET  /api/intel/profiles/{id}          # full profile + evidence
GET  /api/intel/clusters               # cluster list
GET  /api/intel/rollup/sectors|org|network
GET  /api/intel/assessment             # org-level brief
POST /api/intel/assessment/export      # PDF leadership brief
POST /api/intel/profiles/{id}/export   # MISP export
POST /api/intel/profiles/{id}/feedback # analyst rating
GET  /api/intel/status
```

---

## 4. Running Services and Ports

| Service | URL | Login | Notes |
|---|---|---|---|
| **PhishGuard SOC Console** | `localhost:8000` | `dev-key` (any role) | ✅ Profiling tab live |
| **Elasticsearch** | `localhost:9200` | `elastic / changeme` | ✅ Working |
| **Kibana** | `localhost:5601` | `elastic / changeme` | ✅ Working |
| **MLflow** | `localhost:5000` | none | ✅ Working |
| **MinIO UI** | `localhost:9001` | `phishguard / changeme123` | ✅ Working |
| **MISP** | `https://localhost:8443/users/login` | `admin@admin.test / changeme123` | ✅ **FIXED** — 306 events, all published |
| **OpenCTI** | `localhost:8080` | `admin@phishguard.local / changeme123` | ✅ **FIXED** — 213 objects, 80 reports |
| **Grafana** | `localhost:3000` | `admin / changeme` | ✅ Working |
| **Prometheus** | `localhost:9090` | none | ✅ Working |
| **Redis** | `localhost:6379` | password: `redispassword` | ✅ Working |
| **SMTP Gateway** | `localhost:8025` | none | ✅ Working |

**14 containers total** (was 13 — added `opencti-worker`)

### Docker Commands
```bash
docker compose up -d                   # start all 14 services
docker compose ps                      # check status
docker compose build app               # rebuild after code changes
docker compose up -d --no-deps app     # restart app only
```

---

## 5. Demo Numbers (as of 2026-06-24 session 7)

| Metric | Value |
|---|---|
| Total emails scanned | 1,445+ |
| Phishing blocked | 189 |
| Suspicious held for SOC | 244 |
| Clean delivered | 1,041 |
| Tests passing | 165+ / (3 skipped) |
| Running containers | 14/14 |
| MISP threat events | 306 (all published) |
| OpenCTI objects | 213 |
| OpenCTI reports | 80 |
| ThreatLens clusters | 126 |
| ThreatLens profiles | 126 (confirmed confidence) |
| TTP observations | 132 |

---

## 6. MISP + OpenCTI — FIXED in session 7

**Both now fully working end-to-end automatically.**

### Flow (fully automatic)
```
Phishing email → PhishGuard scans → MISP event created + published (seconds)
→ connector-misp syncs within 60s → OpenCTI worker creates Report + Observables
```

### What was fixed
1. **connector-misp URL** — `http://misp` → `https://misp` (nginx redirect loop)
2. **Missing opencti/worker container** — added to docker-compose
3. **MISP_CREATE_REPORTS/INDICATORS/OBSERVABLES** — were all None (falsy), nothing was created
4. **MISP events not published** — L4 SOAR now calls `/events/publish/{id}` on creation
5. **MISP baseurl resets on restart** — `BASE_URL=https://localhost:8443` in docker-compose env
6. **nginx HTTPS fastcgi param** — mounted `docker/misp-nginx-php.conf` with `fastcgi_param HTTPS on`
7. **MISP login redirect loop** — `Security.force_https=true` + baseurl fix

### MISP login
Go to `https://localhost:8443/users/login` (note: HTTPS, note: port 8443)  
Accept SSL warning → **Advanced → Proceed**  
Login: `admin@admin.test` / `changeme123`

### Critical MISP gotcha
The MISP container **enforces** `MISP.baseurl` from `BASE_URL` env var on every start.
We set `BASE_URL=https://localhost:8443` in docker-compose — this must stay or nav links break.

---

## 7. ThreatLens Gotchas

### Scrapers in Docker
Crawl4AI, Scrapling, trafilatura are installed in the Docker image via a separate pip step in Dockerfile. They were kept out of `requirements.txt` (causes version conflicts) and put in `requirements-threatlens.txt` (local dev only). The Dockerfile installs them separately with `|| true` so conflicts don't break the build.

### ThreatLens tables init on startup
`app/main.py` lifespan calls `init_db()` on every startup — creates the 9 ThreatLens tables idempotently. Required because the DB is in a Docker volume and doesn't auto-migrate.

### Dirty flag
A cluster is only re-profiled if `updated_at > last_profiled_at`. New phishing emails join clusters → `updated_at` bumps → cluster becomes dirty → re-profiled next cycle. Clean clusters skip profiling entirely.

### INTEL_ENABLED
`INTEL_ENABLED=true` is set in `.env`. The scheduler fires daily. Manual trigger: `POST /api/intel/run` (admin only) or Profiling tab → ▶ Run Analysis button.

### API keys configured for ThreatLens
| Key | Status |
|---|---|
| `ABUSECH_AUTH_KEY` | ✅ Set |
| `OTX_API_KEY` | ✅ Set |
| `PULSEDIVE_API_KEY` | ✅ Set |
| `GREYNOISE_API_KEY` | ❌ Not set (GreyNoise agent dormant) |
| `URLSCAN_API_KEY` | ❌ Not set (URLScan agent dormant) |

---

## 8. Known Issues (session 7)

### GreyNoise + URLScan agents dormant
No keys configured. Agents return `[]` and contribute nothing. System still produces `confirmed` profiles without them via MISP matches.

### Grafana empty panels (✅ correct behaviour)
No change from session 6.

### MISP SSL cert warning in browser
Still shows SSL warning — cert is for hostname `misp`, not `localhost`. Always click **Advanced → Proceed**. This is cosmetic only — all API integrations use `verify=False`.

---

## 9. Immediate Next Steps

1. **Get GreyNoise key** — `greynoise.io/plans/community` → `GREYNOISE_API_KEY=...` in `.env`
2. **Get URLScan key** — `urlscan.io/user/signup` → `URLSCAN_API_KEY=...` in `.env`
3. **Merge `feature/threatlens` → `master`** when ready to ship
4. **CORS lockdown** — `allow_origins=['*']` in `app/main.py`
5. **Default passwords** — ES, Kibana, MinIO, OpenCTI, Grafana still use `changeme`
6. **Retrain ML** — 1,445 real scan records in DB, retrain from ML Ops tab
7. **SMTP rate limiter** — revert `SMTP_RATE_PER_IP=200` to `10` for production

---

## 10. API Keys Configured (in .env)

| Key | Status | Used by |
|---|---|---|
| `JWT_SECRET` | ✅ Set | Auth |
| `ANTHROPIC_API_KEY` | ✅ Set | Claude — primary NLP + ThreatLens profiler |
| `VIRUSTOTAL_API_KEY` | ✅ Set | L1 OSINT |
| `ABUSEIPDB_API_KEY` | ✅ Set | L1 OSINT |
| `GOOGLE_SAFE_BROWSING_API_KEY` | ✅ Set | L1 OSINT |
| `SLACK_WEBHOOK_URL` | ✅ Set | L4 SOAR alerts |
| `MISP_API_KEY` | ✅ Set | L1 + L4 + ThreatLens MISP agent |
| `GMAIL_OAUTH_TOKEN_FILE` | ✅ Set | Gmail delivery |
| `GEMINI_API_KEY` | ✅ Set | LLM fallback |
| `ABUSECH_AUTH_KEY` | ✅ Set | ThreatLens IoC agent |
| `OTX_API_KEY` | ✅ Set | ThreatLens IoC agent |
| `PULSEDIVE_API_KEY` | ✅ Set | ThreatLens IoC agent |
| `GREYNOISE_API_KEY` | ❌ Not set | ThreatLens GreyNoise agent (dormant) |
| `URLSCAN_API_KEY` | ❌ Not set | ThreatLens URLScan agent (dormant) |
| `PHISHTANK_API_KEY` | ❌ Not set | L1 OSINT (registration may be closed) |
| `JIRA_*` | ❌ Not set | L4 SOAR Jira tickets |

---

## 11. Key Files

```
phishguard/
├── app/
│   ├── main.py                              # 40+ API endpoints, ThreatLens init in lifespan
│   ├── pipeline.py                          # L0→L1→L2→L3→L4→L5 orchestrator
│   ├── storage.py                           # SQLite: 4 core tables
│   ├── layer0–7/                            # (unchanged from session 6)
│   ├── layer4_soar/misp_exporter.py         # Now publishes events on creation
│   └── threatlens/                          # ThreatLens layer (NEW session 7)
│       ├── config.py / models.py / store.py
│       ├── actor_clusterer.py               # Incremental clustering
│       ├── fusion_engine.py                 # Confidence math (Python, not LLM)
│       ├── profiler.py                      # Claude synthesis
│       ├── ttp_mapper.py                    # ATT&CK + Skylo surface zones
│       ├── sector_rollup.py                 # 3 rollup views
│       ├── org_assessor.py                  # Leadership brief
│       ├── orchestrator.py                  # Dirty-flag cycle runner
│       ├── scheduler.py                     # Daemon thread
│       ├── agents/                          # 10 agent files
│       └── scraper/                         # fetcher.py + crawl4ai + scrapling + trafilatura
├── docker/
│   ├── misp-nginx-php.conf                  # Persistent fastcgi_param HTTPS on fix
│   ├── misp-nginx-http.conf                 # HTTP→HTTPS redirect
│   ├── misp-nginx-https.conf                # HTTPS server block
│   └── misp-init-settings.sh                # Backup settings enforcer via supervisord
├── tests/
│   ├── test_threatlens_*.py                 # 90 ThreatLens tests across 5 phases
│   └── test_layer0/1/2/3/4/5/6/7.py        # 75 core PhishGuard tests
├── requirements.txt                         # Core deps (no scraper conflicts)
├── requirements-threatlens.txt              # Scrapers (local dev only)
├── Dockerfile                               # Installs scrapers separately with || true
├── docker-compose.yml                       # 14 services (added opencti-worker)
├── PRD_Layer8_Threat_Intel.md               # Product requirements
└── EDD_Layer8_Threat_Intel.md               # Engineering design
```

---

---

## 12. Session 7 Continued — Additional Work After Initial Docs Update

### What was added after the SESSION_HANDOFF was first written

**Phase 5 — Hardening (completed)**
- `actor_clusters.last_profiled_at` column — dirty-flag skip (unchanged clusters not re-profiled)
- `get_dirty_clusters()` — only clusters with `updated_at > last_profiled_at` processed
- `mark_cluster_profiled()` — clears dirty flag after profiling
- `log_intel_source()` / `prune_old_intel_sources()` — provenance + 90-day retention
- Orchestrator: `clusters_skipped` + `llm_calls` in cycle summary
- 6 new tests in `tests/test_threatlens_hardening.py`

**Scrapers fixed in Docker**
- Crawl4AI, Scrapling, trafilatura were in `requirements-threatlens.txt` but NOT in the Docker image
- Added separate `pip install` step in Dockerfile with `|| true`
- All three now in the image permanently — no fallback to plain httpx

**MISP baseurl permanently fixed**
- Root cause: `entrypoint.sh` uses `BASE_URL` not `MISP_BASEURL`
- Fix: `BASE_URL=https://localhost:8443` added to docker-compose MISP env
- On every container start now logs: "Enforcing MISP.baseurl to https://localhost:8443"

**API keys added**
```
ABUSECH_AUTH_KEY=f55483...   ✅ abuse.ch IoC feeds
OTX_API_KEY=6fb2b4...        ✅ AlienVault community pulses
PULSEDIVE_API_KEY=f590a2...  ✅ IP/domain reputation
INTEL_ENABLED=true           ✅ ThreatLens live
```

**First ThreatLens cycle completed**
- 126 clusters profiled — all with `confirmed` confidence (MISP IoC matches)
- 132 TTP observations written
- Profiling tab live at `http://localhost:8000` → Profiling

**Dark Web Intelligence Agent (11th agent)**
- `app/threatlens/agents/darkweb_agent.py`
- Three clearnet providers (no Tor access):
  1. **IntelligenceX** (`2.intelx.io`) — paste sites, Tor forums, dark web, data leaks — `INTELX_API_KEY`
  2. **CIRCL.lu PassiveDNS** — free, no key — full DNS history for any domain/IP
  3. **LeakIX** (`leakix.net`) — exposed services + leaked data — `LEAKIX_API_KEY`
- CIRCL PassiveDNS always active (no key). IntelX + LeakIX dormant until keys added.

**Profiling tab complete redesign**
- Stats bar: Total / Critical / High / Confirmed / Surface-mapped counters
- Filter buttons: All / Critical / High / Confirmed
- Profile cards: colored left border, intent icon, severity progress bar, agent mini-dots
- Click 🔍 Intelligence → 3-tab panel:
  - **Intelligence Sources**: 11 agent cards (icon, name, data source, findings, scraped URLs)
  - **ATT&CK & Surface**: techniques grouped by tactic, Skylo surface zone cards
  - **Profile Info**: structured metadata grid

### All 14 API keys now active
ABUSECH, OTX, PULSEDIVE, GREYNOISE, URLSCAN, INTELX, LEAKIX all set →
all 11 agents active. INTEL_ENABLED=true.

### Post-feature enhancements (Options A–E)
| Option | What | Status |
|---|---|---|
| A | All 7 ThreatLens API keys + full 11-agent cycle | ✅ |
| B | Neo4j relationship graph + Neovis.js | ✅ infra (visual polish optional) |
| C | Smart Slack alerts (critical surface / confirmed / high-sev) | ✅ tested live |
| D | Feedback loop — Mark Incorrect feeds next cycle | ✅ |
| E | Merge to master + RECONSTRUCTION_PROMPT update | ✅ |

### Containers: 15 total (added neo4j)
- Neo4j Browser: `http://localhost:7474` (neo4j / changeme123)
- Bolt: `localhost:7687` (used by Neovis.js in the Profiling tab)

### Latest git commits
```
e34cb4a feat: Option D — profile feedback loop
e92bcbc feat: Option C — Smart Slack alerts
c560fe7 feat: Neo4j graph database + Neovis.js
6ddad1e redesign: relationship graph — intent-grouped
18d7c10 feat: Dark Web Intelligence Agent
... (full ThreatLens phases 1-5 below)
```

---

*Resume: read this file → `docker compose ps` (verify 15 containers healthy) → check `http://localhost:8000` Profiling tab (126 profiles live, Neo4j graph) → `python3 scripts/test_smtp_gateway.py` → press F5.*

---

## 13. PENDING (next session) — Email-Bombing Triage Engine rework

**Status:** APPROVED to build, phased, NOT started. Was mid-audit when context ran out.
User gave a full spec + 3 binding decisions. Build with STOP gates after each phase.

### The reframe (why)
Current bombing response = HOLD suspicious mail in Pending Review → that BURIES the OTP,
which is exactly what the attacker wants. New design: ASYMMETRIC DEFENSE — isolate noise,
ACCELERATE high-signal mail, NEVER drop/hold anything. Everything delivers (labeled) within
the window. Keep existing DETECTION (volume/diversity/pattern + velocity + cold-start);
REPLACE the RESPONSE.

### Three binding user decisions
1. **Tier-2 noise signals (CONFIRMED complete):** (a) List-Unsubscribe present, (b)
   Precedence:bulk OR List-Id, (c) first-contact-ever sender domain, (d) ESP fingerprint in
   Received (mailchimp/sendgrid/mailgun/amazonses/sparkpost), (e) very-new domain if WHOIS.
   Any one → Tier 2.
2. **DMARC — do NOT silently approximate.** Audit must report exactly what the parser
   exposes. If only raw spf_result/dkim_result, BUILD A REAL From-domain-vs-authenticated-
   domain alignment check (raw spf=pass does NOT catch forged From). Use checkdmarc/dkimpy
   as fallback only when Authentication-Results header absent. If real alignment genuinely
   out of scope → STOP and ask user, do not default to approximation.
3. **Tier-1 evasion FIX:** subject-match ALONE does NOT qualify for Tier 1. Tier 1 (instant,
   unbuffered, pinned) = AUTHENTICATED critical sender ONLY. Subject-only OTP/bank match from
   unauthenticated sender → Tier 3 (delivered + soft-labeled, never buried, but NOT
   fast-tracked/trusted). Closes throwaway-domain fake-OTP bypass.

### Phase 1 (sub-split if diff too big: [detector+buffer+WAL] then [receiver+classifier+endpoints])
- **1A Cascading windows** (bombing_detector.py): 3 concurrent windows, ANY trips bombing mode:
  Fast 5/30s (existing velocity) · Standard score≥60 over 20 emails/5min (existing) ·
  Slow-drip 100/1hr (NEW). Keep scoring weights + cold-start unchanged. Env-configurable.
- **1B Durable buffer** (storage.py): PRAGMA journal_mode=WAL + synchronous=NORMAL (GLOBAL
  change, affects all tables). Table bombing_buffer(id, recipient, scan_id, timestamp,
  tier CHECK important/noise/uncertain, released INT DEFAULT 0, raw_email BLOB NOT NULL,
  sender_domain, subject) + idx(recipient,released). Helpers: buffer_add, buffer_list_for_
  recipient, buffer_mark_released, buffer_purge_expired. Survives restart. Body OUT of logs.
  NO ack-before-persist queue (durability hole).
- **1C critical_sender.py** (NEW): is_critical_sender(parsed)=True ONLY IF (TLD in
  BOMBING_PROTECTED_TLDS OR domain in trusted_domains) AND DMARC-aligned pass. Claims
  protected TLD but FAILS alignment → "spoofed_critical" → routes to PHISHING path, NOT
  trusted. BOMBING_PROTECTED_TLDS default ".bank,.bank.in,.gov,.gov.in,.nic.in,.insurance"
- **1D Three-tier classifier** (small testable signal fns):
  T1 IMPORTANT (bypass buffer, instant, tag IMPORTANT_VERIFY) = is_critical_sender ONLY.
  T2 NOISE (buffer tier='noise', deliver labeled "[Possible Bombing Noise]" after window) =
     the 5 confirmed signals above.
  T3 UNCERTAIN (buffer tier='uncertain', deliver labeled "[Received During Mail Bomb]") =
     default/safety valve incl. subject-only OTP match from unauth sender. FAVOR DELIVERY.
- **1E smtp_receiver.py:** keep rate limiter at top unchanged. ADD: IP exceeding 421
  boundary >3 consecutive in 60s → hard-drop TCP socket (env-configurable). In bombing mode:
  T1→deliver now skip buffer; T2/3→buffer_add (sync durable). Window-expiry worker (reuse
  scheduler/daemon pattern) at BOMBING_ANALYSIS_WINDOW_SECS=300 releases+labels+delivers+
  purge. Auto-exit bombing mode after BOMBING_MODE_COOLDOWN_SECS=300 no qualifying mail.
  REMOVE old "suspicious→Pending Review" bombing branch. Normal routing unchanged.
- **1F Surface:** extend /health with bombing state (recipients in mode, per-tier counts,
  window countdown, which window tripped). Optional GET /api/bombing/active.
- **Phase 1 tests:** verified .bank DMARC-aligned→T1 instant not buffered mid-bomb; spoofed
  .bank→spoofed_critical→phishing; List-Unsub+first-contact+ESP→T2; non-English→T3 delivered;
  slow-drip 120/1hr→hourly window; window expiry releases; buffer PERSISTS across restart
  (WAL); mode exits after cooldown; existing 21 detector tests still pass. Mock Gmail/network.

### Phase 2 — dormant Gmail ingestion (flag-gated, write+test NOW)
INBOX_INGESTION_ENABLED=false default. Refactor detection+windows+tiering into a SHARED
component both smtp_receiver AND pubsub_watcher/historical_scanner call. Flag off=fully
dormant (no Gmail calls/errors). Flag on=feeds shared pipeline identically. Mock Gmail API.

### Phase 3 — docs/reconciliation
Document rate-limiter (per-rcpt 30/60s) vs bombing-windows interaction in RUNBOOK so they
don't mask each other. Demo-safety env to raise/disable rate limits + warn if 421s appear.
Update SESSION_HANDOFF/PROJECT_CONTEXT/RUNBOOK.

### Global constraints
Match style/structlog/async/Pydantic. Do NOT change rate-limiter behavior (counters/421/
tarpit) beyond the TCP-drop. Don't break normal routing. NEVER buffer/delay Tier-1.
Nothing dropped/held-indefinitely. Durable-before-ack. Body out of logs. All thresholds env-
configurable w/ documented defaults. No real Gmail/network in tests.

### Audit state when context ran out (RESUME HERE)
First STOP gate not yet delivered. Still need to: read app/parser/email_parser.py (DMARC/
spf/dkim exposure — answer audit Q-a), app/storage.py (journal mode + body-in-logs privacy
rule — answer audit Q-b), bombing_detector.py, smtp_receiver.py, test_bombing_detector.py,
pubsub_watcher.py, historical_scanner.py. Then output: (1) state-diff spec-vs-code,
(2) phased plan, (3) audit answers (a)(b). STOP for approval before ANY code.
Parser files that reference dmarc/spf/dkim: app/parser/email_parser.py, app/models.py,
app/pipeline.py, app/layer1/osint_v2.py, app/layer0/pre_filter.py, app/layer2_ai/structural.py.

---

## 14. Email-Bombing Triage Engine — COMPLETE (2026-06-27)

Built on branch `feature/bombing-triage-engine` (off master; not yet pushed/merged).
Replaces the old "hold in Pending Review" bombing response with **asymmetric triage**:
isolate the noise, accelerate authenticated high-signal mail, never drop or hold.
Commits: `c097551` (Phase 1A+1B), `ad474a5` (demo), `dc48bcd` (Phase 2), + Phase 3.

**New/changed code**
- `app/security/critical_sender.py` (NEW) — real DMARC alignment via cryptographic DKIM
  verification (dkimpy); works even as the receiving MTA (no upstream Authentication-
  Results needed). Protected-TLD claim that fails alignment → `spoofed_critical`. SPF
  deferred (needs live peer IP). Fail-closed. checkdmarc optional.
- `app/security/bombing_triage.py` (NEW) — three-tier classifier (Tier 1 authenticated-
  only; Tier 2 five structural noise signals; Tier 3 safety valve). Subject+headers only.
- `app/security/bombing_pipeline.py` (NEW) — shared `evaluate()/buffer()/
  ingest_gmail_message()` called by BOTH the SMTP gateway and the Gmail paths.
- `app/security/bombing_detector.py` — third "slow-drip" window; sliding cooldown
  (replaces fixed HOLD); `is_first_contact()`; `_now()` clock seam.
- `app/storage.py` — WAL + `synchronous=NORMAL`; durable `bombing_buffer` table + helpers.
- `app/layer7_gmail/smtp_receiver.py` — pending-review bombing branch removed; calls the
  shared pipeline; TCP hard-drop; background release worker.
- `app/security/smtp_rate_limiter.py` — RLock (fixed a self-deadlock that hung the handler
  during a distributed bomb); empty-rcpt no longer collectively throttled; `skip_recipient_
  limit` reconciliation (under-attack inbox bypasses per-rcpt limit so it can't bury the
  OTP); `BOMBING_DEMO_MODE`.
- `app/main.py` — release worker started on boot; `/health` buffer state; `/api/bombing/active`.
- Config flag `INBOX_INGESTION_ENABLED` (default off → Gmail ingestion dormant).

**Tests:** ~95+ bombing-related tests green (detector, critical-sender, buffer/WAL, triage,
pipeline, gmail-ingestion, release, tcp-drop, receiver acceptance, reconciliation, rate
limiter). Live logic demo: `PYTHONPATH=. python3 scripts/demo_bombing_triage.py`.

**Docs:** RUNBOOK.md → "Runbook: Email-Bombing Triage Engine" (tiers, window interaction,
demo mode, env-var table, troubleshooting). See also EMAIL_BOMBING_EXPLANATION.md.

**Not done:** real end-to-end mail-delivery test (needs the app restarted on this branch +
Gmail delivery creds). DKIM alignment is unit-tested; the demo simulates it offline.
