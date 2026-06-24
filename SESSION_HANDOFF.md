# PhishGuard — Session Handoff Document
**Last updated:** 2026-06-24 (session 7)  
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

*Resume: read this file → `docker compose ps` (verify 14 containers healthy) → check `http://localhost:8000` Profiling tab → `python3 scripts/test_smtp_gateway.py` → press F5.*
