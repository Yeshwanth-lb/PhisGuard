# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

PhishGuard: a self-hosted, layered email security gateway. Every email flows
through a short-circuiting detection funnel (OSINT → AI/NLP/behavioral/
structural → sandbox → ML → SOAR) and is delivered, held for review, or
quarantined. Two adjacent subsystems run alongside it: ThreatLens (adversary
clustering/profiling from scan history) and a mail-bombing detector.

## Commands

```bash
make up            # start the full Docker Compose stack (app + ES/Redis/MLflow/MISP/OpenCTI/Neo4j/MinIO/...)
make status        # health summary across services
make logs-app      # tail app logs
make shell         # bash shell inside the running app container
make test          # pytest -q on the host
make test-docker   # pytest inside the app container
make test-live     # only tests marked _live (need real API keys/webhooks in .env)
make retrain       # retrain the Layer 5 ML classifier

# Single test / subset (pytest, asyncio_mode=auto so async tests need no decorator):
python3 -m pytest tests/test_bombing_detector.py -q
python3 -m pytest tests/test_bombing_detector.py::test_specific_case -q
python3 -m pytest -k "bombing and not live" -q

# Lint/format (ruff, config in pyproject.toml; also runs via pre-commit):
ruff check . --fix
ruff format .
```

- Python 3.12. Test markers: `slow`, `live` (live hits external services).
- `make build` / `make down` / `make restart` / `make nuke` — see the ⚠️ rule below before using any of these.

## ⚠️ Operational rules specific to this repo

1. **Do NOT `docker compose down` / `up --force-recreate` / `build` / `make
   nuke`/`restart` without checking.** Some fixes live only in the running
   container's writable layer / user-site (scipy-numpy pins, the retrained ML
   model, MISP key, DNS timeouts from earlier sessions), NOT baked into the
   image — a recreate silently reverts them. `docker restart phishguard-app`
   and host reboots are SAFE. `down -v`/`nuke` also wipes scan history, the ML
   model, and evidence storage (named volumes).

2. **Hotfix loop** (app source is baked into the image, not bind-mounted):
   ```
   docker cp app/<path>.py phishguard-app:/app/app/<path>.py && docker restart phishguard-app
   ```
   Wait for `/health` 200, then commit so the change survives an eventual clean rebuild.

3. **Single uvicorn worker, deliberately** — the app holds in-process
   singletons (SMTP gateway :8025, bombing-detector + rate-limiter state, daemon
   schedulers). Don't raise `--workers` without moving that state to Redis first.

4. **Config discipline:** read config via `settings.<field>` (from
   `app/config.py`), NEVER `os.environ.get()` directly — a live
   `PATCH /api/settings` override updates `settings`, not the OS env, so
   raw-env reads silently diverge (this bug was fixed across Slack/Neo4j; don't
   reintroduce it). Keep `.env.example` in sync when adding a settings field.

5. **Verify changes live.** Re-run `PYTHONPATH=. python3 scripts/demo_phishing_15.py`
   (expect ~7 clean / 7 suspicious / 8 phishing). NLP scores drift run-to-run near
   tier boundaries — the "You've been selected — claim your gift" sample flipping to
   phishing is known variance, not a regression. Clean pool is always 7/7.

6. **Datastore backend (`DATABASE_URL`).** All DB access routes through
   `app/db.py` — SQLite by default (empty `DATABASE_URL`, WAL, unchanged
   dev/demo), or PostgreSQL when `DATABASE_URL=postgresql://...` is set. The
   migration is COMPLETE across every module (storage, denylist, ThreatLens
   store/clusterer, retrain, SOAR digest/campaign, watch_state, historical
   scanner, smtp_receiver) and validated on both backends incl. cross-module
   consistency (readers see what writers wrote on Postgres). To deploy on
   Postgres: `docker compose --profile postgres up -d postgres`, set
   `DATABASE_URL`, rebuild the app image (installs psycopg). Note: `app/db.py`
   is the ONLY place allowed to call `sqlite3.connect` — everything else uses
   `_db.connect()` + `_db.ddl()`/`_db.upsert()` for dialect-correct SQL.

## Architecture — the big picture

**Detection funnel (`app/pipeline.py::analyze_email`)** is the spine. Both entry
points — the SMTP gateway (`app/layer7_gmail/smtp_receiver.py`) and the HTTP
`POST /analyze` (`app/main.py`) — feed raw bytes into it. It runs layers in
order and **short-circuits**: the first layer confident enough to condemn
returns immediately (tagged `blocked_at`), otherwise it falls through:

- **Layer 0** (`layer0/`) cheap pre-filter (trusted-sender fast-exit, obvious rejects).
- **Layer 1** (`layer1/`) OSINT reputation — VirusTotal/AbuseIPDB/URLhaus/MISP on URLs/IPs/domains. A hard hit quarantines here.
- **Layer 2** (`layer2_ai/orchestrator.py`) three engines run concurrently — `nlp_engine` (LLM), `behavioral` (per-sender anomaly), `structural` (spoofing/typosquat/DMARC). A **tiered verdict** combines them: any of structural/nlp ≥0.90 → phishing; weighted composite ≥0.70 → phishing; nlp alone ≥0.55 → suspicious; composite ≥0.42 → suspicious. `behavioral` is deliberately excluded from the single-engine override (it saturates on thin baselines).
- **Layer 3** (`layer3_sandbox/`) headless-Chrome URL detonation, only when L2 is suspicious + URLs present.
- **Layer 5** (`layer5_ml/`) ML classifier blends into the L2 confidence to set the final verdict — it can *raise* severity but a floor prevents it *lowering* what L2 decided.
- **`_post_actions`** then fires **Layer 4 SOAR** (`layer4_soar/`: Elasticsearch, Slack, MISP, OpenCTI, Jira, alert email, denylist) + evidence storage (MinIO) + training-record save. Note L4/L5 run *after* the verdict is set, despite the numbering.

Verdict → routing: **clean** delivered, **suspicious** held in the SOC pending-review queue, **phishing** quarantined.

**Config** (`app/config.py`) is a single Pydantic `Settings` object read from
`.env`, with a live `PATCH /api/settings` override layer. Every integration
degrades gracefully (missing key = that feature no-ops, nothing else breaks).

**ThreatLens** (`app/threatlens/`) is a separate scheduler-driven subsystem
(`scheduler.py` daemon): clusters phishing/suspicious scans by actor
(`actor_clusterer.py`), profiles each cluster with enrichment agents
(`agents/`) + an LLM (`profiler.py`), writes a graph to Neo4j
(`neo4j_writer.py`), and exposes `/api/intel/*`.

**Mail-bombing** (`app/security/bombing_detector.py`, `smtp_rate_limiter.py`,
`bombing_pipeline.py`) runs at SMTP ingest, independent of the detection funnel:
volume/velocity/pattern scoring with an asymmetric response — authenticated
critical senders (`critical_sender.py`, DKIM/SPF-aligned .bank/.gov/etc.) surface
instantly even mid-flood, while noise is buffered.

**Layer 7 ingestion** has two modes: the SMTP gateway (used in demos/gateway
deployments) and Gmail. Gmail itself is either single-inbox (personal OAuth
token, `gmail_oauth_token.json`) or **Workspace fleet** (`fleet_scanner.py`,
`fleet_watch.py`, `directory_client.py`) — domain-wide scanning built this
session but dormant until access is granted (see below). Both Gmail modes route
through the same `analyze_email` funnel.

## Google Workspace fleet scanning — dormant, needs access

Built and committed, inactive until a Workspace admin grants: (1) service-account
JSON key at `credentials/sa.json`, (2) domain-wide delegation for scopes
`gmail.modify` + `admin.directory.user.readonly`, (3) an admin email in
`GOOGLE_ADMIN_IMPERSONATE_EMAIL` (required for the Directory list-users call).
Plus `GOOGLE_WORKSPACE_DOMAIN`. Verify in order: `GET /api/gmail/status`
(`fleet_ready:true`) → `GET /api/gmail/fleet/users` (dry-run, no mail) →
`POST /api/gmail/fleet/scan?pilot_users=a@x,b@x` → full rollout.
The single-inbox flow works independently and needs none of this.
Gmail OAuth app is in "Testing" mode → tokens expire ~7 days; on `invalid_grant`
re-run `PYTHONPATH=. python3 scripts/gmail_oauth_setup.py`.

## Reference docs

`PROJECT_CONTEXT.md` (architecture + thresholds), `RUNBOOK.md` (prod ops),
`BRINGUP.md` (first-time setup), `README.md` (quick start + config),
`SECURITY_NOTES.md`, and per-feature: `PHISHING_DETECTION.md`,
`EMAIL_BOMBING_EXPLANATION.md`, `THREAT_INTEL_PROFILING.md`.

## Not production-ready

Secrets in git history (rotate), demo-fast timings still live
(`BOMBING_ANALYSIS_WINDOW_SECS=45`, real=300), SQLite core datastore,
`docker.sock` mounted into the app container, SMTP gateway has no TLS/auth,
Gmail OAuth in Testing mode, single-node everything, ~30% real-world phishing
miss rate, no CI/CD, in-container fixes not baked into the image.
