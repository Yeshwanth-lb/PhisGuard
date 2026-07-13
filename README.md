# PhishGuard

A self-hosted email security gateway: every inbound email passes through a
layered detection pipeline (OSINT reputation checks → AI/NLP/behavioral/
structural analysis → sandbox URL detonation → ML classifier → SOAR response)
before it's delivered, held for review, or quarantined. Includes ThreatLens
(adversary clustering/profiling from your own scan history) and a mail-bombing
detector with asymmetric response (critical alerts surface instantly even mid-flood).

## Quick start

```bash
cp .env.example .env
# fill in the values marked "Required" below, at minimum
docker compose up -d --build
```

The app comes up at `http://localhost:8000` (dashboard + API), with an SMTP
gateway listening on `:8025` for inline scanning. First request may take a
few seconds while the ML model bootstraps.

Check everything's healthy: `curl http://localhost:8000/health`

## What you actually need to configure

Everything is driven by `.env` — no code changes required for a new
deployment. `.env.example` is fully commented; the short version:

**Required:**
- `JWT_SECRET` — a strong random secret (`openssl rand -hex 32`). The app
  refuses to start without this set to something real.
- `PHISHGUARD_API_KEY` — the API key clients use to authenticate.
- One LLM provider key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or
  `GEMINI_API_KEY`) — this powers the core NLP detection engine. Without one,
  detection falls back to a weaker heuristic-only mode.

**Strongly recommended:**
- `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` — free-tier keys are enough for
  the OSINT reputation layer to do anything useful; without them it's a no-op.
- Change every `*_PASSWORD` / `*_SECRET_KEY` value in `.env.example` from its
  shipped default (Elasticsearch, OpenCTI, MinIO, Neo4j). The app **warns at
  startup** (not a hard failure — these gate optional integrations) if any are
  still on the placeholder value. Check the logs for `insecure_default_credentials`.

**Optional, each independently gated (missing = that feature quietly no-ops,
nothing else breaks):**
- MISP / OpenCTI — threat intel export and correlation.
- Slack webhook / Jira / outbound alert email — SOAR notification channels.
- Google Workspace service account + domain-wide delegation — scans/monitors
  every mailbox in your org instead of one inbox. See `app/layer7_gmail/`;
  the safe first call once configured is `GET /api/gmail/fleet/users`
  (pure discovery, touches no mail) before ever running a real scan.

## Architecture at a glance

| Layer | Does |
|---|---|
| 0 | Pre-filter at SMTP time (cheap rejects before full parsing) |
| 1 | OSINT — VirusTotal/AbuseIPDB/URLhaus/MISP reputation on URLs, IPs, domains |
| 2 | AI engines — NLP (LLM), behavioral (per-sender anomaly), structural (spoofing/typosquat/DMARC) |
| 3 | Sandbox — headless-Chrome URL detonation for suspicious links |
| 4 | SOAR — Elasticsearch, Slack, MISP, OpenCTI, Jira, email alert, denylist |
| 5 | ML — classifier blends with L2, trained on scan history + SOC feedback |
| 6 | Security — JWT/RBAC, rate limiting, audit log |
| 7 | Gmail — SMTP gateway ingest + inbox delivery, or Workspace fleet scanning |

Verdict tiers: **clean** → delivered, **suspicious** → held for SOC review,
**phishing** → quarantined. Full detail in `PROJECT_CONTEXT.md`.

## Production deployment (hardening)

All hardening is **opt-in and config-driven** — the defaults above run the full
dev/demo stack. For a production deployment, layer these on:

- **Postgres datastore** — set `DATABASE_URL=postgresql://…` and start the
  profile-gated service: `docker compose --profile postgres up -d postgres`,
  then rebuild the app image (installs the driver). Empty `DATABASE_URL` keeps
  the default SQLite backend.
- **Multiple workers / HA** — a Redis leader-lock ensures the background
  schedulers run in exactly one process, so you can now scale HTTP workers.
  Recommended topology: single SMTP-ingress replica (its rate-limiter/bombing
  counters are authoritative), horizontally-scaled HTTP workers, one scheduler
  leader. Redis (already in the stack) powers this and the L1 OSINT cache.
- **Sandbox without the root socket** — instead of mounting `/var/run/docker.sock`
  into the app (container-escape surface), run the least-privilege proxy:
  `docker compose --profile hardened-sandbox up -d docker-proxy`, set
  `SANDBOX_DOCKER_HOST=tcp://docker-proxy:2375`, and drop the app's socket mount.
- **Inbound SMTP TLS/auth** (internet-facing gateway) — set `SMTP_TLS_CERT_FILE`
  / `SMTP_TLS_KEY_FILE` to enable STARTTLS, `SMTP_AUTH_USER` / `SMTP_AUTH_PASSWORD`
  to require SMTP AUTH, and `SMTP_REQUIRE_TLS=true` to reject cleartext.
- **Before going live:** rotate every credential (especially `MISP_API_KEY` — see
  git history), publish the Gmail OAuth app out of "Testing" mode (else user
  tokens expire every 7 days), and run behind TLS termination.

## Notes for anyone deploying this fresh

- Reproducible image: `docker compose build` produces a working stack (all deps,
  including the `setuptools`/`pkg_resources` pin MLflow needs, are in
  `requirements.txt`). Named volumes persist scan history, the ML model, and
  evidence across restarts; `docker compose down -v` deletes them.
- CI (`.github/workflows/ci.yml`) runs ruff + the offline test suite + a docker
  build on every PR. `make eval` runs the detection-quality regression gate
  against the running stack.
