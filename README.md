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

## Notes for anyone deploying this fresh

- Runs as a **single uvicorn worker by default, on purpose** — the app holds
  in-process state (SMTP gateway, bombing-detector counters, background
  schedulers). Scaling to multiple workers needs that state moved to Redis
  first; don't just bump `--workers`.
- `docker compose up --force-recreate` / `down` wipes anything living only in
  a container's writable layer. If you've hotfixed something directly inside
  a running container, get it into source/`.env`/`requirements.txt` before
  recreating, or it's gone.
- Named volumes persist scan history, the ML model, and evidence storage
  across restarts; `docker compose down -v` deletes them.
