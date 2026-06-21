# PhishGuard Bring-Up Guide

A complete PhishGuard deployment runs five Docker services on the `phishguard` bridge network.

| Service | Image | Port | Role |
| ---- | ---- | ---- | ---- |
| `app` | `phishguard-app:latest` built locally | 8000, 8025 | FastAPI app, dashboard, SMTP listener |
| sandbox | `phishguard-sandbox:latest` built locally | internal only | Headless browser for Layer 3 detonation |
| `elasticsearch` | `docker.elastic.co/elasticsearch/elasticsearch:8.13.2` | 9200 | SOAR alert and audit storage |
| `kibana` | `docker.elastic.co/kibana/kibana:8.13.2` | 5601 | Operator UI for ES |
| `redis` | `redis:7.2-alpine` | 6379 | Cache and rate-limit store |
| `mlflow` | `ghcr.io/mlflow/mlflow:v2.13.2` | 5000 | Model tracking server |

---

## 1. Prerequisites

- Docker Engine 24+ and Docker Compose v2.
- 4 GB free RAM (Elasticsearch alone reserves 1 GB).
- macOS or Linux. Windows works through WSL2.

## 2. First-time setup

```bash
git clone <repo-url> phishguard && cd phishguard
make env                   # copies .env.example to .env
vim .env                   # set JWT_SECRET, GEMINI_API_KEY, VIRUSTOTAL_API_KEY
make build                 # build sandbox and app images
make up                    # start the full stack in background
make status                # health summary across services
```

After `make up` returns, give Elasticsearch ~60 s to finish bootstrap, then visit:

- http://localhost:8000/dashboard for the PhishGuard dashboard
- http://localhost:8000/docs for FastAPI Swagger
- http://localhost:5601 for Kibana, login elastic / changeme
- http://localhost:5000 for MLflow tracking UI

## 3. Required environment variables

At minimum you must set:

- `JWT_SECRET`: 32-byte random hex; signs auth tokens. Generate with `openssl rand -hex 32`.
- `GEMINI_API_KEY` or `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`: Layer 2 NLP engine. Without one, Layer 2 stays in heuristic-only fallback.
- `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY`: Layer 1 OSINT enrichment. Both have free tiers.

Everything else (Slack, Jira, SMTP alerts, Gmail, MISP) is optional and silently skipped if blank.

## 4. Layer 3 sandbox note

The app container mounts `/var/run/docker.sock` so Layer 3 can launch sibling `phishguard-sandbox` containers on demand. This is the standard "Docker-out-of-Docker" pattern. The sandbox image must be built before the app starts processing emails. `make build` does this automatically.

On Linux hosts using rootless Docker, mount `$XDG_RUNTIME_DIR/docker.sock` instead.

## 5. Common operations

```bash
make logs            # tail all logs
make logs-app         # tail app logs
make shell           # bash into running app container
make test-docker     # run pytest inside the app container
make restart         # graceful restart
make down            # stop, preserve volumes
make nuke            # stop AND wipe volumes (DESTRUCTIVE)
```

## 6. Troubleshooting

| Symptom | Likely cause | Fix |
| ---- | ---- | ---- |
| `app` exits with connection refused to ES | ES still bootstrapping | Wait 60 s, then `make restart`. Healthcheck has a 60 s start_period. |
| `Cannot connect to the Docker daemon` | Docker socket not mounted, or rootless Docker on a non-default path | Confirm `/var/run/docker.sock` is the host path; otherwise edit `docker-compose.yml`. |
| Layer 3 always returns sandbox disabled | `phishguard-sandbox:latest` image not built | `make build-sandbox` |
| ES max virtual memory areas error | Linux host needs `vm.max_map_count` raised | `sudo sysctl -w vm.max_map_count=262144` |
| Dashboard 401 after upgrade | Old JWT in localStorage | Hard-refresh the dashboard tab and log in again. |

## 7. Kibana operations dashboard

PhishGuard ships with a one-shot script that provisions an Elasticsearch index template, a Kibana data view, five Lens visualisations, and an `Operations` dashboard. Run it once after the stack is healthy, or any time you want to repair the saved objects.

```bash
python3 scripts/setup_kibana.py
```

Useful flags:

```bash
python3 scripts/setup_kibana.py --reset-indexes        # drop existing phishguard-verdicts-* indices first
python3 scripts/setup_kibana.py --kibana-url http://kibana.internal:5601
python3 scripts/setup_kibana.py --es-url http://es.internal:9200
```

Environment variables override defaults: `KIBANA_URL`, `KIBANA_USERNAME`, `KIBANA_PASSWORD`, `ELASTICSEARCH_URL`, `ELASTICSEARCH_USERNAME`, `ELASTICSEARCH_PASSWORD`.

The script is idempotent — re-running it overwrites the dashboard objects but leaves your data untouched. Once it finishes, open:

http://localhost:5601/app/dashboards#/view/phishguard-ops

Panels:

| Panel | Source field | Question it answers |
| ---- | ---- | ---- |
| Verdict distribution | `verdict` | How many phishing vs suspicious vs clean? |
| Verdicts over time | `@timestamp` + `verdict` | Are we seeing a spike? |
| Top sender domains (phishing only) | `sender_domain` | Which domains are repeatedly hostile? |
| ML score distribution | `ml_score` | Is the Layer 5 model bimodal (healthy)? |
| Layer 2 confidence distribution | `l2_confidence` | Is the AI engine confident or uncertain? |

To populate sample data quickly, run `python3 scripts/demo_batch.py --n 20 --quiet` against the running stack — every processed email writes a verdict document to ES.

## 8. Going to production

Before exposing this stack to real traffic:

- [ ] Replace `JWT_SECRET` with a freshly-generated 32-byte hex secret.
- [ ] Replace `elastic` slash `changeme` credentials in compose AND in .env.
- [ ] Put the app behind a reverse proxy with TLS, plus a real DNS host record.
- [ ] Switch MLflow to a Postgres or MySQL backend store (current setup uses local files).
- [ ] Pin every image to a digest, not a tag, in `docker-compose.yml`.
- [ ] Enable Elasticsearch snapshot lifecycle management to persist audit data offsite.
