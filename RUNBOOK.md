# PhishGuard Production Runbook

## Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| **P0** | All email scanning down, data loss, security breach | Immediate (< 5 min) |
| **P1** | Partial outage, high error rate (> 5%), Layer 1/2 degraded | 30 min |
| **P2** | Single integration down (MISP, Jira, Slack), elevated latency | 2 hours |
| **P3** | Dashboard UI issues, non-critical feature degraded | Next business day |

---

## Alert Routing

| Alert | Owner | Channel |
|-------|-------|---------|
| App container down / health fail | On-call SRE | `#phishguard-alerts` |
| Elasticsearch unhealthy | On-call SRE | `#phishguard-alerts` |
| Redis unhealthy | On-call SRE | `#phishguard-alerts` |
| ML model missing / retrain failed | ML Ops | `#phishguard-ml` |
| 5xx error rate > 1% | On-call SRE | `#phishguard-alerts` |
| p95 latency > 10s on `/analyze` | On-call SRE | `#phishguard-alerts` |
| Audit log write failure | Security team | `#security-ops` |
| DKIM / SPF check failure spike | Security team | `#security-ops` |

On-call rotation is managed in PagerDuty. Escalation path: SRE → Backend lead → Security lead.

---

## On-Call Procedures

### Receiving an Alert
1. Acknowledge in PagerDuty within 5 minutes.
2. Check the Grafana dashboard: `http://grafana:3000/d/phishguard-soc`.
3. Check container health: `docker compose ps` and `docker compose logs --tail=100 app`.
4. Check `/health` endpoint: `curl -s http://localhost:8000/health | jq`.

### Escalation
- If unable to resolve P0/P1 within 30 minutes, page the backend lead.
- For potential data exfiltration or credential compromise, immediately page the Security lead and start an incident channel `#incident-YYYYMMDD`.

---

## Runbook: App Container Down

**Symptoms:** Health check fails, `/health` returns connection refused.

**Steps:**
```bash
docker compose ps app
docker compose logs --tail=200 app
docker compose restart app
```

If restart loop:
```bash
docker compose down app && docker compose up -d app
```

Check for OOM: `docker stats --no-stream phishguard-app`

If OOM: increase `mem_limit` in `docker-compose.yml` (current: 2g) or reduce concurrency.

---

## Runbook: Elasticsearch Unhealthy

**Symptoms:** `layer4_soar_configured` shows false in `/health`, audit writes failing.

**Steps:**
```bash
curl -s -u elastic:changeme http://localhost:9200/_cluster/health | jq
docker compose logs --tail=100 elasticsearch
```

Common causes:
- Disk full: `df -h` — clear old ES indices if > 85% disk usage.
  ```bash
  curl -X DELETE "http://localhost:9200/phishguard-verdicts-$(date -d '30 days ago' +%Y.%m.%d)" -u elastic:changeme
  ```
- OOM: increase ES heap in `docker-compose.yml` (`ES_JAVA_OPTS=-Xms1g -Xmx1g`).
- Split-brain: not applicable (single-node deployment).

---

## Runbook: Redis Unhealthy

**Symptoms:** L1 cache misses 100%, OSINT checks all re-run on every request, latency spikes.

**Steps:**
```bash
docker compose logs --tail=50 redis
redis-cli -h localhost ping
docker compose restart redis
```

Redis failure is non-fatal — the app degrades gracefully (cache miss = live OSINT check). The main risk is OSINT API rate limits. Monitor VirusTotal/AbuseIPDB rate-limit responses in app logs.

---

## Runbook: High Error Rate (5xx > 1%)

**Symptoms:** Grafana "Error Rate" panel shows spike, Slack alert fires.

**Steps:**
1. Check recent errors: `docker compose logs --tail=200 app | grep ERROR`
2. Identify the failing endpoint from Grafana (filter by `handler`).
3. Common causes:
   - **`/analyze` 500s**: Parser crash — check `email_parse_inner_failed` log entries. Redeploy from the last good Docker image tag.
   - **`/api/ml/retrain` 500s**: Training data corrupt — check `data/training/` directory size and JSONL validity.
   - **Redis connection refused**: See Redis runbook above.
   - **Elasticsearch 503**: See ES runbook above.

---

## Runbook: ML Model Missing or Stale

**Symptoms:** `layer5_ml_ok: false` in `/health`, `/api/ml/status` returns `exists: false`.

**Steps:**
```bash
# Check if model file exists
docker compose exec app ls -lh data/model.pkl

# Bootstrap a new model (runs in ~60s on 300 synthetic samples)
curl -X POST http://localhost:8000/api/ml/bootstrap \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Or retrain on real collected data
curl -X POST http://localhost:8000/api/ml/retrain \
  -H "Authorization: Bearer $ANALYST_TOKEN"
```

The app runs without the model (L5 disabled, L2 verdict used directly). There is no scanning outage — verdicts are slightly less accurate.

---

## Runbook: Gmail Integration / Pub/Sub Stopped

**Symptoms:** Emails no longer flowing in from Gmail, `pull_enabled` shows false or 0 messages/hour.

**Steps:**
```bash
# Check watch expiry (Gmail watches expire after 7 days)
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8000/api/gmail/status | jq

# Renew the watch
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8000/api/gmail/renew
```

If renew fails with 401/403: Service account credentials in `credentials/sa.json` may have expired or been revoked. Rotate via Google Cloud IAM console and update the file.

---

## Runbook: SOAR Integration Failure (Slack / Jira / MISP)

**Symptoms:** Phishing verdicts not appearing in Slack, no Jira tickets created.

**Steps:**
1. Check SOAR status: `curl -H "Authorization: Bearer $ANALYST_TOKEN" http://localhost:8000/api/soar/status | jq`
2. Check app logs for `soar_err` or `slack_err` entries.
3. Individual integrations fail independently — other integrations continue. No scanning impact.
4. For Slack: verify `SLACK_WEBHOOK_URL` in `.env` is still valid (webhook URLs can be invalidated if the Slack app is removed or re-authorized).
5. For Jira: verify `JIRA_API_TOKEN` has not expired (Atlassian tokens expire after 90 days by default).

---

## Runbook: Email-Bombing Triage Engine

**What it does:** When an inbox is flooded to bury a real alert (OTP / bank notice),
PhishGuard isolates the noise and accelerates authenticated high-signal mail instead of
blocking or holding. Detection runs three cascading windows; mail arriving during an
attack is triaged into three tiers; nothing is dropped or held for a human.

**Tiers (only applied while a recipient is in active bombing mode):**
- **Tier 1 — IMPORTANT:** an *authenticated* critical sender (protected TLD or trusted
  domain **AND** cryptographically DMARC/DKIM-aligned). Delivered instantly, tagged
  `[PhishGuard-Priority]`, never buffered. A protected-TLD claim that FAILS alignment →
  `spoofed_critical` → routed to quarantine (phishing). Subject words alone never qualify.
- **Tier 2 — NOISE:** structural signals (List-Unsubscribe, Precedence:bulk/List-Id,
  first-contact domain, ESP fingerprint, new domain). Buffered, released labeled
  `[Possible Bombing Noise]`.
- **Tier 3 — UNCERTAIN:** everything else (default favors delivery). Buffered, released
  labeled `[Received During Mail Bomb]`. A subject-only OTP from an unauthenticated
  sender lands here — delivered + labeled, never fast-tracked.

**Detection windows (any one trips bombing mode):** fast `5 subscription/30s`,
standard `score≥60 over 20/5min`, slow-drip `100/1h`. Mode is a **sliding cooldown**:
it stays active while qualifying mail keeps arriving and auto-exits after
`BOMBING_MODE_COOLDOWN_SECS` of quiet.

**Durability:** the buffer is SQLite (WAL mode) so it survives a restart mid-bomb. The
release worker (daemon) delivers buffered mail labeled once it ages past
`BOMBING_ANALYSIS_WINDOW_SECS`, then purges.

### Rate limiter ↔ bombing windows (IMPORTANT interaction)
The SMTP rate limiter (per-IP 10/60s, per-domain 20/3600s, **per-recipient 30/60s**,
global 60/60s) sits *in front of* the bombing engine. These are reconciled so they
don't mask each other:
- The bombing **volume** window (20/5min) and **velocity** (5/30s) trip *before* the
  per-recipient limit (30/60s), so bombing mode activates first.
- **Once an inbox is in bombing mode, the per-recipient limit is bypassed for it**
  (`skip_recipient_limit`), so the limit can never 421 — and thereby bury — the OTP.
  Per-IP, per-domain, global limits and the TCP hard-drop still protect the gateway.
- TCP hard-drop: an IP that exceeds the 421 boundary `>BOMBING_TCP_DROP_THRESHOLD`
  times in `BOMBING_TCP_DROP_WINDOW_SECS` has its socket dropped (connection-pool
  protection); reset by any allowed email.

### Demo safety
A real demo bomb (~25 emails to one inbox) would otherwise be 421'd by the
per-recipient limit before the detector sees enough. For a demo run set
`BOMBING_DEMO_MODE=1` — rate-limit **blocking is disabled** (arrivals still recorded,
burst alerts still fire, each would-be block logged as `smtp_rate_limit_demo_bypass`).
**Never enable in production** (logs `smtp_rate_limiter_DEMO_MODE_ON` at startup).

### Observability
- `GET /health` → `bombing_detector` (windows + active attacks) and `bombing_buffer`
  (per-recipient tier counts, release window).
- `GET /api/bombing/active` → active events + per-recipient tier breakdown (banner).
- `GET /api/bombing/status` → detector thresholds + active attacks.
- `POST /api/bombing/{rcpt}/clear` → manually clear a recipient's bombing mode.
- Key log events: `inbox_bombing_started`, `smtp_bombing_triage`,
  `smtp_bombing_priority_delivered`, `smtp_bombing_buffered`,
  `smtp_bombing_spoofed_critical`, `bombing_release_cycle`, `smtp_tcp_dropped`.

### Gmail ingestion (dormant)
`INBOX_INGESTION_ENABLED=false` by default → no Gmail API calls. When true, Gmail
push + historical mail feed the SAME pipeline (same tiers/labels/alerts). Note: a
historical backfill arrives as a burst that can look like a bomb — prefer enabling for
the live push path.

### Tunable env vars (all have documented defaults)
| Var | Default | Meaning |
|---|---|---|
| `BOMBING_VOLUME_THRESHOLD` | 20 | emails in standard 5-min window |
| `BOMBING_VELOCITY_THRESHOLD` / `_WINDOW_SECS` | 5 / 30 | fast subscription-burst window |
| `BOMBING_SLOWDRIP_THRESHOLD` / `_WINDOW_SECS` | 100 / 3600 | slow-drip window |
| `BOMBING_MODE_COOLDOWN_SECS` | 300 | quiet period before mode auto-exits |
| `BOMBING_ANALYSIS_WINDOW_SECS` | 300 | buffer hold before labeled release |
| `BOMBING_RELEASE_POLL_SECS` | 15 | release-worker poll interval |
| `BOMBING_PROTECTED_TLDS` | .bank,.gov,… | TLDs eligible for Tier 1 (if aligned) |
| `BOMBING_ESP_FINGERPRINTS` | mailchimp,sendgrid,… | Received-header ESP markers (Tier 2) |
| `BOMBING_TIER2_WHOIS` / `_NEW_DOMAIN_DAYS` | false / 30 | optional new-domain WHOIS check |
| `BOMBING_TCP_DROP_THRESHOLD` / `_WINDOW_SECS` | 3 / 60 | TCP hard-drop escalation |
| `BOMBING_DEMO_MODE` | (off) | disable rate-limit blocking for demos |
| `INBOX_INGESTION_ENABLED` | false | feed Gmail-ingested mail to the engine |

### Troubleshooting
- **OTP not delivered during a bomb:** confirm the sender is genuinely DMARC-aligned
  (`critical_sender` requires a verified DKIM signature). An unauthenticated OTP is
  Tier 3 by design — delivered but soft-labeled, look in the inbox for
  `[Received During Mail Bomb]`.
- **Buffered mail not releasing:** check the `bombing-release` daemon is running and
  `bombing_release_cycle` appears in logs; verify `BOMBING_ANALYSIS_WINDOW_SECS`.
- **Demo bomb gets 421'd:** set `BOMBING_DEMO_MODE=1` (and/or raise `SMTP_RATE_*`).
- **"database is locked":** confirm WAL is on — `PRAGMA journal_mode` should be `wal`.

---

## Routine Maintenance

### Weekly
- Review Grafana error rate trend.
- Run `docker system prune -f` on the host to clear dangling images/containers.
- Check `data/audit.jsonl` size: `wc -l data/audit.jsonl`. Rotate if > 100k lines.

### Monthly
- Rotate `JWT_SECRET` in `.env` (triggers re-login for all active sessions).
- Review ML model accuracy: compare current `cv_f1_mean` in `/api/ml/status` to baseline in `ml/baselines/`.
- Renew Gmail watch proactively (7-day TTL).
- Check Jira/MISP API tokens for upcoming expiry.

### After a Deployment
1. Verify `/health` returns `status: ok`.
2. Run a test scan via the dashboard (load the demo phish, verify verdict = phishing).
3. Confirm Grafana shows traffic on the new deployment.
4. Check `docker compose logs --tail=50 app` for startup errors.
