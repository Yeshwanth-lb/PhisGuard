# PhishGuard — Session Handoff (2026-06-30)

Demo-prep session. Both **phishing detection** and **email-bombing** demos verified working; ThreatLens (adversary profiling) improved.

## 🚨 #1 RULE: do NOT recreate containers
Almost every fix below lives in the **running container's writable layer / user-site**, NOT baked into the image.
- ✅ Safe: `docker restart phishguard-app`, host reboot (writable layer + volumes persist).
- ⛔ Reverts EVERYTHING: `docker compose up --force-recreate`, `docker compose down`, `docker compose build`.
- Host repo files were edited too but **NOT committed** to git.

## Verified working
- **Phishing:** clean→inbox · suspicious→Pending Review · phishing→Quarantine (clean 5/5, phishing 5/5, **suspicious ~3-4/5 — borderline drift**). L1 VirusTotal+Safe Browsing, L2 AI engines, L5 ML (live), L3 sandbox screenshots, SOC Approve→inbox, SOAR (ES+MISP+OpenCTI+Slack+email+denylist), MLflow, Grafana.
- **Email bombing:** `scripts/demo_bombing_all_labels.py` → 34-email flood, deterministic 3 priority / 26 noise / 3 received-during-bomb / 2 quarantine.
- **MISP:** live, exporting events. UI http://localhost:8888 — **`admin@admin.test` / `Phishguard2026!`** (not @phishguard.local).
- **OpenCTI:** synced. UI http://localhost:8080 — **`admin@phishguard.local` / `changeme123`**. Hourly sync; sort by **Platform creation date** for today's data.

## Fixes applied (in-container)
1. scipy stack corruption → reinstalled `numpy==1.26.4 scipy==1.13.1 scikit-learn==1.5.0`.
2. ML model stale (14-feat) → retrained to 24-feat (CV F1 0.95). `data/model.pkl` (volume); backup `data/model.pkl.bak14feat`.
3. setuptools 82→80.10.2 → restores `pkg_resources` → MLflow logging works.
4. `app/layer7_gmail/gmail_client.py`: `internalDateSource` → **receivedTime**.
5. `app/main.py`: `/api/scan/{id}/screenshot` serves `l3.screenshot_b64` fallback.
6. `app/pipeline.py`: L3 sandbox `sb_thr` 0.45→**0.35**.
7. `app/layer1/verdicts.py` (MISP re-enabled) + `osint_v2.py` DNS timeout 8/12→2/3.
8. `app/config.py` validator: `misp_api_key`→`MISP_KEY`; `opencti_token`←`credentials/opencti_token`.
9. `app/templates/index.html`: Pending auto-reload disabled (flicker); vis-network graph improved (edge-thin, palette, physics). **Served per-request → docker cp + browser refresh, no restart.**
10. ThreatLens: `actor_clusterer.py` `_W_INTENT` 0.35→**0.75**; `profiler.py` descriptive names. Rebuilt → **141→13 clusters, 7 named threat profiles, 6 MISP findings, 0 "Unattributed"**.

## New demo scripts
- `scripts/send_mail.py` (paste email in terminal, end with `.` → verdict+tactics+route)
- `scripts/lead_send.py`, `scripts/demo_phishing_15.py` (5/5/5), `scripts/demo_sandbox.py` (sandbox screenshot via local fake page `scripts/phish_page/verify.html`), `scripts/demo_bombing_all_labels.py` (34-email), `scripts/demo_e2e.sh`, `scripts/demo_full_set.py`, `scripts/rebuild_threatlens.py`, `scripts/profile_dirty.py`
- Run scripts in container: `docker cp <s> phishguard-app:/app/ && docker exec -w /app phishguard-app python3 <s>` (no `/app/scripts` dir; DB at `/app/data`).

## Open / pending
- **ThreatLens enrichment agents show "no data"** for fake demo domains (they aren't in real external DBs; only MISP/OpenCTI light up). Correct behavior — to populate, cluster a real known-bad IOC.
- ThreatLens org assessment not generated; benign (legitimate/clean) + generic_phish(2) clusters unprofiled (correct to skip benign).
- Suspicious tier 3-4/5 drift (stronger samples offered, not done).
- **Bake all in-container fixes into the image** (post-demo).
- Pending from before: merge PR #1, rotate MISP/OpenCTI tokens (git history), revert `BOMBING_ANALYSIS_WINDOW_SECS` 45→300 after demo, Jira off (no token).

## Creds (local dev)
App http://localhost:8000 (api_key `dev-key`) · MISP admin@admin.test/Phishguard2026! · OpenCTI admin@phishguard.local/changeme123 · Grafana admin/changeme · Neo4j neo4j/changeme123 · SMTP gateway :8025 (no auth/TLS) · delivery → yeshwanthlb0@gmail.com.
