# PhishGuard — Security Notes

Tracks the security posture after the full-system review + remediation pass, including
items intentionally **deferred** because changing them naively would break the local/demo
stack. These are production-hardening items, not active vulnerabilities in the demo context.

## Fixed in the remediation pass
- **DKIM multi-signature spoof** — Tier-1 trust now verifies each signature individually
  and only trusts a verified, From-signing, aligned `d=`.
- **SPF alignment** — real DMARC SPF-alignment (live peer-IP check + envelope alignment).
- **Release-worker crash-loss** — claimed/delivered states + stale-claim recovery; nothing dropped.
- **Gmail recipient collapse** — keyed per real delivered-to mailbox.
- **Bounded buffer / cooldown backstop / LRU seen-domains.**
- **Endpoint auth** — all read/mutating core endpoints now require auth / permission.
- **JWT hardening** — secret guard (fail-fast on default), `alg` validation, decode guards,
  server-side role on `/token` (no client-chosen role).
- **CORS** — restricted to configured origins (no wildcard-with-credentials).
- **SSRF** — URL resolution validates each redirect hop against public IP ranges.
- **Infra** — app container runs non-root; OPENCTI/MISP tokens moved out of committed compose.

## Deferred — production hardening (NOT changed to avoid breaking the local stack)
1. **Outbound TLS verification to internal services** (`misp_verify_ssl=false`, ES probes).
   MISP uses a self-signed cert (`docker/misp-ca.pem`), so enabling strict verification
   requires pointing `httpx(verify=...)` at that CA bundle. **Action for prod:** set
   `MISP_VERIFY_SSL=true` and mount/trust the CA bundle; use TLS for Elasticsearch.
2. **Backing-service default credentials** (`elasticsearch:changeme`, `redis:redispassword`,
   `minio:changeme123`, `neo4j:changeme123`, grafana, etc.) and ports bound to `0.0.0.0`.
   Fine for localhost-only; **for any shared/cloud host**: replace with generated secrets via
   `.env` and bind internal services to `127.0.0.1`.
3. **Refresh-token store is in-memory** (`token_store.py`). With the single-worker setup this
   is consistent, but tokens are lost on restart and access tokens can't be revoked before
   expiry. **For prod:** back it with Redis + add a `jti` denylist for access-token revocation.
4. **Blocking calls in async paths** (sklearn `predict`, synchronous SQLite under one global
   lock). Acceptable at demo scale; **for scale:** offload via `run_in_executor`/thread pool
   and use a connection pool.
5. **`PATCH /api/settings` persists secrets to plaintext JSON.** Gated by the `settings`
   permission; **for prod:** use a secret manager or 0600-restricted storage.
6. **docker.sock mounted into the app container** (needed by the Layer-3 sandbox). Even
   non-root, socket access ≈ host control. **For prod:** front it with a scoped
   docker-socket-proxy limited to the container-create calls the sandbox needs.

## Rotate these (previously committed to git history)
- OpenCTI admin token and MISP key were committed in `docker-compose.yml` before this pass.
  They've been moved to `.env`, but **rotate them** since they exist in git history.

## Required production env (fail-fast / must-set)
- `JWT_SECRET` — strong random (e.g. `openssl rand -hex 32`). Startup refuses the default
  unless `ALLOW_INSECURE_JWT_SECRET=true`.
- `API_KEY` / `API_KEY_ROLE` (or `API_KEY_ROLES` map) — controls issued token roles.
- `CORS_ALLOW_ORIGINS` — the real dashboard origin(s).
