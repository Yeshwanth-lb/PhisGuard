# PhishGuard Layer 8 — Threat Intelligence & Adversary Profiling
## Engineering Design Document (EDD)

| | |
|---|---|
| **Document** | EDD — Layer 8: Threat Intelligence & Adversary Profiling |
| **Companion** | PRD_Layer8_Threat_Intel.md |
| **Status** | Draft for review |
| **Last updated** | 2026-06-23 |
| **Target** | PhishGuard v1.5 → v1.6 |

---

## 1. Overview

This document specifies the engineering design for Layer 8, the threat-intelligence and adversary-profiling layer. It implements the PRD. Layer 8 is an **offline, read-only, cadence-driven** subsystem that consumes the `scans` table, clusters scans into candidate adversaries, enriches each cluster via parallel agents, maps behavior to MITRE ATT&CK and the Skylo NTN attack surface, and synthesizes structured `AdversaryProfile` records surfaced in a new dashboard tab.

It does **not** sit in the SMTP/delivery path. It introduces no new blocking behavior. It reuses PhishGuard's existing primitives wherever possible: `asyncio.gather` concurrency, SQLite storage, Redis caching, structlog logging, Pydantic models, FastAPI endpoints, the unified LLM client, the audit middleware, and the daemon-thread scheduler pattern from the weekly digest.

---

## 2. Design principles

1. **Read-only w.r.t. routing.** Layer 8 never mutates a verdict or touches delivery. (PRD NG1.)
2. **Assess, don't assert.** Every output carries confidence + evidence; attribution is always hedged. (PRD G8/NG2.)
3. **Lawful sources only, enforced in code.** A source allowlist + robots/rate-limit middleware is the only path to external data. No dark-web data-exfil code paths exist. (PRD §6.)
4. **Graceful degradation.** Any agent or source can fail; the run still produces a partial profile.
5. **Reuse over reinvention.** Extend `campaign_detector`, reuse cache/audit/LLM/export. Minimize new surface area.
6. **Incremental & idempotent.** Re-running profiling updates existing profiles rather than duplicating them.

---

## 3. High-level architecture

```
                         ┌───────────────────────────────────────────────┐
                         │              Layer 8 — app/layer8_intel/        │
                         │                                                 │
  scans table  ─────────►│  actor_clusterer.py                             │
  (SQLite)               │     └─ candidate clusters (incremental)         │
  campaign_detector ────►│                  │                              │
                         │                  ▼                              │
                         │  orchestrator.py  (asyncio.gather per cluster)  │
                         │     ├─ agents/osint_report_agent.py ──┐         │
                         │     ├─ agents/attack_mapper_agent.py  │         │
                         │     ├─ agents/misp_opencti_agent.py   ├─► findings (cited)
                         │     ├─ agents/cve_agent.py            │         │
                         │     └─ agents/exposure_agent.py ──────┘         │
                         │                  │                              │
                         │                  ▼                              │
                         │  ttp_mapper.py  → ATT&CK + Skylo surface zones  │
                         │                  │                              │
                         │                  ▼                              │
                         │  profiler.py  (Claude, via llm/client)          │
                         │     └─ AdversaryProfile (structured JSON)        │
                         │                  │                              │
                         │                  ▼                              │
                         │  sector_rollup.py → sector/org/network views    │
                         │                  │                              │
                         │                  ▼                              │
                         │  store.py → SQLite: actor_profiles,             │
                         │             intel_sources, ttp_observations      │
                         └───────────────────────────────────────────────┘
                                            │
        ┌───────────────────────────────────┼───────────────────────────────┐
        ▼                                    ▼                               ▼
  FastAPI endpoints                  Profiling dashboard tab           MISP/OpenCTI export
  (app/main.py)                      (templates/index.html)            (reuse L4 exporters)

  scraper/  (Scrapy + httpx)  ── used only by osint_report_agent & cve_agent,
                                 gated by allowlist + robots + rate-limit middleware
```

---

## 4. Module / file layout

```
app/layer8_intel/
├── __init__.py
├── orchestrator.py          # top-level: run a profiling cycle
├── actor_clusterer.py       # scans → candidate adversary clusters (extends campaign logic)
├── fusion_engine.py         # parses ALL agent outputs → normalize, dedupe, corroborate, weight
├── profiler.py              # per-cluster synthesizing Claude step → AdversaryProfile
├── org_assessor.py          # NEW: aggregates all profiles+rollups+signals → OrgThreatAssessment (leadership view)
├── ttp_mapper.py            # ATT&CK technique mapping + Skylo surface-zone mapping
├── sector_rollup.py         # sector / org-team / network-technology aggregation
├── store.py                 # SQLite DAO for the new tables
├── models.py                # Pydantic models (Cluster, Finding, AdversaryProfile, OrgThreatAssessment, Rollup)
├── config.py                # Layer-8 settings (cadence, thresholds, allowlist, source keys — blank by default)
├── agents/
│   ├── __init__.py
│   ├── registry.py          # pluggable registry; each agent declares required creds + not_configured behavior
│   ├── base_agent.py        # abstract: run(cluster)->list[Finding]; timeout/cache/isolation/not_configured
│   ├── osint_report_agent.py     # public reports & advisories (Crawl4AI + Scrapling)
│   ├── attack_mapper_agent.py    # behavior → MITRE ATT&CK (local STIX, free)
│   ├── misp_opencti_agent.py     # existing MISP/OpenCTI intrusion-sets/galaxies
│   ├── ioc_reputation_agent.py   # NEW: abuse.ch (URLhaus/MalwareBazaar/ThreatFox/Feodo), AlienVault OTX, Pulsedive
│   ├── cve_agent.py              # NVD + CISA KEV + EPSS, NTN/5G/telecom/cloud filter (free)
│   ├── compromise_intel_agent.py # RENAMED+expanded: ransomware.live + RansomLook + breach-directory (free); HIBP/DeHashed/RF/Intel471/Flare optional-key
│   └── telecom_ntn_agent.py      # 3GPP/GSMA/satellite-sector advisories (Skylo-specific)
├── scraper/
│   ├── __init__.py
│   ├── fetcher.py           # THE chokepoint: allowlist + robots + rate-limit + honest UA; wraps all tools
│   ├── crawl4ai_client.py   # Crawl4AI wrapper → clean markdown, BM25 filter, JS render
│   ├── scrapling_client.py  # Scrapling (D4Vinci) wrapper → adaptive selectors, anti-bot, spiders, --ai-targeted
│   ├── text_extract.py      # httpx + trafilatura fast path for simple/static pages
│   ├── feeds_client.py      # NEW: typed clients for free JSON feeds (ransomware.live, RansomLook, abuse.ch, OTX, NVD, KEV, EPSS, Pulsedive)
│   ├── discovery.py         # optional Katana URL/endpoint discovery on allowlisted hosts
│   ├── allowlist.yaml       # maintained source allowlist (domains + source metadata)
│   └── spiders/             # Scrapling spiders for multi-page sources
│       └── report_spider.py
└── data/
    ├── attack_surface.yaml  # Skylo surface-zone taxonomy (versioned)
    └── attack_techniques.json  # local MITRE ATT&CK technique reference (id, name, tactic)

tests/
├── test_layer8_clusterer.py
├── test_layer8_store.py
├── test_layer8_agents.py        # agents mocked — no live network in unit tests; includes not_configured cases
├── test_layer8_feeds.py         # NEW: free-feed client parsing (ransomware.live/RansomLook/abuse.ch/OTX) mocked
├── test_layer8_fusion.py        # normalize/dedupe/corroborate/confidence-weighting logic
├── test_layer8_profiler.py
├── test_layer8_org_assessor.py  # NEW: strategic org assessment synthesis + confidence discipline
├── test_layer8_ttp_mapper.py
├── test_layer8_rollup.py
├── test_layer8_api.py
├── test_layer8_scheduler.py
├── test_layer8_hardening.py
└── test_layer8_scraper_guard.py # asserts allowlist/robots enforcement across ALL scraper clients
```

---

## 5. Data model

### 5.1 New SQLite tables

```sql
-- Candidate adversary clusters (mutable; updated each cycle)
CREATE TABLE IF NOT EXISTS actor_clusters (
    id              TEXT PRIMARY KEY,          -- stable cluster id (hash of seed signature)
    created_at      REAL,
    updated_at      REAL,
    first_seen      REAL,
    last_seen       REAL,
    member_scan_ids TEXT,                      -- JSON array
    dominant_intent TEXT,                      -- e.g. bec_fraud
    ioc_json        TEXT,                      -- JSON: domains, ips, url_patterns, registrars, asns
    target_json     TEXT,                      -- JSON: recipients, segments
    signature_json  TEXT,                      -- JSON: structural/behavioral signature used for matching
    status          TEXT DEFAULT 'active'      -- active | dormant | merged
);

-- Synthesized adversary profiles (one current profile per cluster; history optional)
CREATE TABLE IF NOT EXISTS actor_profiles (
    id                  TEXT PRIMARY KEY,
    cluster_id          TEXT NOT NULL,
    generated_at        REAL,
    assessed_identity   TEXT,                  -- alias or 'unattributed cluster'
    suspected_apt       TEXT,                  -- nullable; always hedged in UI
    assessed_intent     TEXT,
    severity            TEXT,                  -- critical|high|medium|low
    confidence          TEXT,                  -- confirmed|high|moderate|low|speculative
    ttp_json            TEXT,                  -- JSON: [{attack_id, name, tactic, evidence_ref}]
    surface_zones_json  TEXT,                  -- JSON: list of Skylo surface zones
    segments_json       TEXT,                  -- JSON: targeted industry verticals
    evidence_json       TEXT,                  -- JSON: evidence chain [{claim, source, ref}]
    summary             TEXT,                  -- Claude's prose assessment
    model               TEXT,                  -- which LLM produced it
    FOREIGN KEY (cluster_id) REFERENCES actor_clusters(id)
);

-- External intel sources fetched (provenance + cache audit)
CREATE TABLE IF NOT EXISTS intel_sources (
    id              TEXT PRIMARY KEY,
    cluster_id      TEXT,
    agent           TEXT,                      -- which agent fetched it
    source_url      TEXT,
    source_title    TEXT,
    fetched_at      REAL,
    finding_json    TEXT,                      -- structured finding extracted
    confidence      TEXT
);

-- Observed technique mappings (queryable for rollups)
CREATE TABLE IF NOT EXISTS ttp_observations (
    id              TEXT PRIMARY KEY,
    cluster_id      TEXT,
    attack_id       TEXT,                      -- ATT&CK technique id, e.g. T1566
    tactic          TEXT,
    surface_zone    TEXT,
    evidence_ref    TEXT,
    observed_at     REAL
);

-- Strategic org-level assessment (one current row; history optional). Leadership view.
CREATE TABLE IF NOT EXISTS org_threat_assessment (
    id                  TEXT PRIMARY KEY,
    generated_at        REAL,
    adversary_landscape TEXT,                  -- prose: who is plausibly targeting an NTN operator like Skylo
    surface_pressure_json TEXT,                -- JSON: per-zone pressure (ground_station/ntn_5g_core/gcp/supply_chain)
    sector_pressure_json  TEXT,                -- JSON: per-vertical targeting (maritime/logistics/mining/...)
    strategic_intent    TEXT,                  -- assessed: espionage|disruption|financial|hacktivism|mixed
    top_campaigns_json  TEXT,                  -- JSON: most significant emerging campaigns
    source_profile_ids  TEXT,                  -- JSON: profiles this assessment synthesized
    confidence          TEXT,                  -- overall confidence tier
    evidence_json       TEXT,                  -- evidence chain back to profiles/signals
    summary             TEXT,                  -- leadership-facing prose
    model               TEXT
);
```

Privacy note: none of these tables store email bodies or third-party PII. IoCs and metadata only. Compromise/exposure findings are stored as signals (`finding_json` describing *that* an exposure/victim-listing exists), never raw breach records or leaked data.

### 5.2 Key Pydantic models (`models.py`)

```python
class IoCSet(BaseModel):
    domains: list[str] = []
    ips: list[str] = []
    url_patterns: list[str] = []
    registrars: list[str] = []
    asns: list[str] = []

class ActorCluster(BaseModel):
    id: str
    member_scan_ids: list[str]
    first_seen: float
    last_seen: float
    dominant_intent: str | None
    iocs: IoCSet
    targets: dict            # {recipients: [...], segments: [...]}
    signature: dict
    status: str = "active"

class Finding(BaseModel):
    agent: str
    claim: str               # one assessed statement
    source_url: str | None   # citation; None for internal-feed findings
    source_title: str | None
    confidence: str          # confirmed|high|moderate|low|speculative
    raw: dict = {}           # structured extras

class TTP(BaseModel):
    attack_id: str
    name: str
    tactic: str
    evidence_ref: str

class CorroboratedClaim(BaseModel):
    claim: str
    attack_id: str | None = None
    iocs: IoCSet | None = None
    supporting_sources: list[str]   # finding/source/scan refs — independent supporters
    independent_source_count: int
    confidence: str                 # assigned deterministically by the fusion engine

class AdversaryProfile(BaseModel):
    id: str
    cluster_id: str
    generated_at: float
    assessed_identity: str
    suspected_apt: str | None
    assessed_intent: str
    severity: str
    confidence: str
    ttps: list[TTP]
    surface_zones: list[str]
    segments: list[str]
    claims: list[CorroboratedClaim]  # the fusion engine's weighted, evidence-linked claim set
    evidence: list[Finding]          # raw findings retained for the audit trail
    summary: str
    model: str
```

---

## 6. Component design

### 6.1 `actor_clusterer.py`
- **Input:** phishing + suspicious scans from the `scans` table since the last watermark.
- **Approach:** extends the existing campaign logic. The current detector clusters on normalized sender-domain and NLP intent. Layer 8 adds a composite **signature**: normalized-domain base + intent + infrastructure features (shared IP/ASN/registrar, URL structural fingerprint) + recipient-segment. Two scans join the same cluster if their signatures match above a configurable similarity threshold.
- **Incrementality:** a cluster id is a stable hash of its seed signature. New scans are matched against existing cluster signatures first (cheap), and only form a new cluster on no-match. Clusters not seen within `CLUSTER_DORMANT_DAYS` flip to `dormant`.
- **Output:** upserts `actor_clusters` rows.
- **Reuse:** import and call the existing normalization helpers from `campaign_detector.py` rather than duplicating regex.

> **Integration point — needs your code:** I need the actual `campaign_detector.py` and `storage.py` to wire the signature extension to your real schema/helpers without guessing field names.

### 6.2 `agents/base_agent.py` + `agents/registry.py`
- Abstract base: `async def run(self, cluster: ActorCluster) -> list[Finding]`.
- Wraps each concrete agent with: `asyncio.wait_for` timeout, try/except isolation (returns `[]` on failure, logs structured error), and Redis caching keyed on `(agent_name, cluster_signature_hash)` with a TTL.
- This is the single chokepoint that guarantees PRD FR7 (isolation) and FR8 (caching).
- `registry.py` holds the active agent list. Adding an agent = implement `base_agent` + register; the orchestrator iterates the registry, so no orchestrator/fusion change is needed (PRD FR6a). Each agent also declares a `prompt_injection_safe()` step it must run on any scraped text before returning findings (PRD FR8a).

### 6.3 Concrete agents (`agents/`)
All run concurrently in `orchestrator.py` via `asyncio.gather(*[a.run(cluster) for a in registry.active()], return_exceptions=True)`.

- **`osint_report_agent.py`** — given cluster intent + IoCs, discovers and reads public reports/advisories that match the tradecraft. Uses the scraper layer (Crawl4AI for clean markdown, Scrapling for fragile/anti-bot sources), then Claude to extract structured `Finding`s, each with a source URL. Cited claims only.
- **`attack_mapper_agent.py`** — maps the cluster's observed behaviors (from scan metadata + stored NLP intent/tactics) to MITRE ATT&CK technique IDs using the local `attack_techniques.json` reference plus an LLM mapping pass. Produces `TTP`s.
- **`misp_opencti_agent.py`** — queries the **existing** MISP and OpenCTI integrations for intrusion-sets/galaxies matching the cluster IoCs. A hard match yields a `confirmed`-confidence finding (PRD §9). Reuses L4 exporter clients.
- **`cve_agent.py`** — pulls NVD/CVE entries relevant to NTN/5G/telecom/cloud keywords associated with the cluster's apparent targeting (httpx JSON path); flags exploit-relevant CVEs.
- **`exposure_agent.py`** — queries a breach-**exposure** API for Skylo + named partner domains; reports *that* an exposure is referenced. Stores signals only, no records. (PRD §6.)
- **`telecom_ntn_agent.py`** — the Skylo-specific source domain: satellite/teleport security advisories, 3GPP security notes, GSMA and NTN/5G-sector reporting. This is the agent that makes profiles relevant to ground-station / NTN-core / supply-chain targeting rather than generic enterprise phishing.

### 6.4 `scraper/` — tools behind one lawful chokepoint
- **`fetcher.py`:** every outbound fetch — from *any* client below — passes through here. Enforces: (1) host ∈ `allowlist.yaml`; (2) robots.txt check (cached); (3) per-domain token-bucket rate limit; (4) honest `User-Agent`; (5) timeout. A fetch to a non-allowlisted host raises and is logged — there is **no bypass path**, and the powerful clients below cannot route around it.
- **`crawl4ai_client.py`:** wraps **Crawl4AI** (`AsyncWebCrawler`). Returns LLM-ready Markdown with its BM25/"fit-markdown" filter applied so only cluster-relevant sections survive — this is the default extractor for report pages and keeps profiler token cost down. JS rendering via Playwright when needed.
- **`scrapling_client.py`:** wraps **Scrapling (the D4Vinci library)**. Used when a source changes layout often or has anti-bot friction: its adaptive self-healing selectors relocate target elements when pages update, so collection doesn't silently break. Scrapy-like spiders (in `spiders/`) with proxy rotation handle multi-page sources. Runs with `--ai-targeted`/AI-safe extraction so scraped content is hardened against prompt injection before it reaches an LLM. Anti-bot features are used only for resilience on **public** pages — never to defeat an access-control gate (enforced by the allowlist + a guard test).
- **`text_extract.py`:** **httpx + trafilatura** fast path for simple JSON APIs and plain article pages where a browser is overkill.
- **`discovery.py`:** optional **Katana** URL/endpoint discovery on an allowlisted host before deciding what to fetch.
- **`allowlist.yaml`:** the maintained set of approved OSINT domains with per-source metadata (type, polite-delay, preferred client). This file *is* the legal boundary; editing it is a reviewed action.

**Tool-selection rule (encoded in `osint_report_agent` + `telecom_ntn_agent`):** httpx/trafilatura for simple/static → Crawl4AI for JS-heavy or LLM-bound extraction → Scrapling when the source is fragile or pushes back. A source that needs more than Scrapling is dropped from the allowlist, not escalated against.

### 6.5 `ttp_mapper.py`
- Consolidates `attack_mapper_agent` output + any ATT&CK hits from MISP into a deduped TTP list per cluster.
- Maps each cluster to Skylo **surface zones** from `data/attack_surface.yaml`. The taxonomy (versioned):

```yaml
# attack_surface.yaml (v1)
zones:
  - id: ground_station_ingress
    label: "Ground-station ingress path"
    keywords: [earth station, ground station, teleport, gateway, baseband]
  - id: ntn_5g_core
    label: "NTN / 5G signaling & core"
    keywords: [5g core, ntn, vran, ran, 3gpp, signaling, amf, smf, gtp, s6a, s8]
  - id: gcp_infra
    label: "Cloud (GCP) infrastructure"
    keywords: [gcp, google cloud, kubernetes, iam, service account, bucket]
  - id: supply_chain
    label: "MNO / chipset / module / SIM supply chain"
    keywords: [mno, carrier, chipset, module, sim, esim, qualcomm, modem, ota firmware]
  - id: corporate_it
    label: "Corporate / IT / identity"
    keywords: [okta, vpn, email, credential, payroll, invoice, wire]
segments:
  - agriculture
  - maritime
  - logistics
  - mining
  - automotive
  - consumer_wearables
```
- Mapping is keyword + LLM-assisted, evidence-referenced. Writes `ttp_observations`.

### 6.6 `fusion_engine.py` — the engine that parses all agent results
This is the dedicated synthesis stage (PRD FR8b–FR8g). It is deliberately separate from both the agents (which only *collect*) and the profiler LLM step (which only *writes prose/JSON*). The fusion engine is where raw, overlapping, multi-source agent output becomes one coherent assessment.

Pipeline inside `run(cluster, findings: list[Finding]) -> AdversaryProfile`:
1. **Collect** — accept the full `list[Finding]` from `asyncio.gather` (including partials from agents that errored; `return_exceptions=True` results are filtered).
2. **Normalize** — canonicalize IoCs (lowercase domains, defang/refang consistency, CIDR-normalize IPs), normalize ATT&CK ids, and unify claim phrasing into a common shape.
3. **Dedupe** — collapse identical claims/IoCs reported by multiple agents into one, *retaining the list of contributing sources* (this is what makes corroboration measurable).
4. **Corroborate & weight** — for each surviving claim, count *independent* sources supporting it and assign a confidence tier per §8:
   - MISP/OpenCTI intrusion-set hit → `confirmed`
   - ≥2 independent OSINT sources agree (+ optional ATT&CK pattern match) → `high`
   - single credible source or strong internal infra clustering → `moderate`
   - weak/circumstantial → `low`; pattern-only guess → `speculative`
5. **Assemble evidence chain** — every claim keeps refs to its supporting findings/sources/scan IDs.
6. **Synthesize** — call `profiler.py` (§6.7) with the corroborated, weighted, evidence-linked claim set. The profiler writes the prose + structured `AdversaryProfile`; the fusion engine owns the *confidence math*, so the LLM cannot inflate confidence beyond what the source agreement supports (a key anti-overclaim control).
7. **Fallback** — if the profiler step fails/unparseable, build a `speculative` profile deterministically from the corroborated claims (no free-text attribution). Always returns a profile.
8. **Upsert** — idempotent write to `actor_profiles` keyed on cluster id; unchanged inputs update in place.

Design choice: keeping confidence assignment in deterministic Python (step 4) rather than delegating it to the LLM is what lets us *test* the confidence behavior (`test_layer8_fusion.py`) and guarantee the §8 invariants hold regardless of model output.

### 6.7 `profiler.py`
- Called by the fusion engine. Builds a single prompt containing: the cluster summary, the **corroborated & weighted** claim set (not raw findings), the TTP list, and the surface-zone mapping. Calls Claude via the existing unified LLM client with `cache_control: ephemeral` on the system prompt.
- **Untrusted-input handling:** all agent-supplied text is wrapped/framed as data, never instructions; the system prompt states scraped content may contain injection attempts and must not be obeyed.
- **Output contract:** Claude returns JSON only, parsed into `AdversaryProfile`. The system prompt forbids asserting attribution as fact, requires the confidence tier handed to it by the fusion engine (it may *lower* but not *raise* it), and requires an evidence ref for every claim.
- On parse failure: one repair retry, then defer to the fusion engine's deterministic fallback.

### 6.7 `sector_rollup.py`
- Pure aggregation over `actor_profiles` + `ttp_observations`:
  - **Sector view:** count/severity of profiles per industry vertical.
  - **Org view:** which internal recipient functions/teams are targeted (derived from recipient metadata already in scans).
  - **Network view:** activity per surface zone (ground-station / NTN-5G / GCP / supply-chain).
- Returns Pydantic `Rollup` objects for the API.

### 6.8 `orchestrator.py`
- `async def run_cycle()`:
  1. `actor_clusterer.refresh()` → active clusters.
  2. For each cluster (bounded concurrency, e.g. `asyncio.Semaphore`): `asyncio.gather` the registered agents → `ttp_mapper` → `fusion_engine.run(cluster, findings)` (which internally calls `profiler`).
  3. `sector_rollup.recompute()`.
  4. Log run summary (counts, duration, per-agent success/failure) via audit.
- Triggered by: daemon-thread scheduler (cadence from config, default daily) **and** `POST /api/intel/run`. Same scheduler pattern as `digest.py`.

---

## 7. API endpoints (added to `app/main.py`)

```
POST   /api/intel/run                  # trigger a profiling cycle (admin)
GET    /api/intel/profiles             # list profiles (sortable by severity/confidence)
GET    /api/intel/profiles/{id}        # full profile + evidence chain + linked scans
GET    /api/intel/clusters             # candidate clusters
GET    /api/intel/rollup/sectors       # sector view
GET    /api/intel/rollup/org           # org/team view
GET    /api/intel/rollup/network       # NTN/5G/ground-station/GCP view
POST   /api/intel/profiles/{id}/export # to MISP/OpenCTI (reuse L4) or PDF brief
POST   /api/intel/profiles/{id}/feedback # analyst rates assessment (extends feedback table)
GET    /api/intel/status               # last run, next run, per-agent health
```
All gated by existing RBAC (`analyst` read, `admin` for run/export). All logged by existing audit middleware.

---

## 8. Dashboard (`app/templates/index.html`)

- New **Profiling** nav tab (the SPA already has the tab/polling infrastructure).
- **Profiles list:** severity/confidence-ranked cards. Card header shows assessed identity, a hedged APT line ("possible association: …"), severity + confidence badges.
- **Expanded card:** intent, TTP pills (ATT&CK ids), targeted surface-zone chips, targeted segments, the evidence chain (each item links to its source URL or to the linked scans), and Claude's prose summary.
- **Three rollup panels:** sector pressure, org/team targeting, network-surface activity.
- **Export PDF** reuses the existing `buildPrintHTML` pattern.
- **Reuses** the existing panel-survives-re-render trick and the `data-*`-attribute onclick pattern (not inline `JSON.stringify`) — both documented gotchas in the project journal.
- Privacy: renders metadata/scores/IoCs/intel only; no raw bodies (consistent with existing privacy hardening).

---

## 9. Concurrency, performance, cost

- **Parallelism:** agents per cluster via `asyncio.gather(..., return_exceptions=True)`; clusters processed with a bounded semaphore so a large backlog can't fan out unboundedly.
- **Caching:** Redis on every external fetch and every agent result (keyed on cluster signature) → repeat cycles are cheap and sources aren't hammered.
- **LLM cost:** profiler is the main spend. Mitigations: prompt caching on the system prompt; profiling batched on cadence (not per-email); skip re-profiling clusters whose signature/membership is unchanged since last run (dirty-flag).
- **Isolation from delivery path:** runs in a background thread / async task, reads scans asynchronously, never holds the SMTP path.

---

## 10. Failure modes & degradation

| Failure | Behavior |
|---|---|
| One agent times out/errors | `return_exceptions=True` isolates it; fusion engine builds the profile from remaining findings; logged |
| All external sources down | Fusion engine works from internal cluster evidence only; confidence capped at `moderate` |
| LLM profiler unavailable / unparseable | Fusion engine emits a deterministic `speculative` profile from corroborated claims; no free-text attribution |
| Scraper hits non-allowlisted host | Hard error in `fetcher.py`, logged; no fetch — by design, not recoverable via any client (Crawl4AI/Scrapling included) |
| Scrapling adaptive selector still fails | Agent returns `[]` for that source; source flagged for allowlist review; other sources unaffected |
| Redis down | Falls back to uncached fetches (slower); functionally intact |
| MISP/OpenCTI down | `misp_opencti_agent` returns `[]`; loses only `confirmed`-tier corroboration |
| Prompt-injection attempt in scraped text | Hardened at extraction (Scrapling `--ai-targeted`, Crawl4AI filter) and at the profiler (data-not-instructions framing); content cannot raise its own confidence |

---

## 11. Security, privacy, legal

- **Source legality enforced in code** via `fetcher.py` allowlist + robots + rate-limit; no code path performs authenticated access to leak markets or downloads stolen data. (PRD §6, NG3.)
- **No PII / no bodies stored** (NFR6). Exposure findings are signals, not records.
- **RBAC + audit** reuse existing Layer 6 mechanisms.
- **Attribution hedging** enforced in the profiler system prompt and in the UI copy. (NG2/G8.)
- **Outbound calls** are to OSINT/feeds only and are logged for provenance.

---

## 12. Testing strategy

- **Unit, no live network.** All agents are tested against mocked fetch/LLM responses (mirrors how `test_layer3` mocks the Docker SDK).
- `test_layer8_clusterer.py` — signature matching, incremental join, dormant flip, merge.
- `test_layer8_agents.py` — each agent's parsing, timeout isolation, cache hit/miss, graceful empty-on-error.
- `test_layer8_fusion.py` — **critical:** normalize/dedupe of multi-agent claims, independent-source counting, confidence-tier assignment invariants (e.g. no `confirmed` without a feed hit; LLM can lower but not raise the fusion-assigned tier), deterministic fallback path.
- `test_layer8_profiler.py` — JSON contract parsing, repair retry, attribution-hedge invariant, untrusted-input framing.
- `test_layer8_ttp_mapper.py` — ATT&CK dedup, surface-zone keyword mapping, evidence refs present.
- `test_layer8_rollup.py` — aggregation correctness.
- `test_layer8_scraper_guard.py` — **critical:** asserts a non-allowlisted host is refused through **every** scraper client (httpx, Crawl4AI, Scrapling) and robots is obeyed (the legal boundary has a test).
- Target: keep the suite green (current 186 passing) and add ~70–85 Layer-8 tests.

---

## 13. Configuration (env / files)

```
INTEL_ENABLED=false              # off by default; activate after Phase 1 verified green
INTEL_RUN_CADENCE=daily            # daily|hourly|on_campaign
INTEL_CLUSTER_SIM_THRESHOLD=0.72
INTEL_CLUSTER_DORMANT_DAYS=14
INTEL_AGENT_TIMEOUT_SECS=30
INTEL_MAX_CLUSTER_CONCURRENCY=4
INTEL_CACHE_TTL_SECS=86400
INTEL_ALLOWLIST_PATH=app/layer8_intel/scraper/allowlist.yaml
INTEL_SURFACE_TAXONOMY_PATH=app/layer8_intel/data/attack_surface.yaml
INTEL_ENABLED_AGENTS=osint,attack,misp,ioc,cve,compromise,telecom   # registry toggle

# Scraper stack
INTEL_SCRAPER_DEFAULT=crawl4ai     # crawl4ai|scrapling|httpx (per-source override in allowlist.yaml)
INTEL_SCRAPLING_AI_TARGETED=true   # prompt-injection hardening on scraped content
INTEL_CRAWL4AI_HEADLESS=true
INTEL_FETCH_RATE_PER_DOMAIN=6      # requests/min per source domain
INTEL_FETCH_TIMEOUT_SECS=20

# Monitored identifiers
INTEL_MONITORED_DOMAINS=skylo.tech,...   # Skylo + partner domains to watch in compromise intel
INTEL_MONITORED_SECTORS=maritime,logistics,mining,agriculture,automotive,telecom

# Free sources — no key, or free account. Left as-is; agents that need a free account read these.
ABUSECH_AUTH_KEY=                  # abuse.ch now requires a free account key
OTX_API_KEY=                       # AlienVault OTX free account
PULSEDIVE_API_KEY=                 # free tier
NVD_API_KEY=                       # optional; raises NVD rate limit
# ransomware.live, RansomLook, CISA KEV, EPSS, XposedOrNot — no key needed

# Optional commercial connectors — BLANK BY DEFAULT.
# With no key an agent reports `not_configured` and contributes nothing; the free path still runs.
HIBP_API_KEY=
DEHASHED_API_KEY=
SPYCLOUD_API_KEY=
RF_API_KEY=                        # Recorded Future
INTEL471_API_KEY=
FLARE_API_KEY=
CYBERSIXGILL_API_KEY=
SHODAN_API_KEY=
```

> **Key policy:** every credential above is optional. The system is fully functional on the free sources alone. Supplying a commercial key activates that connector with no code change (FR6b). No key is ever hardcoded; blanks are the default and are safe.

---

## 14. Migration / rollout

- Additive only: five new tables (`actor_clusters`, `actor_profiles`, `intel_sources`, `ttp_observations`, `org_threat_assessment`) created on startup via `CREATE TABLE IF NOT EXISTS`. No changes to existing tables.
- Behind `INTEL_ENABLED`. Off → zero impact on the running gateway.
- Rollout follows the PRD slices; each slice ships independently and is testable on the existing scan corpus.

---

## 15. Build sequence

The detailed phase-by-phase build plan — tasks, full given/when/then test cases, and exit criteria for each of the five phases — now lives in **PRD §11 (Phasing) and §12 (Implementation & test plan)**, which is the single source of truth for sequencing. The mapping of phases to the files in §4 is:

1. **Phase 1 (Foundation):** `config.py`, `models.py`, `store.py` (+ all four tables), `actor_clusterer.py`. *(Needs `campaign_detector.py`, `storage.py`, `pipeline.py` from you.)*
2. **Phase 2 (Vertical slice):** `base_agent.py` + `registry.py`, `scraper/fetcher.py` + `crawl4ai_client.py` + `scrapling_client.py`, `osint_report_agent.py`, `attack_mapper_agent.py`, `fusion_engine.py`, `profiler.py`, minimal `orchestrator.run_cycle`, one dashboard card.
3. **Phase 3 (Breadth):** `misp_opencti_agent.py`, `cve_agent.py`, `exposure_agent.py`, `telecom_ntn_agent.py`, `text_extract.py`/`discovery.py`, `ttp_mapper.py`.
4. **Phase 4 (Product):** `sector_rollup.py`, full Profiling tab, exports, scheduler + API.
5. **Phase 5 (Hardening):** caching/rate-limit tuning, fusion confidence-weighting tuning, audit polish, retention, docs (RUNBOOK + reconstruction-prompt update).

---

## 16. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Over-attribution erodes analyst trust | Confidence scale + hedged copy + fallback never attributes |
| LLM cost grows with cluster count | Prompt caching, dirty-flag skip, cadence batching, bounded concurrency |
| Scraper legal/politeness issues | Allowlist+robots+rate-limit enforced in one chokepoint, with a test |
| Clustering too coarse/fine | `INTEL_CLUSTER_SIM_THRESHOLD` tunable; analyst feedback loop |
| Scope creep into raw leak data | Hard product boundary (PRD §6) + no code path exists for it |

---

## 17. Open engineering questions (mirror PRD §13)

- "D4Vinci" resolved → **Scrapling**; stack is Crawl4AI + Scrapling + httpx/trafilatura (+ optional Katana). Any specific day-one allowlist sources?
- Whether profiles may feed the denylist later (currently read-only).
- Retention policy for profiles/intel snapshots.
- **Code I need from you to finalize Phase 1:** `app/pipeline.py`, `app/layer4_soar/campaign_detector.py`, `app/storage.py`.
