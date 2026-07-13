# PhishGuard — Threat Intelligence & Adversary Profiling: Complete Technical Reference

> **Audience:** engineers, SOC analysts, or anyone recreating / extending this system.
> Everything in this document reflects the live build as of 2026-07-02.
> This is Layer 8 ("ThreatLens") of PhishGuard v1.5.

---

## 1. What is ThreatLens?

ThreatLens is an **offline, cadence-driven, read-only** subsystem that runs on top of the phishing detection pipeline. It does not sit in the email delivery path — it never blocks or modifies a verdict.

**What it does:**
- Clusters all detected phishing campaigns into **adversary actor profiles**
- Enriches each cluster using 11 parallel intelligence agents (OSINT, CVE feeds, Shodan, Pulsedive, geolocation, etc.)
- Maps actor behavior to MITRE ATT&CK techniques and Skylo's NTN attack-surface zones
- Synthesizes a human-readable **adversary profile** via LLM (Claude)
- Generates an **org-level threat assessment** explaining what Skylo's threat posture looks like right now
- Exports findings to a Neo4j graph for relationship visualization
- Surfaces everything in the dashboard's **Campaigns**, **Profiling**, and **ThreatLens** tabs

**What it does NOT do:**
- Block email delivery
- Mutate a verdict
- Scrape dark web or non-lawful sources
- Attribution beyond hedged confidence bands

---

## 2. Architecture overview

```
[phishguard-verdicts (ES)] + [scans table (SQLite)]
              │
              ▼
    [Actor Clusterer]                  ← groups scans into candidate actors
              │
              ▼
    [11 Enrichment Agents]             ← run in parallel per cluster
    (OSINT, CVE, Shodan, Pulsedive,
     geo, MISP, OpenCTI, behavioural,
     telecom-NTN, sector, kill-chain)
              │
              ▼
    [Fusion Engine]                    ← merges findings, resolves conflicts
              │
              ▼
    [LLM Profiler]                     ← Claude writes a structured AdversaryProfile
              │
              ├──→ [TTP Mapper]         ← maps to ATT&CK + Skylo surface zones
              │
              ├──→ [Org Assessor]       ← LLM generates org-level threat assessment
              │
              ├──→ [Neo4j Writer]       ← writes relationship graph
              │
              └──→ [Sector Rollup]      ← industry vertical exposure summary
                        │
                        ▼
              [Dashboard API + UI]      ← /api/intel/* endpoints
```

---

## 3. Actor Clusterer

**File:** `app/threatlens/actor_clusterer.py`

Takes all phishing scan records from the database and groups them into candidate adversary clusters using a **composite signature**.

### Composite signature fields (with weights)
```python
_W_SENDER_DOMAIN = 0.20   # same sending domain → same actor
_W_SENDER_IP     = 0.15   # same sending IP
_W_INTENT        = 0.75   # HIGHEST WEIGHT — same inferred intent (credential harvest, BEC, etc.)
_W_TTP           = 0.30   # similar ATT&CK technique pattern
_W_TARGET        = 0.20   # same target segment/sector
_W_TIMING        = 0.10   # temporal proximity
```

**Why intent gets the highest weight (0.75):**
Sophisticated actors rotate infrastructure constantly — different IPs, different domains, fresh registrations. But the *attack pattern* (what they're trying to do: credential harvesting vs. BEC vs. supply-chain attack) is consistent. Clustering on intent catches actor pivots that infrastructure-only clustering misses.

### Cluster fields (stored in SQLite `actor_clusters` table)
```python
class ActorCluster:
    id: str                    # UUID
    dominant_intent: str       # "credential_harvesting", "bec", etc.
    iocs: ClusterIOCs          # domains, IPs, URLs, hashes
    targets: dict              # recipients, segments
    campaign_count: int        # number of phishing scans in cluster
    first_seen: float          # earliest scan timestamp
    last_seen: float           # latest scan timestamp
    confidence: float          # clustering confidence
    surface_zones: list[str]   # Skylo NTN zones this cluster targets
    segments: list[str]        # industry verticals
```

---

## 4. The 11 Enrichment Agents

**Directory:** `app/threatlens/agents/`

All 11 agents run in **parallel** per cluster via `asyncio.gather`. Each agent is independent — if one fails, the others continue. Each writes its findings to the `intel_sources` table.

| Agent | File | What it does |
|---|---|---|
| **OSINT** | `osint_agent.py` | Queries VirusTotal, URLhaus, AbuseIPDB for IOC reputation |
| **CVE** | `cve_agent.py` | Searches NVD for CVEs matching the cluster's tech stack (ground station, GCP, modem firmware) |
| **Shodan** | `shodan_agent.py` | Looks up cluster IPs in Shodan for exposed ports, services, banners |
| **Pulsedive** | `pulsedive_agent.py` | Queries Pulsedive threat intel for risk score, tags, linked campaigns |
| **Geolocation** | `geo_agent.py` | Resolves IPs to country/ASN/org; flags hosting in high-risk ASNs |
| **MISP** | `misp_agent.py` | Searches MISP for matching IOCs, event correlations |
| **OpenCTI** | `opencti_agent.py` | Queries OpenCTI for related observables and indicators |
| **Behavioral** | `behavioral_agent.py` | Analyzes timing patterns, velocity, target spread |
| **Telecom-NTN** | `telecom_ntn_agent.py` | Specialist agent: looks for telecom/satellite/ground-station specific threats |
| **Sector** | `sector_agent.py` | Maps targets to Skylo's customer industry segments |
| **Kill-chain** | `killchain_agent.py` | Maps observed TTPs to kill-chain stage (recon → weaponize → deliver → exploit) |

### Intel source record (stored in SQLite `intel_sources` table)
```python
{
    "cluster_id": "uuid",
    "agent": "shodan",
    "source_url": "https://shodan.io/host/...",
    "source_title": "Shodan — Open ports on 185.220.x.x",
    "finding_json": '{"claim": "Port 443 open, hosting nginx/1.14", "confidence": 0.8}',
    "confidence": 0.8
}
```

### Why the UI was showing "no data" (fixed in this session)
The original `/api/intel/profiles/{id}` endpoint only returned `profile.evidence`, where all entries were tagged `agent="profiler"` (the LLM synthesis step). The actual agent findings were in `intel_sources`, never returned.

**Fix (in `app/main.py`):**
```python
agent_findings = []
for s in tl_store.get_intel_sources(profile.cluster_id):
    fj = json.loads(s.get("finding_json") or "{}")
    agent_findings.append({
        "agent":        s.get("agent"),
        "claim":        fj.get("claim", "") or s.get("source_title", ""),
        "source_url":   s.get("source_url"),
        "source_title": s.get("source_title"),
        "confidence":   s.get("confidence"),
    })
# returned in the profile dict as "agent_findings"
```

**UI fix (in `app/templates/index.html`):**
```javascript
const byAgent = {};
const _af = (p.agent_findings && p.agent_findings.length)
    ? p.agent_findings
    : (p.evidence || []);  // fallback for older profiles
_af.forEach(e => {
    if (!byAgent[e.agent]) byAgent[e.agent] = [];
    byAgent[e.agent].push(e);
});
```

---

## 5. Fusion Engine

**File:** `app/threatlens/fusion_engine.py`

After all 11 agents complete, the fusion engine:
1. **Deduplicates** findings across agents (same IP reported by OSINT and Shodan → one record)
2. **Resolves conflicts** (different confidence scores for the same IOC → weighted average)
3. **Aggregates** into a structured `FusedProfile` dict passed to the LLM profiler

---

## 6. LLM Profiler

**File:** `app/threatlens/profiler.py`

Takes the fused findings and calls Claude to synthesize a structured `AdversaryProfile` JSON.

### System prompt (key context given to the LLM)
```
You are a threat intelligence analyst for Skylo, an NTN satellite connectivity company.
Skylo infrastructure: ground stations, 5G core on GCP, MNO partners, critical industries.
SKYLO SURFACE ZONES TARGETED: <zones>
...
Produce a structured JSON AdversaryProfile with exactly these fields: ...
```

### Output schema (AdversaryProfile)
```python
class AdversaryProfile:
    cluster_id: str
    actor_label: str           # e.g. "UNC-SAT-421 (suspected)"
    confidence: float          # attribution confidence
    dominant_intent: str       # "credential_harvesting", "bec", "supply_chain", etc.
    sophistication: str        # "low", "medium", "high", "nation_state"
    ttps: list[TTP]            # MITRE ATT&CK techniques observed
    surface_zones: list[str]   # Skylo attack surface zones targeted
    segments: list[str]        # industry verticals targeted
    narrative: str             # human-readable summary
    evidence: list[Evidence]   # supporting evidence items (tagged agent="profiler")
    iocs: ClusterIOCs          # domains, IPs, URLs
    first_seen: float
    last_seen: float
    assessment_confidence: str # LOW / MEDIUM / HIGH
```

### Repair-retry pattern (critical fix applied this session)
The LLM sometimes returns truncated JSON. The profiler implements a repair loop:
```python
raw = await llm.complete(system_prompt, user_prompt, max_tokens=2000)
profile = _parse(raw)
if not profile and raw:
    # First attempt was truncated — ask LLM to repair it
    raw2 = await llm.complete(system, _REPAIR_PROMPT + raw, max_tokens=2000)
    profile = _parse(raw2)
```

This pattern is also implemented in the org assessor (`app/threatlens/org_assessor.py`), which was generating empty assessments before this fix was applied.

---

## 7. TTP Mapper

**File:** `app/threatlens/ttp_mapper.py`

Maps cluster + findings text to:
1. **MITRE ATT&CK techniques** — extracted from agent findings by `attack_id` (e.g. `T1566.001`)
2. **Skylo NTN attack-surface zones** — keyword matching against `app/threatlens/data/attack_surface.yaml`

### Attack surface taxonomy (`attack_surface.yaml`)

**Five zones:**

| Zone ID | Label | Key keywords |
|---|---|---|
| `ground_station_ingress` | Ground-station ingress | earth station, ground station, teleport, gateway, baseband, antenna, uplink, downlink, feeder link, gnss, jamming, vsat, interference, spectrum |
| `ntn_5g_core` | NTN / 5G signaling & core | 5g core, ntn, vran, amf, smf, gtp, 3gpp, signaling, upf, ausf, udm, ngap, nas, bearer, network slice, handover |
| `gcp_infra` | Cloud (GCP) infrastructure | gcp, google cloud, kubernetes, k8s, iam, service account, bucket, gke, pubsub, bigquery, terraform, helm, kms, vpc |
| `supply_chain` | MNO / chipset / supply chain | mno, carrier, chipset, esim, qualcomm, modem, ota firmware, mediatek, sierra wireless, euicc, imsi, plmn, roaming, fota, hsm |
| `corporate_it` | Corporate / IT / identity | okta, vpn, email, credential, payroll, wire transfer, helpdesk, active directory, sso, saml, bec, github, api key, rdp, cve, zero trust |

**Industry segments:**
`agriculture`, `maritime`, `logistics`, `mining`, `automotive`, `consumer_wearables`, `telecom`, `energy`, `defense`, `aviation`, `enterprise_iot`

**Keyword matching is deterministic** — if a keyword appears in the cluster's IOCs, dominant_intent, or any agent finding, the zone is matched. No ML, no guessing.

---

## 8. Org Assessor

**File:** `app/threatlens/org_assessor.py`

Runs after profiling completes. Generates a single **org-level threat assessment** summarizing:
- How many actor clusters are active
- Which Skylo zones are under the most pressure
- What the highest-confidence actor is doing
- Overall threat posture (LOW / ELEVATED / HIGH / CRITICAL)

**Critical fix applied this session:** Original `max_tokens=1000` was truncating the JSON response mid-string → silent fallback to a speculative template → empty assessment on the dashboard.

**Fix:** Bumped `max_tokens` to 2000 + added repair-retry (same pattern as profiler):
```python
raw = await llm.complete(_SYSTEM_PROMPT, user_prompt, max_tokens=2000)
assessment = _parse(raw, profiles, max_conf, llm.model, db_path)
if not assessment and raw:
    logger.warning("org_assessor_parse_failed_attempting_repair")
    raw2 = await llm.complete(_SYSTEM_PROMPT, _REPAIR_PROMPT + raw, max_tokens=2000)
    assessment = _parse(raw2, profiles, max_conf, llm.model, db_path)
```

The org assessment is surfaced in the dashboard's ThreatLens tab as the top-level card.

---

## 9. Neo4j Graph Writer

**File:** `app/threatlens/neo4j_writer.py`

Writes the adversary relationship graph to Neo4j for visualization:
- Nodes: `ActorCluster`, `Domain`, `IP`, `URL`, `TTP`, `SurfaceZone`, `Segment`
- Edges: `USES_DOMAIN`, `SENDS_FROM`, `TARGETS_ZONE`, `EMPLOYS_TTP`, `TARGETS_SEGMENT`

Access via Neo4j Browser: `http://localhost:7474` (user: `neo4j`, password: in `.env`).

The dashboard's **Graph tab** renders a subset of this via `/api/intel/graph` (D3.js force-directed layout).

---

## 10. Sector Rollup

**File:** `app/threatlens/sector_rollup.py`

Aggregates all profiles into a per-sector exposure summary:
- Which industry segments appear most in actor targets
- Which actor has the highest targeting confidence per segment

Surfaced via `/api/intel/rollup/sectors`.

---

## 11. The scheduler

**File:** `app/threatlens/scheduler.py`

Runs as a daemon thread (started at app boot). Cadence: every N minutes (configurable).

Each cycle:
1. Reads all phishing scans from SQLite
2. Runs the actor clusterer
3. For each new/updated cluster: runs all 11 agents in parallel
4. Runs fusion engine + LLM profiler
5. Runs TTP mapper + org assessor + sector rollup
6. Writes to Neo4j

The scheduler is the only thing that calls enrichment — the API is read-only.

---

## 12. Seeding real IOCs for enrichment (what was done this session)

Out of the box, ThreatLens clusters only demo/synthetic phishing emails — which have no real C2 infrastructure, so Shodan/Pulsedive return no data.

**To get real enrichment data in demo clusters:**
1. Pull real malware C2 IPs from the Feodo Tracker (public, lawful source): `https://feodotracker.abuse.ch/downloads/ipblocklist.json`
2. Pick 5 IPs with known malware families (Emotet, QakBot, etc.)
3. Insert fake scan records into the SQLite `scans` table that reference these IPs as `sender_ip`
4. Trigger a ThreatLens enrichment cycle

**Script used:** `scripts/rebuild_threatlens.py` (with Feodo IPs hardcoded from a fresh pull)

**Result:** Clusters named after real malware families (Emotet/QakBot) now have real Shodan banners, Pulsedive risk scores, and geolocation data — making the enrichment cards meaningful for demo.

**Baseline timestamp captured before seeding:** `1782817312.139368` — this can be used to revert by deleting all `intel_sources` records with `scraped_at > baseline`.

---

## 13. Database schema (SQLite — key tables)

**File:** `app/threatlens/store.py`

```sql
actor_clusters (
    id TEXT PRIMARY KEY,
    dominant_intent TEXT,
    iocs_json TEXT,           -- ClusterIOCs serialized
    targets_json TEXT,
    campaign_count INTEGER,
    first_seen REAL,
    last_seen REAL,
    confidence REAL,
    surface_zones_json TEXT,
    segments_json TEXT
)

adversary_profiles (
    id TEXT PRIMARY KEY,
    cluster_id TEXT,
    actor_label TEXT,
    confidence REAL,
    dominant_intent TEXT,
    sophistication TEXT,
    narrative TEXT,
    evidence_json TEXT,       -- list of Evidence items, all tagged agent="profiler"
    ttps_json TEXT,
    surface_zones_json TEXT,
    segments_json TEXT,
    assessment_confidence TEXT,
    created_at REAL,
    updated_at REAL
)

intel_sources (
    id TEXT PRIMARY KEY,
    cluster_id TEXT,
    agent TEXT,               -- which of the 11 agents wrote this
    source_url TEXT,
    source_title TEXT,
    finding_json TEXT,        -- {"claim": "...", "confidence": 0.8, ...}
    confidence REAL,
    scraped_at REAL
)

ttp_observations (
    id TEXT PRIMARY KEY,
    cluster_id TEXT,
    attack_id TEXT,           -- e.g. "T1566.001"
    tactic TEXT,
    surface_zone TEXT,
    evidence_ref TEXT,
    observed_at REAL
)
```

---

## 14. API endpoints

**Base:** `http://localhost:8000/api/intel/`

| Endpoint | Method | Returns |
|---|---|---|
| `/api/intel/profiles` | GET | All adversary profiles (paginated) |
| `/api/intel/profiles/{id}` | GET | Single profile + `agent_findings` (11-agent data) |
| `/api/intel/assessment` | GET | Org-level threat assessment |
| `/api/intel/graph` | GET | Neo4j relationship graph (nodes + edges for D3) |
| `/api/intel/rollup/sectors` | GET | Per-sector exposure summary |
| `/api/intel/rollup/network` | GET | Network-layer enrichment rollup |
| `/api/intel/rollup/org` | GET | Org-level rollup (zones + segments) |
| `/api/intel/run` | POST | Trigger a manual enrichment cycle |
| `/api/intel/assessment/export` | POST | Export org assessment to MISP/OpenCTI |
| `/api/campaigns` | GET | All detected phishing campaigns |

All endpoints require Bearer token (`Authorization: Bearer <token>`). Get a token via `POST /token` with the API key.

---

## 15. Dashboard tabs

### Campaigns tab (`/api/campaigns`)
Shows detected phishing campaign groups — raw clustering output before LLM synthesis. Each card shows: campaign intent, IOC count, first/last seen, confidence. This is the input side of ThreatLens.

### Profiling tab (`/api/intel/profiles`)
Shows fully synthesized `AdversaryProfile` records — one per cluster. Each card shows: actor label, sophistication, ATT&CK techniques, surface zones, narrative summary, and the 11 enrichment agent findings (the "no data" fix was specifically for this).

**Currently 7 profiles** because only 7 clusters have been enriched. The count grows as more phishing emails arrive and the scheduler cycles.

### ThreatLens tab
Shows:
- **Org assessment** — top-level summary card (generated by org_assessor)
- **Zone pressure** — bar chart of which Skylo surface zones have the most actor activity
- **Sector exposure** — which customer segments are most targeted
- **Graph** — D3 force-directed graph of actor → domain → IP → zone relationships

---

## 16. Source allowlist (legal boundary)

**File:** `app/threatlens/scraper/feeds_client.py`

All external data fetches go through a source allowlist. Unlisted URLs are blocked in code. This enforces the "lawful sources only" design principle.

Current allowlist includes:
- `feodotracker.abuse.ch` — Feodo Tracker malware C2 list
- `api.virustotal.com`
- `api.abuseipdb.com`
- `urlhaus-api.abuse.ch`
- `api.pulsedive.com`
- `api.shodan.io`
- `nvd.nist.gov` — CVE database
- `ip-api.com` — geolocation

No dark web, no data exfiltration paths, no scrapers outside this list.

---

## 17. Known limitations

**Demo clusters are synthetic:** Without real inbound mail hitting the SMTP gateway, clusters are built from demo emails to fake senders. The Feodo Tracker seeding provides real C2 infrastructure data but the cluster itself is still based on synthetic emails.

**7 profiles only:** The number of profiles equals the number of clusters that have been through a full enrichment cycle. As more real phishing emails arrive, this grows automatically.

**Org assessment empty (was a bug, now fixed):** The `max_tokens=1000` truncation bug caused silent fallback to a placeholder template. Fixed by bumping to 2000 + repair-retry.

**Scheduler interval:** Currently set to a short interval for demo. In production, consider running enrichment every 30–60 minutes to avoid hitting API rate limits on VirusTotal/Shodan.

**Neo4j graph sparse:** With synthetic demo data, few real relationship edges exist. The graph becomes meaningful when real phishing campaigns (with shared infrastructure) are clustered.

---

## 18. For management — one paragraph

> *"ThreatLens transforms PhishGuard from a mail filter into a threat intelligence platform. Every phishing email that the system catches is not just blocked — it is analysed for what it reveals about the attacker. The system automatically groups detected attacks by actor: campaigns sharing the same intent, infrastructure, or targeting pattern are clustered together as a single adversary. For each actor cluster, eleven intelligence agents run in parallel: checking the sending IPs against Shodan for exposed services, querying threat databases like Pulsedive and VirusTotal for reputation history, mapping the attack to MITRE ATT&CK techniques, and determining which part of Skylo's infrastructure — ground stations, 5G core, cloud infrastructure, supply chain, or corporate IT — the actor appears to be targeting. These findings are synthesized by an AI analyst into a structured adversary profile and an organisation-wide threat assessment. The result is a SOC capability: instead of reacting to each email, security teams can see campaigns as campaigns — track an actor across multiple attacks, understand their sophistication level, and brief leadership on which business areas are under the most pressure."*
