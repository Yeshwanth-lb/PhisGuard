What the problem is

PhishGuard answers one question per email: is this phishing? It does that well. But after a wave of phishing hits, the SOC analyst asks: who is doing this, what do they want, and which part of our infrastructure are they targeting?

Answering that today requires manually pivoting between MISP, Google, VirusTotal, vendor blogs. ThreatLens automates the entire chain.

---
Architecture overview

scans table (existing)
    ↓
Actor Clusterer         ← groups emails by attacker
    ↓
11 parallel agents      ← each researches one intelligence source
    ↓
Fusion Engine           ← deduplicates, weights, assigns confidence
    ↓
Claude Profiler         ← synthesizes structured adversary profile
    ↓
Org Assessor            ← builds leadership-facing strategic picture
    ↓
Dashboard Profiling tab ← analyst-facing output

---
Stage 1 — Actor Clustering

File: app/threatlens/actor_clusterer.py

The pipeline already produces 1,445 individual scan records. Clustering groups them into candidate adversary clusters — the hypothesis that a set of emails came from the same actor.

The signature

Every email scan produces a 4-field fingerprint:
{
  "domain_base":  "payment-hub",   # normalized sender domain (year suffix stripped)
  "intent":       "bec_fraud",     # NLP intent from Layer 2
  "sender_ip":    "1.2.3.4",       # from L1 OSINT
  "asn":          "AS12345",       # network owner
}

payment-hub-2026.com, payment-hub-2027.com, payment-hub-2025.net all normalize to payment-hub. The year suffix stripping is inherited from campaign_detector.py.

Similarity scoring

Two scans are compared by a weighted sum:

domain_base match  → +0.40
intent match       → +0.35
shared sender IP   → +0.45   ← highest weight: shared infrastructure is strongest signal
shared ASN         → +0.30

score ≥ 0.72 → same cluster

The IP weight (0.45) is intentionally higher than domain (0.40). An attacker can register 10 new domains in an hour but their sending infrastructure (IP/ASN) takes effort to change.

Incremental refresh

Clusters are stored in SQLite with a last_profiled_at timestamp. The clusterer is additive — new scans join existing clusters without recomputing from scratch. A cluster not seen in 14 days flips to dormant.

Phase 5 dirty flag: A cluster is only re-profiled if updated_at > last_profiled_at. If no new scans arrived since the last profiling run, zero LLM calls are made for that cluster. Cost-controlled.

---
Stage 2 — The 11 Parallel Agents

Directory: app/threatlens/agents/

Each agent owns exactly one intelligence source and returns structured Finding objects with citations. All 11 fire simultaneously via asyncio.gather().

findings = await asyncio.gather(
    osint_agent.run(cluster),
    attack_mapper.run(cluster),
    misp_agent.run(cluster),
    ioc_agent.run(cluster),
    cve_agent.run(cluster),
    compromise_agent.run(cluster),
    telecom_agent.run(cluster),
    network_agent.run(cluster),
    greynoise_agent.run(cluster),
    urlscan_agent.run(cluster),
    darkweb_agent.run(cluster),
    return_exceptions=True
)

Every agent inherits from BaseAgent which enforces three guarantees:
1. Timeout isolation — asyncio.wait_for(timeout=30s) — slow agents don't block others
2. Exception isolation — any crash returns [], never propagates
3. TTL cache — same cluster + same agent + within 24h = returns cached result without network call

What each agent queries

┌─────────────────┬─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
│      Agent      │               Source                │                           Method                           │
├─────────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ OSINT Report    │ CISA, Unit42, SANS ISC              │ Crawl4AI scrapes advisory pages → Claude extracts findings │
├─────────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ ATT&CK Mapper   │ Local MITRE JSON                    │ Dictionary lookup: intent → technique IDs                  │
├─────────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ MISP/OpenCTI    │ Existing MISP feeds                 │ POST /attributes/restSearch on cluster IoCs                │
├─────────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ IoC Reputation  │ abuse.ch, OTX, Pulsedive            │ JSON API calls per domain/IP                               │
├─────────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ CVE Agent       │ NVD, CISA KEV, EPSS                 │ NVD keyword search filtered to NTN/5G/telecom              │
├─────────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ Compromise      │ ransomware.live, RansomLook         │ Clearnet APIs indexing ransomware .onion victim listings   │
│ Intel           │                                     │                                                            │
├─────────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ Telecom/NTN     │ NCSC UK, SANS ISC                   │ Crawl4AI scrapes → Claude extracts satellite/5G-specific   │
│                 │                                     │ findings                                                   │
├─────────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ Network Intel   │ Shodan InternetDB, BGPView          │ Free JSON APIs — open ports, ASN, network owner per IP     │
├─────────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ GreyNoise       │ GreyNoise community                 │ Is this IP a known scanner or a real attacker?             │
├─────────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ URLScan         │ urlscan.io                          │ Community scan verdicts for the cluster's domains          │
├─────────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ Dark Web        │ IntelligenceX, CIRCL PassiveDNS,    │ Dark web mentions + DNS history + exposed services         │
│                 │ LeakIX                              │                                                            │
└─────────────────┴─────────────────────────────────────┴────────────────────────────────────────────────────────────┘

Legal boundary enforcement

All web fetches go through scraper/fetcher.py — a single chokepoint that enforces:
1. Source allowlist (43 approved domains, YAML file)
2. robots.txt compliance
3. Per-domain rate limiting (token bucket, 6 req/min default)
4. Honest User-Agent

if host not in _allowed_hosts:
    raise DisallowedSourceError(...)  # zero network I/O

There is no bypass path — not even Crawl4AI or Scrapling can reach a non-allowlisted host. This is tested.

Scraper routing

Three tools, chosen per source based on preferred_client in allowlist.yaml:

Simple JSON API     → httpx (direct, no browser)
Static article page → trafilatura (boilerplate-stripped text)
JS-heavy page       → Crawl4AI (headless browser → Markdown)
Anti-bot source     → Scrapling (adaptive selectors, --ai-targeted mode)

Crawl4AI's BM25 filter keeps only the sections relevant to the cluster's intent — the token cost of sending a full advisory page to Claude is dramatically reduced.

Prompt injection hardening: BaseAgent.sanitize_text() strips injection markers from scraped content before it reaches any LLM. Scrapling's --ai-targeted mode further hardens content. The profiler system prompt explicitly tells Claude that agent-supplied text is data, never instructions.

---
Stage 3 — Fusion Engine

File: app/threatlens/fusion_engine.py

This is the most important stage. It's pure Python — no LLM. This is deliberate: confidence assignment must be testable and deterministic.

Pipeline

1. Normalize   → lowercase IoCs, strip whitespace, canonical ATT&CK IDs
2. Deduplicate → collapse identical claims from multiple agents into one
                 retain all contributing source refs
3. Corroborate → count INDEPENDENT sources per claim
4. Assign confidence (fixed rules, not AI)

Confidence rules (hard-coded, tested)

if finding.agent == "misp":                        → "confirmed"
elif independent_source_count >= 2:                → "high"
elif independent_source_count == 1:                → "moderate"
elif source_url is None:                           → "low"
else:                                              → "speculative"

Independence test: two findings from blog.unit42.com and unit42.paloaltonetworks.com share the root domain paloaltonetworks.com → count as 1 independent source, not 2.

The MISP rule is the only path to confirmed. No amount of OSINT agreement can reach confirmed. Only a hard IoC match in a trusted feed. This is enforced in Python and tested with 8 unit tests in test_threatlens_fusion.py.

---
Stage 4 — Claude Profiler

File: app/threatlens/profiler.py

Claude receives the fusion output — the weighted, corroborated, evidence-linked claim set — and writes structured JSON:

{
  "assessed_identity": "Unattributed Cluster",
  "suspected_apt": "possible association: FIN7",
  "assessed_intent": "BEC wire fraud via executive impersonation",
  "severity": "high",
  "confidence": "moderate",
  "ttps": [{"attack_id": "T1566", "tactic": "Initial Access"}, ...],
  "surface_zones": ["corporate_it"],
  "summary": "2-3 sentence hedged assessment"
}

Three invariants enforced in Python after parsing

1. Confidence clamping:
profile.confidence = min(claude_output.confidence, fusion_max_confidence)
Claude cannot raise the confidence the fusion engine assigned. It can only lower it.

2. Attribution hedging:
if suspected_apt and not suspected_apt.startswith("possible association:"):
    suspected_apt = f"possible association: {suspected_apt}"
Claude cannot assert "this is APT28". Only "possible association with APT28".

3. Parse failure fallback:
First attempt → parse JSON
Failure → one repair retry with the broken output
Second failure → deterministic fallback profile:
  - assessed_identity = "Unattributed Cluster"
  - confidence = "speculative"
  - suspected_apt = None
  - summary = templated text (no free-text attribution)
A profile is always produced. The system never fails to output something.

---
Stage 5 — Skylo Surface Zone Mapping

File: app/threatlens/ttp_mapper.py

After profiling, the TTP mapper assigns the cluster to Skylo's specific attack surface zones using keyword matching against data/attack_surface.yaml:

zones:
  - id: ground_station_ingress
    keywords: [earth station, ground station, teleport, gateway, baseband]
  - id: ntn_5g_core
    keywords: [5g core, ntn, vran, amf, smf, gtp, signaling]
  - id: gcp_infra
    keywords: [gcp, kubernetes, iam, service account, bucket]
  - id: supply_chain
    keywords: [mno, chipset, sim, esim, qualcomm, modem, ota firmware]
  - id: corporate_it
    keywords: [okta, vpn, email, credential, payroll, wire transfer]

If the cluster's findings, domains, or intent text contain any keyword → that zone is assigned. Multiple zones can be assigned per cluster. This mapping writes to the ttp_observations table for the network rollup queries.

---
Stage 6 — Org Assessor

File: app/threatlens/org_assessor.py

A separate Claude step that reads ALL active profiles + three rollups and writes one leadership-facing OrgThreatAssessment.

The system prompt is explicitly Skylo-contextualized — it tells Claude that Skylo operates ground stations, a 5G/NTN vRAN and core on GCP, MNO partnerships, and serves maritime/logistics/mining/agriculture. Without this context, Claude would produce generic enterprise threat assessment language instead of NTN operator language.

Same confidence discipline applies — the org assessment confidence cannot exceed the highest-confidence individual profile that fed it.

---
The numbers

┌────────────────────────────┬──────────────────────────────────────────┐
│           Metric           │                  Value                   │
├────────────────────────────┼──────────────────────────────────────────┤
│ Clusters from 1,445 scans  │ 126                                      │
├────────────────────────────┼──────────────────────────────────────────┤
│ Profiles generated         │ 126                                      │
├────────────────────────────┼──────────────────────────────────────────┤
│ TTP observations           │ 132                                      │
├────────────────────────────┼──────────────────────────────────────────┤
│ Confidence level           │ confirmed (MISP matches)                 │
├────────────────────────────┼──────────────────────────────────────────┤
│ Agents per cluster         │ 11, all parallel                         │
├────────────────────────────┼──────────────────────────────────────────┤
│ LLM calls per cycle        │ 1 per dirty cluster + 1 for org assessor │
├────────────────────────────┼──────────────────────────────────────────┤
│ Cycle cadence              │ daily (daemon thread)                    │
├────────────────────────────┼──────────────────────────────────────────┤
│ Unchanged clusters skipped │ 0 LLM calls                              │
├────────────────────────────┼──────────────────────────────────────────┤
│ Tests                      │ 90 across 5 phases                       │
└────────────────────────────┴──────────────────────────────────────────┘

✻ Cogitated for 1m 10s · 28 shells still running

※ recap: PhishGuard is a complete email security gateway with a threat intelligence layer called ThreatLens that profiles attacker clusters using 11 parallel intelligence agents. Next action: get the 4 remaining free API keys (IntelligenceX, LeakIX, GreyNoise, URLScan) to activate the dormant agents.

───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯
──────────────────