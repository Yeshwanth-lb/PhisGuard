"""Rebuild ThreatLens clusters + profiles with the new intent-consolidation and naming.
Clears old clusters/profiles, re-clusters all scans, then re-profiles every cluster."""
import asyncio
import sqlite3
import time
from collections import Counter

from app.threatlens import actor_clusterer
from app.threatlens.orchestrator import run_cycle

DB = "data/phishguard.db"

c = sqlite3.connect(DB)
c.execute("DELETE FROM actor_clusters")
c.execute("DELETE FROM actor_profiles")
c.commit()
c.close()
print("cleared old clusters + profiles", flush=True)

t0 = time.time()
clusters = actor_clusterer.refresh()
print(f"clusters after refresh: {len(clusters)}  ({time.time()-t0:.1f}s)", flush=True)
print("cluster intents:", dict(Counter((cl.dominant_intent or '?') for cl in clusters)), flush=True)

t0 = time.time()
res = asyncio.run(run_cycle())
print(f"run_cycle done ({time.time()-t0:.1f}s): {res}", flush=True)
