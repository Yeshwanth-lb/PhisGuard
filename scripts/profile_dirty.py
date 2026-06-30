"""Profile any remaining dirty ThreatLens clusters — loops run_cycle until none left."""
import asyncio
from app.threatlens import store
from app.threatlens.orchestrator import run_cycle

for i in range(8):
    dirty = store.get_dirty_clusters()
    if not dirty:
        print("all clusters profiled", flush=True)
        break
    print(f"iteration {i}: {len(dirty)} dirty -> profiling...", flush=True)
    res = asyncio.run(run_cycle())
    print(f"  result: {res}", flush=True)

print("profiles now:", len(store.get_profiles()), flush=True)
