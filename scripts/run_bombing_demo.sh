#!/usr/bin/env bash
# Run the email-bombing demo in the container AND pull its incident report onto
# the host (your Mac) automatically — no manual `docker cp` needed.
#
# Usage:   bash scripts/run_bombing_demo.sh
#
# /app/data is a named Docker volume (not a host folder), so the container writes
# the report there and this wrapper copies the newest one into ./data/bombing_reports/
# on your Mac. That host folder is gitignored (reports are run artifacts).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
CONTAINER="phishguard-app"

echo "→ copying demo script into $CONTAINER ..."
docker cp scripts/demo_bombing_all_labels.py "$CONTAINER:/app/demo_bombing_all_labels.py" >/dev/null

echo "→ running email-bombing demo (delivers 34 emails, writes report) ..."
docker exec -w /app "$CONTAINER" python3 demo_bombing_all_labels.py

echo "→ pulling the report onto your Mac ..."
mkdir -p data/bombing_reports
LATEST="$(docker exec -w /app "$CONTAINER" sh -c 'ls -t data/bombing_reports/*.json 2>/dev/null | head -1' || true)"
if [ -n "$LATEST" ]; then
  BASE="$(basename "$LATEST")"
  docker cp "$CONTAINER:/app/$LATEST" "data/bombing_reports/$BASE" >/dev/null
  echo ""
  echo "✓ Report saved on your Mac:"
  echo "    $REPO/data/bombing_reports/$BASE"
else
  echo "⚠ No report file found in the container (did the demo finish?)."
fi

# tidy the temp copy inside the container
docker exec --user root "$CONTAINER" rm -f /app/demo_bombing_all_labels.py >/dev/null 2>&1 || true
