#!/usr/bin/env bash
# watch_injecagent.sh
# Wait for InjecAgent experiment (PID $1) to finish, then fill paper placeholders.

set -euo pipefail

PID=${1:-39927}
REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$REPO/results/injecagent_watch.log"

echo "[$(date)] Watching InjecAgent PID $PID ..." | tee -a "$LOG"

while kill -0 "$PID" 2>/dev/null; do
    sleep 60
done

echo "[$(date)] PID $PID exited. Running paper update." | tee -a "$LOG"
sleep 5

cd "$REPO"
source .venv/bin/activate 2>/dev/null || true
python scripts/update_injecagent_numbers.py 2>&1 | tee -a "$LOG"
echo "[$(date)] InjecAgent paper update complete." | tee -a "$LOG"
