#!/usr/bin/env bash
# watch_and_update.sh
# Wait for the TDSC experiment (PID $1) to finish, then update paper numbers.

set -euo pipefail

PID=${1:-89023}
REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$REPO/results/tdsc_full_v2_watch.log"

echo "[$(date)] Watching PID $PID for experiment completion..." | tee -a "$LOG"

# Poll every 60 seconds
while kill -0 "$PID" 2>/dev/null; do
    sleep 60
done

echo "[$(date)] PID $PID has exited. Checking for results..." | tee -a "$LOG"

REPORT="$REPO/results/tdsc_full_v2/tdsc_report.json"
ALL_RESULTS="$REPO/results/tdsc_full_v2/all_results.json"

# Give the process a moment to flush writes
sleep 5

if [[ -f "$REPORT" ]]; then
    echo "[$(date)] Found $REPORT — running paper update." | tee -a "$LOG"
    cd "$REPO"
    source .venv/bin/activate 2>/dev/null || true
    python scripts/update_paper_numbers.py 2>&1 | tee -a "$LOG"
    echo "[$(date)] Paper update complete." | tee -a "$LOG"
elif [[ -f "$ALL_RESULTS" ]]; then
    echo "[$(date)] No tdsc_report.json; computing stats from all_results.json..." | tee -a "$LOG"

    # Generate the report from raw results
    cd "$REPO"
    source .venv/bin/activate 2>/dev/null || true
    python - <<'PYEOF' 2>&1 | tee -a "$LOG"
import json, math
from pathlib import Path

REPO = Path(".")
raw = json.loads((REPO / "results/tdsc_full_v2/all_results.json").read_text())

def wilson_ci(k, n, z=1.96):
    if n == 0: return 0.0
    p = k / n
    denom = 1 + z**2 / n
    margin = z * math.sqrt(p*(1-p)/n + z**2/(4*n**2)) / denom
    return round(margin * 100, 2)

systems = {}
cat_data = {}
for row in raw:
    s = row["system"]
    cat = row.get("scenario_category", "unknown")
    if s not in systems:
        systems[s] = {"attack": {"n":0,"k":0}, "benign": {"n":0,"k":0}}
    if row["scenario_type"] == "attack":
        systems[s]["attack"]["n"] += 1
        systems[s]["attack"]["k"] += int(row.get("attack_success", False))
        key = f"{s}__{cat}"
        cat_data.setdefault(key, {"n":0,"k":0})
        cat_data[key]["n"] += 1
        cat_data[key]["k"] += int(row.get("attack_success", False))
    else:
        systems[s]["benign"]["n"] += 1
        systems[s]["benign"]["k"] += int(not row.get("blocked", False))

agg = {}
for sname, d in systems.items():
    n_a, k_a = d["attack"]["n"], d["attack"]["k"]
    n_b, k_b = d["benign"]["n"], d["benign"]["k"]
    asr = round(k_a / max(n_a,1) * 100, 4)
    tsr = round(k_b / max(n_b,1) * 100, 4)
    agg[sname] = {
        "asr_ia_mean": asr, "asr_ia_ci_half": wilson_ci(k_a, n_a),
        "tsr_mean": tsr, "tsr_ci_half": wilson_ci(k_b, n_b),
        "n_attack": n_a, "n_benign": n_b,
    }
    print(f"  {sname}: ASR-IA={asr:.2f}% ±{wilson_ci(k_a,n_a):.1f}  TSR={tsr:.2f}% ±{wilson_ci(k_b,n_b):.1f}")

# Per-category for provsafe
per_cat = {}
for key, d in cat_data.items():
    sname, cat = key.split("__", 1)
    if sname != "provsafe": continue
    n, k = d["n"], d["k"]
    per_cat[cat] = {
        "asr_ia_mean": round(k/max(n,1)*100, 4),
        "asr_ia_ci_half": wilson_ci(k, n),
        "n": n,
    }

report = {"aggregate": agg, "per_category": per_cat}
out = REPO / "results/tdsc_full_v2/tdsc_report.json"
out.write_text(json.dumps(report, indent=2))
print(f"Report written to {out}")
PYEOF

    python scripts/update_paper_numbers.py 2>&1 | tee -a "$LOG"
    echo "[$(date)] Paper update complete." | tee -a "$LOG"
else
    echo "[$(date)] ERROR: neither $REPORT nor $ALL_RESULTS found. Manual check required." | tee -a "$LOG"
    exit 1
fi
