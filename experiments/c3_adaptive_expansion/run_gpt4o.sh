#!/usr/bin/env bash
# C3a: Adaptive adversary on GPT-4o-mini (currently only Llama-3.1-8B has been run)
#
# 50 attacks × 3 reps = 150 trials on GPT-4o-mini.
# Estimated cost: ~$5 in API calls.
# Output: results/adaptive_adversary_gpt4o/

set -euo pipefail
if [ ! -f "evaluation/adaptive_adversary.py" ]; then
  echo "ERROR: run from repo root" >&2
  exit 1
fi
if [ -f "evaluation/.env" ]; then
  set -a; source evaluation/.env; set +a
fi
if [ -z "${OPENAI_API_KEY:-}" ]; then
  echo "ERROR: OPENAI_API_KEY not set" >&2
  exit 1
fi

OUT="results/adaptive_adversary_gpt4o"
mkdir -p "$OUT"

# Existing adaptive_adversary.py default-runs Llama; we override to GPT-4o-mini.
# If that flag doesn't exist, you'll need to add --model support to the script.
python evaluation/adaptive_adversary.py \
  --model gpt-4o-mini \
  --reps 3 \
  --output "$OUT/results.json" \
  2>&1 | tee "$OUT/run.log"

echo "Done. Aggregate per-strategy results with:"
echo "  python -c 'import json; d=json.load(open(\"$OUT/results.json\")); print(d)'"
