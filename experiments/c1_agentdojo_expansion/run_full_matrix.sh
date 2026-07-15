#!/usr/bin/env bash
# C1: AgentDojo full-matrix expansion
#
# Single invocation of run_agentdojo.py over:
#   --suite   workspace slack banking travel
#   --attack  important_instructions direct ignore_previous injecagent tool_knowledge
#   --defense no_defense provsafe
#   --model   gpt-4o-mini
#
# The runner has built-in checkpointing (--resume) and AgentDojo log cache,
# so re-running is idempotent.
#
# Estimated cost (GPT-4o-mini): ~$15-30, ~4-6 hours wallclock.
# Output: results/agentdojo_full_matrix/

set -euo pipefail

if [ ! -f "evaluation/run_agentdojo.py" ]; then
  echo "ERROR: must run from repo root (where evaluation/run_agentdojo.py exists)" >&2
  exit 1
fi

if [ -f "evaluation/.env" ]; then
  set -a; source evaluation/.env; set +a
fi
if [ -z "${OPENAI_API_KEY:-}" ]; then
  echo "ERROR: OPENAI_API_KEY not set. Source evaluation/.env first." >&2
  exit 1
fi

OUT="results/agentdojo_full_matrix"
mkdir -p "$OUT"
LOG="$OUT/run.log"

echo "=== AgentDojo full matrix run started $(date -u +%FT%TZ) ===" | tee -a "$LOG"

python evaluation/run_agentdojo.py \
  --suite workspace slack banking travel \
  --attack important_instructions direct ignore_previous injecagent tool_knowledge \
  --defense no_defense provsafe \
  --model gpt-4o-mini \
  --output "$OUT" \
  --resume \
  2>&1 | tee -a "$LOG"

echo "=== Done $(date -u +%FT%TZ) ===" | tee -a "$LOG"
echo "Aggregate with: python experiments/c1_agentdojo_expansion/aggregate.py $OUT"
