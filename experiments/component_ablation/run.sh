#!/usr/bin/env bash
# Component ablation: substring-only vs +embedding vs +fallback (full PROVSAFE)
#
# Existing data:
#   results/full_212/  -> provsafe FULL (Stage 1 + 2 + 3 fail-closed)
#
# New runs (this script):
#   results/ablation_substring_only/  -> Stage 1 only, Stage 3 fail-OPEN
#   results/ablation_subembed/        -> Stage 1+2, Stage 3 fail-OPEN
#
# Scoping: 4 local models × 212 scenarios × 5 reps × 1 system (provsafe) per ablation.
# Total: 4,240 trials × 2 ablations = 8,480 new trials.
# Estimated: ~6-10 hours wallclock with model swaps.
#
# Smaller cell first: phi-3.5-mini only (fastest model) — 1,060 trials per ablation.

set -euo pipefail
if [ ! -f "evaluation/run_experiments.py" ]; then
  echo "ERROR: run from repo root" >&2
  exit 1
fi

# Models - either all 4 or just phi-3.5-mini for the smaller cell
if [ "${1:-}" = "single" ]; then
  MODEL_ARG="--model phi-3.5-mini-instruct"
  TAG="single"
else
  MODEL_ARG=""
  TAG="full"
fi

# Substring-only ablation
echo "=== Ablation A: substring-only (Stage 1 only, Stage 3 fail-OPEN) ==="
PROVSAFE_EMBEDDING=0 PROVSAFE_CONSERVATIVE_DEFAULT=0 \
  python3 evaluation/run_experiments.py \
    --system provsafe $MODEL_ARG --reps 5 \
    --output "results/ablation_substring_only_${TAG}" \
    --resume

# Substring + embedding ablation (no fallback)
echo "=== Ablation B: substring + embedding (Stage 1+2, Stage 3 fail-OPEN) ==="
PROVSAFE_EMBEDDING=1 PROVSAFE_CONSERVATIVE_DEFAULT=0 \
  python3 evaluation/run_experiments.py \
    --system provsafe $MODEL_ARG --reps 5 \
    --output "results/ablation_subembed_${TAG}" \
    --resume

echo "=== Done. Aggregate with experiments/component_ablation/aggregate.py ==="
