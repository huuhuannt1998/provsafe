#!/bin/bash
# ============================================================================
# Comprehensive InjecAgent rerun — ALL 5 systems × 4 local models × 3 reps
# ============================================================================
#
# Uses --resume to skip completed trials so it's safe to run repeatedly.
#
# IMPORTANT: This replaces rerun_local.sh. Kill rerun_local.sh first:
#   kill <PID>
# Then run:
#   nohup bash run_all_injecagent_local.sh > results/injecagent_rerun.log 2>&1 &
#
# LM Studio must be running at localhost:1234.
# Models are requested by name — ensure LM Studio can auto-load them,
# or manually switch models when prompted in the log.
# ============================================================================

set -e

cd /Users/huanbui/Desktop/provsafe
source .venv/bin/activate
cd evaluation

LOCAL_MODELS=(
    "meta-llama-3.1-8b-instruct"
    "qwen2.5-7b-instruct"
    "gemma-2-9b-it"
    "phi-3.5-mini-instruct"
)

SYSTEMS=("no_defense" "pattern_filter" "policy_only" "taint_everything" "provsafe")

OUTPUT="../results/injecagent"

echo "============================================="
echo "InjecAgent Comprehensive Local Rerun"
echo "Models: ${LOCAL_MODELS[*]}"
echo "Systems: ${SYSTEMS[*]}"
echo "Reps: 3"
echo "Output: $OUTPUT"
echo "Started: $(date)"
echo "============================================="

for model in "${LOCAL_MODELS[@]}"; do
    echo ""
    echo "============================================="
    echo "=== MODEL: $model ==="
    echo "=== Time: $(date) ==="
    echo "============================================="

    for system in "${SYSTEMS[@]}"; do
        echo ""
        echo "--- $model / $system ($(date)) ---"
        python -u run_injecagent.py \
            --model "$model" \
            --system "$system" \
            --reps 3 \
            --output "$OUTPUT" \
            --resume
        echo "--- Done: $model / $system ($(date)) ---"
    done

    echo "=== Completed all systems for $model ==="
done

echo ""
echo "============================================="
echo "All local InjecAgent trials complete!"
echo "Finished: $(date)"
echo "============================================="
