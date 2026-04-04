#!/bin/bash
# run_overnight.sh — Complete overnight experiment suite
# Runs all pending experiments on 4 local models via LM Studio
# Loads/unloads models one at a time to stay within 24 GB RAM
#
# Usage: cd evaluation && bash run_overnight.sh
# Estimated: ~20 hours total
#
# Part 1: Taint-everything × 4 models (212 scenarios × 5 reps)    ~12 hrs
# Part 2: All 5 systems × 4 models on 12 new NL scenarios (5 reps) ~4 hrs
# Part 3: InjecAgent taint-everything × 4 models (1,054 × 3 reps)  ~4 hrs

set -euo pipefail

MODELS=(
    "meta-llama-3.1-8b-instruct"
    "qwen2.5-7b-instruct"
    "gemma-2-9b-it"
    "phi-3.5-mini-instruct"
)

ALL_SYSTEMS=("no_defense" "pattern_filter" "policy_only" "taint_everything" "provsafe")

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="/Users/huanbui/Desktop/provsafe/.venv/bin/python"
RESULTS="/Users/huanbui/Desktop/provsafe/results"
LOG="$RESULTS/overnight.log"

mkdir -p "$RESULTS"

echo "========================================" | tee -a "$LOG"
echo "PROVSAFE Overnight Experiment Suite" | tee -a "$LOG"
echo "Started: $(date)" | tee -a "$LOG"
echo "Models: ${MODELS[*]}" | tee -a "$LOG"
echo "========================================" | tee -a "$LOG"

# Unload all models first
echo "[$(date)] Unloading all models..." | tee -a "$LOG"
lms unload --all 2>/dev/null || true
sleep 5

# ── Part 1: Taint-everything on full 212-scenario benchmark ─────────────────
TAINT_OUTPUT="$RESULTS/taint_everything_local"
mkdir -p "$TAINT_OUTPUT"

echo "" | tee -a "$LOG"
echo "========================================" | tee -a "$LOG"
echo "PART 1: Taint-Everything × 4 models (212 scenarios × 5 reps)" | tee -a "$LOG"
echo "========================================" | tee -a "$LOG"

for MODEL in "${MODELS[@]}"; do
    echo "" | tee -a "$LOG"
    echo "[$(date)] Loading $MODEL..." | tee -a "$LOG"
    lms load "$MODEL" 2>&1 | tee -a "$LOG"
    sleep 10

    echo "[$(date)] Running taint_everything with $MODEL (5 reps)..." | tee -a "$LOG"
    cd "$SCRIPT_DIR"
    $PYTHON run_experiments.py \
        --system taint_everything \
        --model "$MODEL" \
        --reps 5 \
        --output "$TAINT_OUTPUT" \
        --resume \
        2>&1 | tee -a "$LOG"

    echo "[$(date)] Finished taint_everything: $MODEL" | tee -a "$LOG"
    lms unload "$MODEL" 2>&1 | tee -a "$LOG"
    sleep 5
done

echo "[$(date)] Part 1 complete!" | tee -a "$LOG"

# ── Part 2: All 5 systems on full 212-scenario benchmark ───────────────────
# The old results had 200 scenarios. We need all 5 systems on the updated 212.
# Use --resume so completed trials from Part 1 (taint_everything) are reused.
FULL_OUTPUT="$RESULTS/full_212"
mkdir -p "$FULL_OUTPUT"

echo "" | tee -a "$LOG"
echo "========================================" | tee -a "$LOG"
echo "PART 2: All 5 systems × 4 models (212 scenarios × 5 reps)" | tee -a "$LOG"
echo "========================================" | tee -a "$LOG"

for MODEL in "${MODELS[@]}"; do
    echo "" | tee -a "$LOG"
    echo "[$(date)] Loading $MODEL..." | tee -a "$LOG"
    lms load "$MODEL" 2>&1 | tee -a "$LOG"
    sleep 10

    for SYSTEM in "${ALL_SYSTEMS[@]}"; do
        echo "[$(date)] Running $SYSTEM with $MODEL (5 reps)..." | tee -a "$LOG"
        cd "$SCRIPT_DIR"
        $PYTHON run_experiments.py \
            --system "$SYSTEM" \
            --model "$MODEL" \
            --reps 5 \
            --output "$FULL_OUTPUT" \
            --resume \
            2>&1 | tee -a "$LOG"

        echo "[$(date)] Finished $SYSTEM: $MODEL" | tee -a "$LOG"
    done

    lms unload "$MODEL" 2>&1 | tee -a "$LOG"
    sleep 5
done

echo "[$(date)] Part 2 complete!" | tee -a "$LOG"

# ── Part 3: InjecAgent taint-everything (local models) ─────────────────────
INJECAGENT_OUTPUT="$RESULTS/injecagent_taint_local"
mkdir -p "$INJECAGENT_OUTPUT"

echo "" | tee -a "$LOG"
echo "========================================" | tee -a "$LOG"
echo "PART 3: InjecAgent taint-everything × 4 models (1,054 × 3 reps)" | tee -a "$LOG"
echo "========================================" | tee -a "$LOG"

for MODEL in "${MODELS[@]}"; do
    echo "[$(date)] Loading $MODEL for InjecAgent..." | tee -a "$LOG"
    lms load "$MODEL" 2>&1 | tee -a "$LOG"
    sleep 10

    echo "[$(date)] Running InjecAgent taint_everything with $MODEL (3 reps)..." | tee -a "$LOG"
    cd "$SCRIPT_DIR"
    $PYTHON run_injecagent.py \
        --system taint_everything \
        --model "$MODEL" \
        --reps 3 \
        --output "$INJECAGENT_OUTPUT" \
        2>&1 | tee -a "$LOG"

    echo "[$(date)] InjecAgent finished: $MODEL" | tee -a "$LOG"
    lms unload "$MODEL" 2>&1 | tee -a "$LOG"
    sleep 5
done

echo "" | tee -a "$LOG"
echo "========================================" | tee -a "$LOG"
echo "[$(date)] ALL OVERNIGHT EXPERIMENTS COMPLETE!" | tee -a "$LOG"
echo "Part 1 (taint-everything):  $TAINT_OUTPUT" | tee -a "$LOG"
echo "Part 2 (full 212 benchmark): $FULL_OUTPUT" | tee -a "$LOG"
echo "Part 3 (InjecAgent taint):   $INJECAGENT_OUTPUT" | tee -a "$LOG"
echo "========================================" | tee -a "$LOG"
