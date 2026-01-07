#!/bin/bash
# Run full evaluation pipeline

set -e

echo "=== PROVSAFE Evaluation Pipeline ==="
echo ""

# Default values
SEED=${SEED:-42}
OUTPUT_DIR=${OUTPUT_DIR:-runs/eval_$(date +%Y%m%d_%H%M%S)}

echo "Configuration:"
echo "  Seed: $SEED"
echo "  Output: $OUTPUT_DIR"
echo ""

# Run benign suite
echo "1. Running benign benchmark suite..."
python -m provsafe.eval.run_suite \
  --suite configs/suites/default.yaml \
  --policy configs/policies/provsafe.yaml \
  --out "$OUTPUT_DIR/benign" \
  --seed $SEED

echo ""

# Run attack suite
echo "2. Running attack injection suite..."
python -m provsafe.eval.run_attacks \
  --suite configs/suites/injection.yaml \
  --policy configs/policies/provsafe.yaml \
  --out "$OUTPUT_DIR/attacks" \
  --seed $SEED

echo ""

# Verify determinism
echo "3. Verifying determinism (replay)..."
python -m provsafe.replay.replay_cli \
  --transcript "$OUTPUT_DIR/benign/transcript.json" \
  --verify

echo ""
echo "=== Evaluation Complete ==="
echo "Results saved to: $OUTPUT_DIR"
echo ""
echo "View metrics:"
echo "  cat $OUTPUT_DIR/benign/metrics.json"
echo "  cat $OUTPUT_DIR/attacks/metrics.json"
