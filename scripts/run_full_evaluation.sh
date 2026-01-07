#!/bin/bash
# Complete evaluation pipeline for research paper

set -e

SEED=${SEED:-42}
BASE_OUT=${BASE_OUT:-runs/paper_eval_$(date +%Y%m%d_%H%M%S)}
PYTHON="/Users/huanbui/Desktop/provsafe/.venv/bin/python"

echo "========================================="
echo "PROVSAFE RESEARCH EVALUATION PIPELINE"
echo "========================================="
echo ""
echo "Configuration:"
echo "  Seed: $SEED"
echo "  Output: $BASE_OUT"
echo ""
echo "This will run:"
echo "  1. Baseline comparison (4 systems)"
echo "  2. Ablation study (7 configurations)"
echo "  3. Statistical analysis (30 trials)"
echo "  4. Benign task evaluation"
echo "  5. Comprehensive attack evaluation"
echo ""
echo "Estimated time: 30-45 minutes"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 0
fi

# 1. Baseline Comparison
echo ""
echo "========================================="
echo "1/5: Baseline Comparison"
echo "========================================="
$PYTHON -m provsafe.eval.run_comparative \
  --suite configs/suites/comprehensive_attacks.yaml \
  --policy configs/policies/provsafe.yaml \
  --out "$BASE_OUT/comparative" \
  --seed $SEED

# 2. Ablation Study
echo ""
echo "========================================="
echo "2/5: Ablation Study"
echo "========================================="
$PYTHON -m provsafe.eval.run_ablation \
  --suite configs/suites/default.yaml \
  --policy configs/policies/provsafe.yaml \
  --out "$BASE_OUT/ablation" \
  --seed $SEED

# 3. Statistical Analysis
echo ""
echo "========================================="
echo "3/5: Statistical Analysis (30 trials)"
echo "========================================="
$PYTHON -m provsafe.eval.run_statistical \
  --suite configs/suites/injection.yaml \
  --policy configs/policies/provsafe.yaml \
  --out "$BASE_OUT/statistical" \
  --trials 30 \
  --start-seed $SEED

# 4. Benign Tasks
echo ""
echo "========================================="
echo "4/5: Benign Task Evaluation"
echo "========================================="
$PYTHON -m provsafe.eval.run_suite \
  --suite configs/suites/default.yaml \
  --policy configs/policies/provsafe.yaml \
  --out "$BASE_OUT/benign" \
  --seed $SEED

# 5. Comprehensive Attacks
echo ""
echo "========================================="
echo "5/5: Comprehensive Attack Evaluation"
echo "========================================="
$PYTHON -m provsafe.eval.run_attacks \
  --suite configs/suites/comprehensive_attacks.yaml \
  --policy configs/policies/provsafe.yaml \
  --out "$BASE_OUT/comprehensive_attacks" \
  --seed $SEED

# Generate summary
echo ""
echo "========================================="
echo "EVALUATION COMPLETE"
echo "========================================="
echo ""
echo "Results saved to: $BASE_OUT"
echo ""
echo "Key files:"
echo "  - $BASE_OUT/comparative/comparative_summary.json"
echo "  - $BASE_OUT/ablation/ablation_results.json"
echo "  - $BASE_OUT/statistical/statistical_summary.json"
echo "  - $BASE_OUT/benign/metrics.json"
echo "  - $BASE_OUT/comprehensive_attacks/metrics.json"
echo ""
echo "Next steps:"
echo "  1. Review RESEARCH_EVALUATION.md for interpretation guide"
echo "  2. Generate plots for paper (see scripts/generate_plots.py)"
echo "  3. Extract key numbers for tables"
echo ""
echo "To verify reproducibility:"
echo "  $PYTHON -m provsafe.replay.replay_cli \\"
echo "    --transcript $BASE_OUT/benign/transcript.json \\"
echo "    --verify"
echo ""
