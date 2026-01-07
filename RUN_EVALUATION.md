# Running Full Evaluation on School PC

## Quick Start

```bash
# 1. Clone the repository
git clone <your-github-repo-url>
cd provsafe

# 2. Navigate to evaluation directory
cd evaluation

# 3. Install dependencies (if needed)
pip install requests

# 4. Run full evaluation (6-7 hours)
python3 full_evaluation.py

# Or run in background with nohup
nohup python3 full_evaluation.py > eval.log 2>&1 &
```

## What It Does

The evaluation will:
- Test **100 scenarios** (20 benign + 80 attacks)
- Across **4 models** (gpt-oss-120b, InternVL3.5-30B, Qwen3-30B, gpt-oss-20b)
- With **4 baseline systems** (no_defense, pattern_filter, policy_only, provsafe)
- Total: **1,600 evaluations**
- Time: **~6-7 hours**

## Results Location

Results will be saved to:
```
evaluation/results/full_eval_[timestamp]/
├── detailed_results.json  # All individual evaluation results
├── metrics.json          # Computed metrics by system
└── summary_report.json   # Overall summary and key findings
```

## Monitor Progress

If running with nohup:
```bash
# Check progress
tail -f eval.log

# Check if still running
ps aux | grep full_evaluation
```

## Quick Test First (Optional)

To test with just 10 scenarios first (~10 minutes):
```bash
python3 full_evaluation.py --quick
```

## Key Metrics

The evaluation computes:
- **ASR (Attack Success Rate)**: % of attacks that succeeded
- **TSR (Task Success Rate)**: % of benign tasks that succeeded
- **Latency**: Average response time per system

Expected results:
- No Defense: High ASR (~60-80%), validates threat model
- Pattern Filter: Medium ASR (~30-50%), shows naive defenses fail
- Policy-Only: Medium-Low ASR (~15-30%), shows provenance is needed
- PROVSAFE: Low ASR (~2-10%), demonstrates effectiveness
