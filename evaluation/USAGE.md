# Quick Start - PROVSAFE Evaluation

## Run Full Evaluation

```bash
cd /Users/huanbui/Desktop/provsafe/evaluation
python3 full_evaluation.py
```

**Time**: ~6-7 hours (1,600 evaluations)
**Features**: Auto-resume, incremental saving

## Run Quick Test (10 scenarios)

```bash
python3 full_evaluation.py --quick
```

**Time**: ~30 minutes (160 evaluations)

## Results Location

`results/full_eval_<timestamp>/`
- `detailed_results.json` - Complete results
- `metrics.json` - ASR/TSR metrics  
- `summary_report.json` - Summary

## What It Tests

- **100 scenarios** (80 attacks + 20 benign)
- **4 models** (120B, 30B InternVL, 30B Qwen, 20B)
- **4 systems** (No Defense, Pattern Filter, Policy-Only, PROVSAFE)
- **Total**: 1,600 evaluations

## If Interrupted

Just run the same command again - it will automatically resume from where it left off.
