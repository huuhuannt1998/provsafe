#!/usr/bin/env python3
"""Aggregate the three component-ablation runs into a single comparison table.

Inputs (per-config result dirs):
  - results/full_212/                  (full PROVSAFE: Stage 1+2+3 fail-closed)
  - results/ablation_substring_only/   (Stage 1 only, fail-open)
  - results/ablation_subembed/         (Stage 1+2, fail-open)

Output:
  - experiments/component_ablation/ablation_summary.json
  - experiments/component_ablation/ablation_table.tex
"""
import json
from collections import defaultdict
from math import sqrt
from pathlib import Path


CONFIGS = [
    ("Substring only",       "results/ablation_substring_only", "results_provsafe.json"),
    ("+Embedding",           "results/ablation_subembed",        "results_provsafe.json"),
    ("+Conservative default (Full)", "results/full_212",          "results_provsafe.json"),
]


def wilson(k, n, z=1.96):
    if n == 0: return (0, 0)
    p = k / n
    den = 1 + z*z/n
    c = (p + z*z/(2*n))/den
    m = z*sqrt(p*(1-p)/n + z*z/(4*n*n))/den
    return (max(0, c-m)*100, min(1, c+m)*100)


PUB_MODELS = {
    "meta-llama-3.1-8b-instruct", "qwen2.5-7b-instruct",
    "gemma-2-9b-it", "phi-3.5-mini-instruct",
}


def summarize(path):
    p = Path(path)
    if not p.exists():
        return {"status": "missing", "path": str(p)}
    with p.open() as f:
        trials = json.load(f)
    # Filter to the 4 publication local models for apples-to-apples comparison
    trials = [t for t in trials if t.get("model") in PUB_MODELS]
    attack = [t for t in trials if t.get("scenario_type") == "attack"]
    benign = [t for t in trials if t.get("scenario_type") == "benign"]
    asr_k = sum(1 for t in attack if t.get("attack_success"))
    fp_k  = sum(1 for t in benign if t.get("error") or t.get("attack_success"))
    tsr_k = len(benign) - fp_k
    asr_lo, asr_hi = wilson(asr_k, len(attack))
    res_stages = defaultdict(int)
    for t in attack:
        for s, c in (t.get("resolution_stages") or {}).items():
            res_stages[s] += c
    return {
        "status": "ok",
        "n_attack": len(attack), "asr_pct": 100*asr_k/max(1,len(attack)),
        "asr_ci": [asr_lo, asr_hi],
        "n_benign": len(benign), "tsr_pct": 100*tsr_k/max(1,len(benign)),
        "fpr_pct": 100*fp_k/max(1,len(benign)),
        "resolution_counts": dict(res_stages),
    }


def main():
    rows = []
    for label, root, fn in CONFIGS:
        rows.append({"label": label, **summarize(Path(root)/fn)})

    out = Path("experiments/component_ablation")
    out.mkdir(parents=True, exist_ok=True)
    (out/"ablation_summary.json").write_text(json.dumps(rows, indent=2))

    print(f"{'Config':<35} {'n_atk':>6} {'ASR':>10} {'Wilson 95% CI':>20} {'TSR':>10}")
    for r in rows:
        if r.get("status") != "ok":
            print(f"{r['label']:<35} MISSING ({r.get('path')})")
            continue
        ci = r["asr_ci"]
        print(f"{r['label']:<35} {r['n_attack']:>6} {r['asr_pct']:>8.2f}% [{ci[0]:>5.1f},{ci[1]:>5.1f}] {r['tsr_pct']:>8.2f}%")

    # LaTeX
    tex = out/"ablation_table.tex"
    with tex.open("w") as fh:
        fh.write("\\begin{tabular}{lrrrr}\n\\toprule\n")
        fh.write("\\textbf{Configuration} & $n_{\\text{atk}}$ & \\textbf{ASR-IA} & \\textbf{95\\% CI} & \\textbf{TSR} \\\\\n\\midrule\n")
        for r in rows:
            if r.get("status") != "ok":
                fh.write(f"{r['label']} & --- & MISSING & --- & --- \\\\\n")
                continue
            ci = r["asr_ci"]
            fh.write(f"{r['label']} & {r['n_attack']:,} & {r['asr_pct']:.2f}\\% & [{ci[0]:.2f}, {ci[1]:.2f}] & {r['tsr_pct']:.2f}\\% \\\\\n")
        fh.write("\\bottomrule\n\\end{tabular}\n")
    print(f"\nWrote {tex}")


if __name__ == "__main__":
    main()
