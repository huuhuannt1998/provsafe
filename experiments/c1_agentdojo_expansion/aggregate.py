#!/usr/bin/env python3
"""C1 aggregator: combine per-cell JSON outputs into a single full-matrix table.

Usage: python experiments/c1_agentdojo_expansion/aggregate.py results/agentdojo_full_matrix/

Produces: aggregate.json, agentdojo_full_matrix.tex (LaTeX table for paper).
"""
import json
import sys
from collections import defaultdict
from pathlib import Path
from math import sqrt

SUITES = ("workspace", "slack", "banking", "travel")
ATTACKS = ("important_instructions", "direct", "ignore_previous", "injecagent", "tool_knowledge")
SYSTEMS = ("provsafe", "no_defense")


def wilson_ci(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def main(root):
    root = Path(root)
    cells = {}
    for suite in SUITES:
        for attack in ATTACKS:
            for system in SYSTEMS:
                tag = f"{suite}_{attack}_{system}"
                f = root / f"{tag}.json"
                if not f.exists():
                    cells[(suite, attack, system)] = None
                    continue
                with f.open() as fh:
                    cells[(suite, attack, system)] = json.load(fh)

    # Compute ASR / TSR per cell
    summary = []
    for (suite, attack, system), data in cells.items():
        if data is None:
            summary.append({"suite": suite, "attack": attack, "system": system, "status": "missing"})
            continue
        # Schema: list of trial dicts with attack_success / blocked / tool_calls / etc.
        trials = data if isinstance(data, list) else data.get("trials", [])
        attack_trials = [t for t in trials if t.get("scenario_type") == "attack"]
        benign_trials = [t for t in trials if t.get("scenario_type") == "benign"] or trials
        n_a = len(attack_trials) or 1
        n_b = len(benign_trials) or 1
        asr_k = sum(1 for t in attack_trials if t.get("attack_success"))
        tsr_k = sum(1 for t in benign_trials if not t.get("error") and not t.get("attack_success"))
        asr_lo, asr_hi = wilson_ci(asr_k, n_a)
        summary.append({
            "suite": suite, "attack": attack, "system": system, "status": "ok",
            "n_attack": n_a, "n_benign": n_b,
            "asr_pct": 100 * asr_k / n_a,
            "asr_ci": [100 * asr_lo, 100 * asr_hi],
            "tsr_pct": 100 * tsr_k / n_b,
        })

    out = root / "aggregate.json"
    with out.open("w") as fh:
        json.dump(summary, fh, indent=2)
    print(f"Wrote {out}")

    # Pretty matrix print
    print("\nPROVSAFE ASR (%) by suite × attack:")
    header = f"{'suite':<10}" + "".join(f"{a[:14]:>16}" for a in ATTACKS)
    print(header)
    for suite in SUITES:
        row = f"{suite:<10}"
        for attack in ATTACKS:
            entry = next((s for s in summary if s["suite"] == suite and s["attack"] == attack and s["system"] == "provsafe"), None)
            if entry and entry.get("status") == "ok":
                row += f"{entry['asr_pct']:>15.2f} "
            else:
                row += f"{'--':>15} "
        print(row)

    # LaTeX table
    tex = root / "agentdojo_full_matrix.tex"
    with tex.open("w") as fh:
        fh.write("% C1: AgentDojo full-matrix ASR for PROVSAFE\n")
        fh.write("\\begin{tabular}{l" + "r" * len(ATTACKS) + "}\n\\toprule\n")
        fh.write("Suite & " + " & ".join(a.replace("_", "\\_") for a in ATTACKS) + "\\\\\n\\midrule\n")
        for suite in SUITES:
            row = [suite]
            for attack in ATTACKS:
                e = next((s for s in summary if s["suite"] == suite and s["attack"] == attack and s["system"] == "provsafe"), None)
                row.append(f"{e['asr_pct']:.2f}\\%" if e and e.get("status") == "ok" else "--")
            fh.write(" & ".join(row) + "\\\\\n")
        fh.write("\\bottomrule\n\\end{tabular}\n")
    print(f"Wrote {tex}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "results/agentdojo_full_matrix/")
