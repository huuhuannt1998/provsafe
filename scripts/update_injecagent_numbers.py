#!/usr/bin/env python3
"""
update_injecagent_numbers.py
Read results/injecagent/injecagent_report.json and fill in the
\PLACEHOLDER{} tokens in 08_evaluation.tex.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
REPORT = REPO / "results" / "injecagent" / "injecagent_report.json"
SEC8 = REPO / "overleaf" / "sections" / "08_evaluation.tex"


def main():
    if not REPORT.exists():
        print(f"Report not found: {REPORT}")
        sys.exit(1)

    with open(REPORT) as f:
        r = json.load(f)

    agg = r.get("aggregate", {})

    def get(sysname):
        s = agg.get(sysname, {})
        asr = s.get("asr_ia_mean", 0.0)
        ci = s.get("asr_ia_ci_half", 0.0)
        return f"{asr:.2f}", f"{ci:.1f}"

    nd_asr, nd_ci   = get("no_defense")
    pf_asr, pf_ci   = get("pattern_filter")
    po_asr, po_ci   = get("policy_only")
    ps_asr, ps_ci   = get("provsafe")

    replacements = {
        r"\PLACEHOLDER{injecagent_nd_asr}": nd_asr,
        r"\PLACEHOLDER{injecagent_nd_ci}":  nd_ci,
        r"\PLACEHOLDER{injecagent_pf_asr}": pf_asr,
        r"\PLACEHOLDER{injecagent_pf_ci}":  pf_ci,
        r"\PLACEHOLDER{injecagent_po_asr}": po_asr,
        r"\PLACEHOLDER{injecagent_po_ci}":  po_ci,
        r"\PLACEHOLDER{injecagent_ps_asr}": ps_asr,
        r"\PLACEHOLDER{injecagent_ps_ci}":  ps_ci,
    }

    text = SEC8.read_text()
    for old, new in replacements.items():
        if old in text:
            text = text.replace(old, new)
            print(f"  [OK] {old} → {new}")
        else:
            print(f"  [WARN] placeholder not found: {old}")

    SEC8.write_text(text)
    print(f"\nInjecAgent numbers written to {SEC8.name}")
    print(f"  No Defense:     ASR-IA = {nd_asr}% ± {nd_ci}")
    print(f"  Pattern Filter: ASR-IA = {pf_asr}% ± {pf_ci}")
    print(f"  Policy-Only:    ASR-IA = {po_asr}% ± {po_ci}")
    print(f"  PROVSAFE:       ASR-IA = {ps_asr}% ± {ps_ci}")


if __name__ == "__main__":
    main()
