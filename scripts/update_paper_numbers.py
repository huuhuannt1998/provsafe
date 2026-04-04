#!/usr/bin/env python3
"""
update_paper_numbers.py
Read results report.json and patch all numeric placeholders
in the overleaf LaTeX sections.
"""

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
REPORT = REPO / "results" / "tdsc_full" / "report.json"
SECTIONS = REPO / "overleaf" / "sections"
MAIN_TEX = REPO / "overleaf" / "main.tex"


def fmt_pct(val, ci=None):
    """Return e.g. '7.50\\% $\\pm$ 0.9'"""
    if ci is not None:
        return f"{val:.2f}\\% $\\pm$ {ci:.1f}"
    return f"{val:.2f}\\%"


def load_report():
    with open(REPORT) as f:
        return json.load(f)


def patch(path: Path, old: str, new: str, label: str = ""):
    text = path.read_text()
    if old not in text:
        print(f"  [WARN] pattern not found in {path.name}: {old[:60]!r}")
        return
    patched = text.replace(old, new, 1)
    path.write_text(patched)
    tag = f" ({label})" if label else ""
    print(f"  [OK] {path.name}{tag}")


def main():
    if not REPORT.exists():
        print(f"Report not found: {REPORT}")
        sys.exit(1)

    r = load_report()
    print(f"Loaded report: {REPORT}")

    # ── pull aggregate stats per system ──────────────────────────────────────
    agg = r.get("aggregate", r)  # some versions nest under "aggregate"

    def sys_stats(sysname):
        """Return (asr_mean, asr_ci_half, tsr_mean, tsr_ci_half) for a system."""
        key = sysname.replace("-", "_").replace(" ", "_").lower()
        # try direct key, then nested
        s = agg.get(key, agg.get(sysname, {}))
        # Support both old format (asr_ia_mean) and new format (asr + wilson ci)
        asr = s.get("asr_ia_mean", s.get("asr_mean", s.get("asr", None)))
        asr_ci = s.get("asr_ia_ci_half", s.get("asr_ci", None))
        if asr_ci is None and "asr_wilson_ci" in s:
            # Wilson CI is [lo, hi]; compute half-width
            lo, hi = s["asr_wilson_ci"]
            asr_ci = round((hi - lo) / 2, 1)
        tsr = s.get("tsr_mean", s.get("tsr", None))
        tsr_ci = s.get("tsr_ci_half", s.get("tsr_ci", None))
        if tsr_ci is None and "tsr_wilson_ci" in s:
            lo, hi = s["tsr_wilson_ci"]
            tsr_ci = round((hi - lo) / 2, 1)
        return asr, asr_ci, tsr, tsr_ci

    po_asr, po_asr_ci, po_tsr, po_tsr_ci = sys_stats("policy_only")

    if po_asr is None:
        print("[WARN] policy_only stats not found in report; dumping keys:")
        print(list(agg.keys()))
        # Try to compute from raw results
        raw_path = REPO / "results" / "tdsc_full_v2" / "all_results.json"
        if raw_path.exists():
            print("Attempting to compute from all_results.json ...")
            compute_from_raw(raw_path)
        sys.exit(1)

    print(f"Policy-Only: ASR-IA={po_asr:.2f}% ±{po_asr_ci:.1f}  TSR={po_tsr:.2f}% ±{po_tsr_ci:.1f}")

    # ── 08_evaluation.tex: replace the placeholder row ────────────────────────
    sec8 = SECTIONS / "08_evaluation.tex"
    old_row = r"Policy-Only       & \multicolumn{3}{c}{\emph{Results pending re-run with corrected baseline (see text)}} \\"
    # Policy-Only key limitation: lower TSR than PROVSAFE because policy rules
    # over-block identical-looking calls that lack provenance context
    limitation = "Over-blocks without provenance context"
    new_row = (
        f"Policy-Only       & {fmt_pct(po_asr, po_asr_ci)} & {fmt_pct(po_tsr, po_tsr_ci)} "
        f"& {limitation} \\\\"
    )
    patch(sec8, old_row, new_row, "policy-only table row")

    # ── Per-category table ─────────────────────────────────────────────────────
    per_cat = r.get("per_category", {})
    cat_map = {
        "encoding_obfuscation": "Encoding Obfusc.",
        "multi_step": "Multi-Turn Chain",
        "confused_deputy": "Confused Deputy",
        "privilege_escalation": "Privilege Escalation",
        "direct_injection": "Direct Injection",
        "device_state_injection": "Device-State Inj.",
        "file_content_injection": "File Content Inj.",
        "role_play_jailbreak": "Role-Play Jailbreak",
    }
    for key, label in cat_map.items():
        cat = per_cat.get(key, {})
        if not cat:
            continue
        asr_v = cat.get("asr_ia_mean", cat.get("asr_mean"))
        ci_v = cat.get("asr_ia_ci_half", cat.get("asr_ci"))
        if asr_v is None:
            continue
        # Update just the ASR cell in the per-category table
        # Pattern: label row ending with old ASR value
        text = sec8.read_text()
        # Escape label for regex
        esc = re.escape(label)
        # Match the ASR cell on that row
        pattern = rf"({re.escape(label)}\s+& \d+ & )([\d.]+\\% \$\\pm\$ [\d.]+)"
        new_asr_cell = f"{asr_v:.2f}\\% $\\pm$ {ci_v:.2f}"
        updated = re.sub(pattern, lambda m: m.group(1) + new_asr_cell, text)
        if updated != text:
            sec8.write_text(updated)
            print(f"  [OK] 08_evaluation.tex (per-cat {label}: {asr_v:.2f}%)")

    # ── Overall numbers in body text ───────────────────────────────────────────
    nd_asr, nd_asr_ci, _, _ = sys_stats("no_defense")
    pf_asr, pf_asr_ci, _, _ = sys_stats("pattern_filter")
    ps_asr, ps_asr_ci, ps_tsr, ps_tsr_ci = sys_stats("provsafe")

    if nd_asr is not None and ps_asr is not None:
        ratio_nd = round(nd_asr / max(ps_asr, 0.01))
        ratio_pf = round(pf_asr / max(ps_asr, 0.01))
        text = sec8.read_text()
        # Update "24x reduction vs No Defense and 7x vs Pattern Filter"
        old_ratio = r"24$\times$ reduction versus No Defense and 7$\times$ versus Pattern Filter"
        new_ratio = f"{ratio_nd}$\\times$ reduction versus No Defense and {ratio_pf}$\\times$ versus Pattern Filter"
        if old_ratio in text:
            sec8.write_text(text.replace(old_ratio, new_ratio))
            print(f"  [OK] 08_evaluation.tex (reduction ratios {ratio_nd}x, {ratio_pf}x)")

    # ── Abstract ───────────────────────────────────────────────────────────────
    if ps_asr is not None:
        text = MAIN_TEX.read_text()
        old_abs = r"\textbf{1.09\% $\pm$ 0.36} with \textbf{95.00\% task success rate}, representing a 24$\times$ reduction"
        new_abs = (
            f"\\textbf{{{ps_asr:.2f}\\% $\\pm$ {ps_asr_ci:.2f}}} "
            f"with \\textbf{{{ps_tsr:.2f}\\% task success rate}}, "
            f"representing a {round(nd_asr/max(ps_asr,0.01))}$\\times$ reduction"
        )
        if old_abs in text:
            MAIN_TEX.write_text(text.replace(old_abs, new_abs))
            print(f"  [OK] main.tex (abstract ASR/TSR)")

    # ── Section 9 encoding obfuscation residual ASR ───────────────────────────
    enc = per_cat.get("encoding_obfuscation", {})
    enc_asr = enc.get("asr_ia_mean", enc.get("asr_mean"))
    if enc_asr is not None:
        sec9 = SECTIONS / "09_discussion.tex"
        text = sec9.read_text()
        # Replace "2.78\% ASR for this category"
        updated = re.sub(
            r"[\d.]+\\% ASR for this category",
            f"{enc_asr:.2f}\\% ASR for this category",
            text,
        )
        if updated != text:
            sec9.write_text(updated)
            print(f"  [OK] 09_discussion.tex (encoding obfuscation ASR → {enc_asr:.2f}%)")

    print("\nDone. Paper numbers updated from corrected experiment.")


def compute_from_raw(raw_path: Path):
    """Fallback: compute stats directly from all_results.json."""
    import math

    with open(raw_path) as f:
        results = json.load(f)

    def wilson_ci(k, n, z=1.96):
        if n == 0:
            return 0.0
        p = k / n
        denom = 1 + z**2 / n
        centre = (p + z**2 / (2 * n)) / denom
        margin = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
        return margin * 100

    systems = {}
    for row in results:
        s = row["system"]
        if s not in systems:
            systems[s] = {"attack": {"n": 0, "k": 0}, "benign": {"n": 0, "k": 0}}
        if row["scenario_type"] == "attack":
            systems[s]["attack"]["n"] += 1
            systems[s]["attack"]["k"] += int(row.get("attack_success", False))
        else:
            systems[s]["benign"]["n"] += 1
            # TSR = not blocked
            systems[s]["benign"]["k"] += int(not row.get("blocked", False))

    for sname, d in systems.items():
        n_a = d["attack"]["n"]
        k_a = d["attack"]["k"]
        n_b = d["benign"]["n"]
        k_b = d["benign"]["k"]
        asr = k_a / max(n_a, 1) * 100
        tsr = k_b / max(n_b, 1) * 100
        asr_ci = wilson_ci(k_a, n_a)
        tsr_ci = wilson_ci(k_b, n_b)
        print(f"  {sname}: ASR-IA={asr:.2f}% ±{asr_ci:.1f}  TSR={tsr:.2f}% ±{tsr_ci:.1f}")


if __name__ == "__main__":
    main()
