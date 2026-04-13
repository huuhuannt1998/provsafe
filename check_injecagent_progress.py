#!/usr/bin/env python3
"""Check InjecAgent progress across all checkpoints."""
import json
from pathlib import Path
from collections import Counter

REPO = Path(__file__).resolve().parent
TARGET_PER_COMBO = 3162  # 1054 cases × 3 reps

LOCAL_MODELS = [
    "meta-llama-3.1-8b-instruct",
    "qwen2.5-7b-instruct",
    "gemma-2-9b-it",
    "phi-3.5-mini-instruct",
]
SYSTEMS = ["no_defense", "pattern_filter", "policy_only", "taint_everything", "provsafe"]


def load_checkpoint(path):
    if not path.exists():
        return []
    with open(path) as f:
        return json.load(f)


def print_table(data, models, label):
    print(f"\n{'=' * 70}")
    print(f"  {label}")
    print(f"{'=' * 70}")

    # Count by (system, model)
    counts = Counter()
    for r in data:
        counts[(r["system"], r["model"])] += 1

    # Header
    short = {m: m.split("-")[0][:8] for m in models}
    header = f"{'System':<20s}"
    for m in models:
        header += f" {short[m]:>10s}"
    header += f" {'Total':>8s}"
    print(header)
    print("-" * len(header))

    grand_total = 0
    grand_needed = 0
    for sys in SYSTEMS:
        row = f"{sys:<20s}"
        sys_total = 0
        sys_needed = 0
        for m in models:
            have = counts.get((sys, m), 0)
            sys_total += have
            sys_needed += max(0, TARGET_PER_COMBO - have)
            pct = have / TARGET_PER_COMBO * 100
            if have >= TARGET_PER_COMBO:
                row += f" {'✓':>10s}"
            else:
                row += f" {have:>5d}/{TARGET_PER_COMBO}"
            # Simplified display
        row += f" {sys_total:>8d}"
        print(row)
        grand_total += sys_total
        grand_needed += sys_needed

    target = TARGET_PER_COMBO * len(models) * len(SYSTEMS)
    print("-" * len(header))
    print(f"{'Total':<20s} {grand_total:>{len(header)-28}d}/{target}")
    print(f"{'Remaining':<20s} {grand_needed:>{len(header)-28}d}")
    pct = grand_total / target * 100
    print(f"{'Progress':<20s} {pct:>{len(header)-29}.1f}%")


def main():
    # Local models
    local_path = REPO / "results" / "injecagent" / "checkpoint.json"
    local_data = load_checkpoint(local_path)
    if local_data:
        print_table(local_data, LOCAL_MODELS, "LOCAL MODELS (results/injecagent/)")

    # GPT-4o-mini
    gpt_path = REPO / "results" / "injecagent_gpt4omini" / "checkpoint.json"
    gpt_data = load_checkpoint(gpt_path)
    if gpt_data:
        print_table(gpt_data, ["gpt-4o-mini"], "GPT-4O-MINI (results/injecagent_gpt4omini/)")

    # Quick ASR summary from completed data
    print(f"\n{'=' * 70}")
    print("  CURRENT ASR (partial data)")
    print(f"{'=' * 70}")
    for label, data in [("Local", local_data), ("GPT-4o-mini", gpt_data)]:
        if not data:
            continue
        print(f"\n  {label}:")
        for sys in SYSTEMS:
            rows = [r for r in data if r["system"] == sys]
            if not rows:
                continue
            n = len(rows)
            k = sum(1 for r in rows if r.get("attack_success"))
            asr = k / n * 100 if n else 0
            print(f"    {sys:<20s} ASR={asr:5.2f}% ({k}/{n})")


if __name__ == "__main__":
    main()
