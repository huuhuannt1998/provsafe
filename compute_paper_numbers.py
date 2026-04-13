#!/usr/bin/env python3
"""Compute all numbers needed for paper update."""
import json, math
from collections import Counter

def wilson_ci(successes, n, z=1.96):
    if n == 0: return 0, 0, 0
    p = successes / n
    denom = 1 + z**2/n
    center = (p + z**2/(2*n)) / denom
    margin = z * math.sqrt(p*(1-p)/n + z**2/(4*n**2)) / denom
    return p*100, max(0, center-margin)*100, min(1, center+margin)*100

def fmt_ci(successes, n):
    p, lo, hi = wilson_ci(successes, n)
    margin = (hi - lo) / 2
    return f"{p:.2f}% ± {margin:.2f}"

def load_cp(path):
    d = json.load(open(path))
    return d if isinstance(d, list) else d.get("results", [])

# === 200-SCENARIO LOCAL ===
full = load_cp("results/full_212/checkpoint.json")
taint = load_cp("results/tdsc_taint_v3/checkpoint.json")
gpt = load_cp("results/gpt4omini_200scenario/checkpoint.json")

print("=" * 80)
print("TABLE 1: Defense Layer Breakdown (PROVSAFE attack trials, 4 local models)")
print("=" * 80)
prov_att = [r for r in full if r.get("system") == "provsafe" and r.get("scenario_type") == "attack"]
total = len(prov_att)
blocked = sum(1 for r in prov_att if r.get("blocked"))
tc0 = sum(1 for r in prov_att if (r.get("tool_calls") or 0) == 0 and not r.get("blocked"))
safe = sum(1 for r in prov_att if (r.get("tool_calls") or 0) > 0 and not r.get("blocked") and not r.get("attack_success"))
bypass = sum(1 for r in prov_att if r.get("attack_success") and not r.get("blocked"))
print(f"  Total attack trials: {total}")
print(f"  Boundary blocked: {blocked} ({blocked/total*100:.1f}%)")
print(f"  Model refusal (TC=0): {tc0} ({tc0/total*100:.1f}%)")
print(f"  Safe tool calls: {safe} ({safe/total*100:.1f}%)")
print(f"  Residual ASR-IA: {bypass} ({fmt_ci(bypass, total)})")

prov_ben = [r for r in full if r.get("system") == "provsafe" and r.get("scenario_type") == "benign"]
ben_succ = sum(1 for r in prov_ben if not r.get("blocked") and r.get("error") is None)
print(f"  TSR: {fmt_ci(ben_succ, len(prov_ben))} ({ben_succ}/{len(prov_ben)})")
print(f"  FPR: {fmt_ci(len(prov_ben) - ben_succ, len(prov_ben))} ({len(prov_ben) - ben_succ}/{len(prov_ben)})")

print("\n" + "=" * 80)
print("TABLE 2: Baseline Comparison")
print("=" * 80)
for sys_name in ["no_defense", "pattern_filter", "policy_only", "provsafe"]:
    att = [r for r in full if r.get("system") == sys_name and r.get("scenario_type") == "attack"]
    ben = [r for r in full if r.get("system") == sys_name and r.get("scenario_type") == "benign"]
    att_succ = sum(1 for r in att if r.get("attack_success") and not r.get("blocked"))
    ben_succ = sum(1 for r in ben if not r.get("blocked") and r.get("error") is None)
    print(f"  {sys_name:20s}: ASR={fmt_ci(att_succ, len(att))}, TSR={fmt_ci(ben_succ, len(ben))}")

# Taint from tdsc_taint_v3
t_att = [r for r in taint if r.get("system") == "taint_everything" and r.get("scenario_type") == "attack"]
t_ben = [r for r in taint if r.get("system") == "taint_everything" and r.get("scenario_type") == "benign"]
t_succ = sum(1 for r in t_att if r.get("attack_success") and not r.get("blocked"))
t_ben_succ = sum(1 for r in t_ben if not r.get("blocked") and r.get("error") is None)
print(f"  {'taint_everything':20s}: ASR={fmt_ci(t_succ, len(t_att))}, TSR={fmt_ci(t_ben_succ, len(t_ben))}")
t_fpr = len(t_ben) - t_ben_succ
print(f"    FPR: {fmt_ci(t_fpr, len(t_ben))}")

print("\n" + "=" * 80)
print("TABLE 3: Per-Category ASR (PROVSAFE)")
print("=" * 80)
cats = sorted(set(r.get("scenario_category") for r in prov_att))
for cat in cats:
    ct = [r for r in prov_att if r.get("scenario_category") == cat]
    succ = sum(1 for r in ct if r.get("attack_success") and not r.get("blocked"))
    # N per rep = len(ct) / 5 reps
    n_per_rep = len(ct) // 5
    print(f"  {cat:30s}: N/rep={n_per_rep:3d}, ASR={fmt_ci(succ, len(ct))} ({succ}/{len(ct)})")
overall_succ = sum(1 for r in prov_att if r.get("attack_success") and not r.get("blocked"))
print(f"  {'Overall':30s}: N/rep={len(prov_att)//5:3d}, ASR={fmt_ci(overall_succ, len(prov_att))} ({overall_succ}/{len(prov_att)})")

print("\n" + "=" * 80)
print("TABLE 4: Cross-Model (PROVSAFE)")
print("=" * 80)
models = ["meta-llama-3.1-8b-instruct", "qwen2.5-7b-instruct", "gemma-2-9b-it", "phi-3.5-mini-instruct"]
for m in models:
    mt_att = [r for r in full if r.get("system") == "provsafe" and r.get("model") == m and r.get("scenario_type") == "attack"]
    mt_ben = [r for r in full if r.get("system") == "provsafe" and r.get("model") == m and r.get("scenario_type") == "benign"]
    att_succ = sum(1 for r in mt_att if r.get("attack_success") and not r.get("blocked"))
    ben_succ = sum(1 for r in mt_ben if not r.get("blocked") and r.get("error") is None)
    tc_gt0 = sum(1 for r in mt_att if (r.get("tool_calls") or 0) > 0)
    blocked_ct = sum(1 for r in mt_att if r.get("blocked"))
    short = m.split("-instruct")[0].split("-it")[0]
    print(f"  {short:30s}: TSR={ben_succ/len(mt_ben)*100:.1f}%, ASR={fmt_ci(att_succ, len(mt_att))}, TC>0={tc_gt0/len(mt_att)*100:.0f}%, Blocked={blocked_ct/len(mt_att)*100:.1f}%")

# Mean
all_att_succ = sum(1 for r in prov_att if r.get("attack_success") and not r.get("blocked"))
all_ben = [r for r in full if r.get("system") == "provsafe" and r.get("scenario_type") == "benign"]
all_ben_succ = sum(1 for r in all_ben if not r.get("blocked") and r.get("error") is None)
all_tc_gt0 = sum(1 for r in prov_att if (r.get("tool_calls") or 0) > 0)
all_blocked = sum(1 for r in prov_att if r.get("blocked"))
print(f"  {'Mean':30s}: TSR={all_ben_succ/len(all_ben)*100:.1f}%, ASR={fmt_ci(all_att_succ, len(prov_att))}, TC>0={all_tc_gt0/len(prov_att)*100:.0f}%, Blocked={all_blocked/len(prov_att)*100:.1f}%")

print("\n" + "=" * 80)
print("TABLE 6: GPT-4o-mini (already matches)")
print("=" * 80)
for sys_name in ["no_defense", "pattern_filter", "policy_only", "taint_everything", "provsafe"]:
    att = [r for r in gpt if r.get("system") == sys_name and r.get("scenario_type") == "attack"]
    ben = [r for r in gpt if r.get("system") == sys_name and r.get("scenario_type") == "benign"]
    att_succ = sum(1 for r in att if r.get("attack_success") and not r.get("blocked"))
    ben_succ = sum(1 for r in ben if not r.get("blocked") and r.get("error") is None)
    print(f"  {sys_name:20s}: ASR={att_succ/len(att)*100:.2f}% ({att_succ}/{len(att)}), TSR={ben_succ/len(ben)*100:.2f}% ({ben_succ}/{len(ben)})")

print("\n" + "=" * 80)
print("TRIAL COUNT CALCULATION")
print("=" * 80)
local_4sys = sum(1 for r in full)
taint_trials = sum(1 for r in taint)
gpt_trials = sum(1 for r in gpt)
print(f"  Local 4 systems (full_212): {local_4sys}")
print(f"  Taint-Everything (tdsc_taint_v3): {taint_trials}")
print(f"  GPT-4o-mini: {gpt_trials}")
print(f"  Total: {local_4sys + taint_trials + gpt_trials}")

print("\n" + "=" * 80)
print("RATIOS FOR NARRATIVE")
print("=" * 80)
nd_asr = 24.56
prov_asr = 1.02
pf_asr = 7.33
print(f"  Reduction vs No Defense: {nd_asr/prov_asr:.0f}x")
print(f"  Reduction vs Pattern Filter: {pf_asr/prov_asr:.0f}x")
# GPT-4o-mini
gpt_nd = 24.19
gpt_prov = 0.35
print(f"  GPT-4o-mini reduction: {gpt_nd/gpt_prov:.0f}x")

print("\n" + "=" * 80)
print("STATISTICAL SIGNIFICANCE (Fisher exact p-values)")
print("=" * 80)
from scipy.stats import fisher_exact
systems_data = {}
for sys_name in ["no_defense", "pattern_filter", "policy_only", "provsafe"]:
    att = [r for r in full if r.get("system") == sys_name and r.get("scenario_type") == "attack"]
    succ = sum(1 for r in att if r.get("attack_success") and not r.get("blocked"))
    fail = len(att) - succ
    systems_data[sys_name] = (succ, fail)

pairs = [("no_defense", "provsafe"), ("pattern_filter", "provsafe"), 
         ("policy_only", "provsafe"), ("no_defense", "pattern_filter"),
         ("no_defense", "policy_only"), ("pattern_filter", "policy_only")]
k = len(pairs)
for s1, s2 in pairs:
    s1s, s1f = systems_data[s1]
    s2s, s2f = systems_data[s2]
    table = [[s1s, s1f], [s2s, s2f]]
    _, p = fisher_exact(table)
    p_adj = min(p * k, 1.0)
    # Cohen's h
    p1 = s1s / (s1s + s1f)
    p2 = s2s / (s2s + s2f)
    h = 2 * math.asin(math.sqrt(p1)) - 2 * math.asin(math.sqrt(p2))
    print(f"  {s1} vs {s2}: p={p:.6f}, p_adj={p_adj:.6f}, h={h:.4f}")
