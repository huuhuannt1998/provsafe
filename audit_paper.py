#!/usr/bin/env python3
"""Compare paper numbers vs actual data."""
import json

def load_cp(path):
    d = json.load(open(path))
    return d if isinstance(d, list) else d.get("results", [])

def metrics(trials, sys_name):
    st = [r for r in trials if r.get("system") == sys_name]
    att = [r for r in st if r.get("scenario_type") == "attack"]
    ben = [r for r in st if r.get("scenario_type") == "benign"]
    att_succ = sum(1 for r in att if r.get("attack_success") and not r.get("blocked"))
    ben_succ = sum(1 for r in ben if not r.get("blocked") and r.get("error") is None)
    asr = att_succ / len(att) * 100 if att else 0
    tsr = ben_succ / len(ben) * 100 if ben else 0
    fpr = (len(ben) - ben_succ) / len(ben) * 100 if ben else 0
    return {"n": len(st), "n_att": len(att), "n_ben": len(ben),
            "asr": asr, "tsr": tsr, "fpr": fpr,
            "att_succ": att_succ, "ben_succ": ben_succ}

print("=" * 70)
print("200-SCENARIO: LOCAL MODELS (full_212)")
print("=" * 70)
full = load_cp("results/full_212/checkpoint.json")
for sys in ["no_defense", "pattern_filter", "policy_only", "provsafe"]:
    m = metrics(full, sys)
    print(f"  {sys:20s}: ASR={m['asr']:.2f}% ({m['att_succ']}/{m['n_att']}) TSR={m['tsr']:.2f}% ({m['ben_succ']}/{m['n_ben']}) FPR={m['fpr']:.2f}%")

# Per-model for provsafe
print("\n  Per-model PROVSAFE:")
for model in ["meta-llama-3.1-8b-instruct", "qwen2.5-7b-instruct", "gemma-2-9b-it", "phi-3.5-mini-instruct"]:
    mt = [r for r in full if r.get("system") == "provsafe" and r.get("model") == model]
    att = [r for r in mt if r.get("scenario_type") == "attack"]
    ben = [r for r in mt if r.get("scenario_type") == "benign"]
    att_succ = sum(1 for r in att if r.get("attack_success") and not r.get("blocked"))
    ben_succ = sum(1 for r in ben if not r.get("blocked") and r.get("error") is None)
    blocked = sum(1 for r in att if r.get("blocked"))
    tc_gt0 = sum(1 for r in att if (r.get("tool_calls") or 0) > 0)
    asr = att_succ/len(att)*100 if att else 0
    tsr = ben_succ/len(ben)*100 if ben else 0
    print(f"    {model:35s}: ASR={asr:.2f}% TSR={tsr:.1f}% TC>0={tc_gt0/len(att)*100:.0f}% Blocked={blocked/len(att)*100:.1f}%")

# Per-category for provsafe
print("\n  Per-category PROVSAFE:")
prov_att = [r for r in full if r.get("system") == "provsafe" and r.get("scenario_type") == "attack"]
cats = sorted(set(r.get("scenario_category") for r in prov_att))
for cat in cats:
    ct = [r for r in prov_att if r.get("scenario_category") == cat]
    succ = sum(1 for r in ct if r.get("attack_success") and not r.get("blocked"))
    print(f"    {cat:30s}: ASR={succ/len(ct)*100:.2f}% ({succ}/{len(ct)})")

# Defense breakdown
print("\n  Defense breakdown (PROVSAFE attack trials):")
total = len(prov_att)
blocked = sum(1 for r in prov_att if r.get("blocked"))
tc0 = sum(1 for r in prov_att if (r.get("tool_calls") or 0) == 0 and not r.get("blocked"))
safe = sum(1 for r in prov_att if (r.get("tool_calls") or 0) > 0 and not r.get("blocked") and not r.get("attack_success"))
bypass = sum(1 for r in prov_att if r.get("attack_success") and not r.get("blocked"))
print(f"    Boundary blocked: {blocked} ({blocked/total*100:.1f}%)")
print(f"    Model refusal (TC=0): {tc0} ({tc0/total*100:.1f}%)")
print(f"    Safe tool calls: {safe} ({safe/total*100:.1f}%)")
print(f"    Bypasses (ASR-IA): {bypass} ({bypass/total*100:.2f}%)")

print("\n" + "=" * 70)
print("200-SCENARIO: TAINT-EVERYTHING (tdsc_taint_v3)")
print("=" * 70)
taint = load_cp("results/tdsc_taint_v3/checkpoint.json")
m = metrics(taint, "taint_everything")
print(f"  taint_everything: ASR={m['asr']:.2f}% ({m['att_succ']}/{m['n_att']}) TSR={m['tsr']:.2f}% ({m['ben_succ']}/{m['n_ben']}) FPR={m['fpr']:.2f}%")

print("\n" + "=" * 70)
print("200-SCENARIO: GPT-4O-MINI (gpt4omini_200scenario)")
print("=" * 70)
gpt = load_cp("results/gpt4omini_200scenario/checkpoint.json")
for sys in ["no_defense", "pattern_filter", "policy_only", "taint_everything", "provsafe"]:
    m = metrics(gpt, sys)
    print(f"  {sys:20s}: ASR={m['asr']:.2f}% TSR={m['tsr']:.2f}% FPR={m['fpr']:.2f}%")

print("\n" + "=" * 70)
print("INJECAGENT: LOCAL MODELS (main checkpoint)")
print("=" * 70)
inj = load_cp("results/injecagent/checkpoint.json")
for sys in sorted(set(r.get("system") for r in inj)):
    st = [r for r in inj if r.get("system") == sys]
    atk_called = sum(1 for r in st if r.get("attacker_tool_called") or r.get("attack_success"))
    blocked = sum(1 for r in st if r.get("blocked"))
    errors = sum(1 for r in st if r.get("error"))
    asr = atk_called/len(st)*100 if st else 0
    print(f"  {sys:20s}: {len(st):5d} trials, ASR={asr:.1f}%, blocked={blocked}, errors={errors}")
    # Per model
    for m in sorted(set(r.get("model") for r in st)):
        mt = [r for r in st if r.get("model") == m]
        mc = sum(1 for r in mt if r.get("attacker_tool_called") or r.get("attack_success"))
        print(f"    {m}: {len(mt)} trials, ASR={mc/len(mt)*100:.1f}%")

print("\n" + "=" * 70)
print("INJECAGENT: GPT-4O-MINI")
print("=" * 70)
inj2 = load_cp("results/injecagent_gpt4omini/checkpoint.json")
for sys in sorted(set(r.get("system") for r in inj2)):
    st = [r for r in inj2 if r.get("system") == sys]
    atk_called = sum(1 for r in st if r.get("attacker_tool_called") or r.get("attack_success"))
    blocked = sum(1 for r in st if r.get("blocked"))
    asr = atk_called/len(st)*100 if st else 0
    print(f"  {sys:20s}: {len(st):5d} trials, ASR={asr:.1f}%, blocked={blocked}")

print("\n" + "=" * 70)
print("PAPER vs ACTUAL COMPARISON")
print("=" * 70)
print("\nTable 2 (Baseline Comparison):")
paper = {"no_defense": 24.56, "pattern_filter": 7.33, "policy_only": 1.72, "provsafe": 1.02}
for sys, paper_asr in paper.items():
    m = metrics(full, sys)
    diff = m["asr"] - paper_asr
    print(f"  {sys:20s}: Paper={paper_asr:.2f}% Actual={m['asr']:.2f}% Diff={diff:+.2f}%")

paper_tsr = {"no_defense": 98.38, "pattern_filter": 99.12, "policy_only": 96.75, "provsafe": 95.00}
print("\nTSR comparison:")
for sys, paper_t in paper_tsr.items():
    m = metrics(full, sys)
    diff = m["tsr"] - paper_t
    print(f"  {sys:20s}: Paper={paper_t:.2f}% Actual={m['tsr']:.2f}% Diff={diff:+.2f}%")

print("\nTable 4 (Cross-Model):")
paper_model_asr = {"meta-llama-3.1-8b-instruct": 0.58, "qwen2.5-7b-instruct": 1.16, "gemma-2-9b-it": 0.58, "phi-3.5-mini-instruct": 1.74}
for model, paper_a in paper_model_asr.items():
    mt = [r for r in full if r.get("system") == "provsafe" and r.get("model") == model and r.get("scenario_type") == "attack"]
    succ = sum(1 for r in mt if r.get("attack_success") and not r.get("blocked"))
    actual = succ/len(mt)*100 if mt else 0
    diff = actual - paper_a
    print(f"  {model:35s}: Paper={paper_a:.2f}% Actual={actual:.2f}% Diff={diff:+.2f}%")
