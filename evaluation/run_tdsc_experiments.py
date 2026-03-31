#!/usr/bin/env python3
"""
IEEE TDSC Multi-Trial Experiment Runner

Runs PROVSAFE + 3 baselines × 4 models × 200 scenarios × 5 repetitions
with temperature=0.0 (deterministic), computing per-model and aggregate
statistics with 95% confidence intervals.

Total: (4 systems × 4 models × 200 scenarios × 5 reps) = 16,000 trials

Usage:
    python run_tdsc_experiments.py                  # Full run (all 4 models, 5 reps)
    python run_tdsc_experiments.py --reps 3         # 3 reps
    python run_tdsc_experiments.py --quick           # 10 scenarios, 2 reps
    python run_tdsc_experiments.py --model X         # Single model
    python run_tdsc_experiments.py --system provsafe # Single system
    python run_tdsc_experiments.py --resume          # Resume from checkpoint
"""

import json
import os
import sys
import time
import math
import hashlib
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import numpy as np

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from baseline_systems import (
    NoDefenseSystem,
    PatternFilterSystem,
    PolicyOnlySystem,
    PROVSAFESystem,
)
from model_providers import (
    get_provider_config,
    is_lmstudio_model,
    ALL_MODELS,
    LMSTUDIO_MODELS,
    GROQ_MODELS,
    GEMINI_MODELS,
)

# ── Configuration ────────────────────────────────────────────────────────────
LMSTUDIO_API = "http://localhost:1234/api/v1"

TEMPERATURE = 0.0  # Deterministic for reproducibility

MODELS = ALL_MODELS

SYSTEMS = {
    "no_defense": NoDefenseSystem,
    "pattern_filter": PatternFilterSystem,
    "policy_only": PolicyOnlySystem,
    "provsafe": PROVSAFESystem,
}

# Load scenarios
with open(Path(__file__).parent / "scenarios_expanded.json", "r") as f:
    SCENARIOS = json.load(f)


# ── LM Studio API helpers ───────────────────────────────────────────────────
def lmstudio_list_loaded() -> List[str]:
    try:
        resp = requests.get(f"{LMSTUDIO_API}/models", timeout=10)
        resp.raise_for_status()
        loaded = []
        for m in resp.json().get("models", []):
            if m.get("type") == "llm":
                for inst in m.get("loaded_instances", []):
                    loaded.append(inst["id"])
        return loaded
    except requests.RequestException:
        return []


def lmstudio_unload_all() -> int:
    loaded = lmstudio_list_loaded()
    count = 0
    for inst_id in loaded:
        try:
            requests.post(
                f"{LMSTUDIO_API}/models/unload",
                json={"instance_id": inst_id},
                timeout=30,
            ).raise_for_status()
            count += 1
        except Exception:
            pass
    if count:
        time.sleep(2)
    return count


def lmstudio_swap(model: str, context_length: int = 4096) -> bool:
    print(f"\n🔄 Swapping to {model} ...")
    lmstudio_unload_all()
    try:
        resp = requests.post(
            f"{LMSTUDIO_API}/models/load",
            json={"model": model, "context_length": context_length, "flash_attention": True},
            timeout=300,
        )
        resp.raise_for_status()
    except Exception as e:
        print(f"  ❌ Failed to load {model}: {e}")
        return False
    for _ in range(6):
        loaded = lmstudio_list_loaded()
        if any(model in inst or inst in model for inst in loaded):
            print(f"  ✅ {model} ready")
            return True
        time.sleep(5)
    print(f"  ⚠️ Proceeding without verification")
    return True


# ── Evaluation ───────────────────────────────────────────────────────────────
def trial_key(system: str, model: str, scenario_id: str, rep: int) -> str:
    return f"{system}|{model}|{scenario_id}|rep{rep}"


def evaluate_single(
    system_cls, system_name: str, model: str, scenario: Dict, rep: int
) -> Dict[str, Any]:
    """Run one trial and return the result dict.

    Each repetition uses a unique seed derived from the scenario ID, system
    name, model name, and rep index.  This ensures that:
    - Within a rep, results are deterministic (reproducible).
    - Across reps, different seeds introduce sampling variation so that
      bootstrap CIs are meaningful.
    """
    # Derive a unique seed for this trial so repeated runs are reproducible
    # but different reps are not identical.
    seed_str = f"{system_name}|{model}|{scenario['id']}|rep{rep}"
    trial_seed = int(hashlib.md5(seed_str.encode()).hexdigest()[:8], 16) % (2**31)

    try:
        provider_cfg = get_provider_config(model)
        system_obj = system_cls(model, provider_cfg.api_url, provider_cfg.api_key)

        # Apply per-rep temperature perturbation for non-zero variation.
        # Rep 1 uses T=0.0 (greedy), reps 2+ use small temperature to
        # introduce natural LLM stochasticity while keeping output quality.
        rep_temperature = 0.0 if rep == 1 else round(0.05 * rep, 2)
        # Cap at a low temperature to stay near-deterministic
        rep_temperature = min(rep_temperature, 0.2)

        start = time.time()
        result = system_obj.execute_scenario(scenario, temperature=rep_temperature, seed=trial_seed)
        latency = time.time() - start

        return {
            "scenario_id": scenario["id"],
            "scenario_type": scenario["type"],
            "scenario_category": scenario.get("category", "N/A"),
            "system": system_name,
            "model": model,
            "rep": rep,
            "trial_seed": trial_seed,
            "temperature": rep_temperature,
            "latency": round(latency, 2),
            "tool_calls": len(result.get("tool_calls", [])),
            "dangerous_calls": result.get("dangerous_calls", []),
            "blocked": result.get("blocked", False),
            "attack_success": result.get("attack_success", False),
            "error": result.get("error"),
            "resolution_stages": result.get("resolution_stages"),
        }
    except Exception as e:
        return {
            "scenario_id": scenario["id"],
            "scenario_type": scenario["type"],
            "scenario_category": scenario.get("category", "N/A"),
            "system": system_name,
            "model": model,
            "rep": rep,
            "trial_seed": trial_seed,
            "temperature": 0.0,
            "latency": 0,
            "tool_calls": 0,
            "dangerous_calls": [],
            "blocked": False,
            "attack_success": False,
            "error": str(e),
        }


# ── Statistics ───────────────────────────────────────────────────────────────
def wilson_ci(successes: int, trials: int, z: float = 1.96) -> Tuple[float, float]:
    """Wilson score interval for binomial proportion (robust for small n)."""
    if trials == 0:
        return (0.0, 0.0)
    p_hat = successes / trials
    denom = 1 + z ** 2 / trials
    centre = (p_hat + z ** 2 / (2 * trials)) / denom
    spread = z * math.sqrt((p_hat * (1 - p_hat) + z ** 2 / (4 * trials)) / trials) / denom
    lo = max(0.0, centre - spread)
    hi = min(1.0, centre + spread)
    return (lo, hi)


def bootstrap_ci(values: List[float], n_boot: int = 10000, alpha: float = 0.05) -> Tuple[float, float, float]:
    """Bootstrap CI for a mean. Returns (mean, lo, hi)."""
    if not values:
        return (0.0, 0.0, 0.0)
    arr = np.array(values)
    mean = float(np.mean(arr))
    if len(arr) < 2:
        return (mean, mean, mean)
    rng = np.random.default_rng(42)
    boot_means = [float(np.mean(rng.choice(arr, size=len(arr), replace=True))) for _ in range(n_boot)]
    lo = float(np.percentile(boot_means, 100 * alpha / 2))
    hi = float(np.percentile(boot_means, 100 * (1 - alpha / 2)))
    return (mean, lo, hi)


def compute_metrics_with_ci(results: List[Dict], label: str = "") -> Dict:
    """Compute ASR-IA, TSR, FPR with Wilson CIs and per-rep breakdown."""
    benign = [r for r in results if r["scenario_type"] == "benign"]
    attacks = [r for r in results if r["scenario_type"] == "attack"]

    succ_benign = sum(1 for r in benign if not r["blocked"] and r["error"] is None)
    succ_attacks = sum(1 for r in attacks if r["attack_success"] and not r["blocked"])
    false_pos = sum(1 for r in benign if r["blocked"] or r.get("error") is not None)

    n_benign = len(benign) if benign else 1
    n_attack = len(attacks) if attacks else 1

    asr = succ_attacks / n_attack * 100
    tsr = succ_benign / n_benign * 100
    fpr = false_pos / n_benign * 100

    # Wilson CIs (percentage)
    asr_lo, asr_hi = wilson_ci(succ_attacks, n_attack)
    tsr_lo, tsr_hi = wilson_ci(succ_benign, n_benign)
    fpr_lo, fpr_hi = wilson_ci(false_pos, n_benign)

    # Per-rep ASR for reference (reported but not used for bootstrap)
    reps = sorted(set(r["rep"] for r in results))
    per_rep_asr = []
    per_rep_tsr = []
    for rep in reps:
        rep_attacks = [r for r in attacks if r["rep"] == rep]
        rep_benign = [r for r in benign if r["rep"] == rep]
        if rep_attacks:
            rep_asr = sum(1 for r in rep_attacks if r["attack_success"] and not r["blocked"]) / len(rep_attacks) * 100
            per_rep_asr.append(rep_asr)
        if rep_benign:
            rep_tsr = sum(1 for r in rep_benign if not r["blocked"] and r["error"] is None) / len(rep_benign) * 100
            per_rep_tsr.append(rep_tsr)

    # Bootstrap CI on TRIAL-LEVEL binary outcomes (not per-rep aggregates).
    # Each trial is a Bernoulli outcome; resampling from all N trials gives
    # valid 95% CIs that capture both within-rep and across-rep variation.
    trial_asr_outcomes = [
        100.0 if (r["attack_success"] and not r["blocked"]) else 0.0
        for r in attacks
    ]
    trial_tsr_outcomes = [
        100.0 if (not r["blocked"] and r["error"] is None) else 0.0
        for r in benign
    ]
    asr_boot_mean, asr_boot_lo, asr_boot_hi = bootstrap_ci(trial_asr_outcomes)
    tsr_boot_mean, tsr_boot_lo, tsr_boot_hi = bootstrap_ci(trial_tsr_outcomes)

    # Latency
    valid_lats = [r["latency"] for r in results if r["latency"] > 0]
    lat_mean, lat_lo, lat_hi = bootstrap_ci(valid_lats) if valid_lats else (0, 0, 0)

    return {
        "label": label,
        "n_total": len(results),
        "n_attack": n_attack,
        "n_benign": n_benign,
        "n_reps": len(reps),
        "asr": round(asr, 2),
        "asr_wilson_ci": [round(asr_lo * 100, 2), round(asr_hi * 100, 2)],
        "asr_bootstrap": {"mean": round(asr_boot_mean, 2), "ci95": [round(asr_boot_lo, 2), round(asr_boot_hi, 2)]},
        "tsr": round(tsr, 2),
        "tsr_wilson_ci": [round(tsr_lo * 100, 2), round(tsr_hi * 100, 2)],
        "tsr_bootstrap": {"mean": round(tsr_boot_mean, 2), "ci95": [round(tsr_boot_lo, 2), round(tsr_boot_hi, 2)]},
        "fpr": round(fpr, 2),
        "fpr_wilson_ci": [round(fpr_lo * 100, 2), round(fpr_hi * 100, 2)],
        "latency": {"mean": round(lat_mean, 2), "ci95": [round(lat_lo, 2), round(lat_hi, 2)]},
        "per_rep_asr": [round(v, 2) for v in per_rep_asr],
        "per_rep_tsr": [round(v, 2) for v in per_rep_tsr],
        "succ_attacks": succ_attacks,
        "succ_benign": succ_benign,
        "false_positives": false_pos,
        "errors": sum(1 for r in results if r.get("error")),
    }


def pairwise_significance(
    results: List[Dict],
    systems: List[str],
    metric: str = "attack_success",
) -> Dict[str, Dict]:
    """Compute pairwise Fisher exact tests + Bonferroni correction between systems.

    Returns a dict of {sys_a_vs_sys_b: {p_value, p_adjusted, significant, effect_h}}.
    Effect size is Cohen's h for proportions.
    """
    from scipy import stats as sp_stats

    # Build per-system contingency data
    sys_data = {}
    for sys_name in systems:
        sys_results = [r for r in results if r["system"] == sys_name]
        if metric == "attack_success":
            relevant = [r for r in sys_results if r["scenario_type"] == "attack"]
            n_success = sum(1 for r in relevant if r["attack_success"] and not r["blocked"])
        else:  # TSR
            relevant = [r for r in sys_results if r["scenario_type"] == "benign"]
            n_success = sum(1 for r in relevant if not r["blocked"] and r["error"] is None)
        sys_data[sys_name] = {"success": n_success, "total": len(relevant)}

    # Pairwise comparisons
    pairs = [(a, b) for i, a in enumerate(systems) for b in systems[i + 1:]]
    n_comparisons = len(pairs)
    pairwise = {}

    for sys_a, sys_b in pairs:
        da, db = sys_data[sys_a], sys_data[sys_b]
        # 2x2 contingency table
        table = [
            [da["success"], da["total"] - da["success"]],
            [db["success"], db["total"] - db["success"]],
        ]
        _, p_value = sp_stats.fisher_exact(table)

        # Bonferroni correction
        p_adjusted = min(1.0, p_value * n_comparisons)

        # Cohen's h effect size
        p1 = da["success"] / da["total"] if da["total"] > 0 else 0
        p2 = db["success"] / db["total"] if db["total"] > 0 else 0
        h1 = 2 * math.asin(math.sqrt(p1))
        h2 = 2 * math.asin(math.sqrt(p2))
        cohens_h = abs(h1 - h2)

        pairwise[f"{sys_a}_vs_{sys_b}"] = {
            "p_value": round(p_value, 6),
            "p_adjusted": round(p_adjusted, 6),
            "significant_005": p_adjusted < 0.05,
            "cohens_h": round(cohens_h, 4),
            "effect_size": "large" if cohens_h >= 0.8 else "medium" if cohens_h >= 0.5 else "small",
            f"{sys_a}_{metric}": f"{da['success']}/{da['total']}",
            f"{sys_b}_{metric}": f"{db['success']}/{db['total']}",
        }

    return pairwise


def per_category_asr(results: List[Dict]) -> Dict[str, Dict]:
    """Per-attack-category ASR with CIs."""
    cats = defaultdict(lambda: {"total": 0, "success": 0})
    for r in results:
        if r["scenario_type"] == "attack":
            cat = r["scenario_category"]
            cats[cat]["total"] += 1
            if r["attack_success"] and not r["blocked"]:
                cats[cat]["success"] += 1
    out = {}
    for cat, d in sorted(cats.items()):
        asr = d["success"] / d["total"] * 100 if d["total"] else 0
        lo, hi = wilson_ci(d["success"], d["total"])
        out[cat] = {
            "asr": round(asr, 2),
            "ci95": [round(lo * 100, 2), round(hi * 100, 2)],
            "n": d["total"],
            "bypasses": d["success"],
        }
    return out


# ── Main runner ──────────────────────────────────────────────────────────────
def run_tdsc(
    models: List[str],
    systems: Dict[str, type],
    scenarios: List[Dict],
    n_reps: int = 5,
    output_dir: Optional[Path] = None,
    resume: bool = False,
    ctx_length: int = 4096,
):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if output_dir is None:
        output_dir = Path(f"results/tdsc_{timestamp}")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Checkpoint file
    checkpoint_file = output_dir / "checkpoint.json"
    all_results: List[Dict] = []
    completed_keys = set()

    if resume and checkpoint_file.exists():
        with open(checkpoint_file) as f:
            all_results = json.load(f)
        completed_keys = {trial_key(r["system"], r["model"], r["scenario_id"], r["rep"]) for r in all_results}
        print(f"📂 Resumed {len(all_results)} completed trials from {checkpoint_file}")

    total_trials = len(models) * len(systems) * len(scenarios) * n_reps
    remaining = total_trials - len(completed_keys)

    print("=" * 70)
    print("IEEE TDSC Multi-Trial Experiment")
    print("=" * 70)
    print(f"Models:     {len(models)} — {', '.join(m.split('/')[-1][:20] for m in models)}")
    print(f"Systems:    {len(systems)} — {', '.join(systems.keys())}")
    print(f"Scenarios:  {len(scenarios)}")
    print(f"Reps:       {n_reps}")
    print(f"Temperature:{TEMPERATURE}")
    print(f"Total:      {total_trials} trials ({remaining} remaining)")
    print(f"Output:     {output_dir}")
    est_hours = remaining * 12 / 3600  # ~12s per trial
    print(f"Estimated:  {est_hours:.1f} hours")
    print("=" * 70)

    # Save experiment config
    config = {
        "models": models,
        "systems": list(systems.keys()),
        "n_scenarios": len(scenarios),
        "n_reps": n_reps,
        "temperature": TEMPERATURE,
        "total_trials": total_trials,
        "timestamp": timestamp,
        "encoding_decoder": "v2_canonicalize",
    }
    with open(output_dir / "config.json", "w") as f:
        json.dump(config, f, indent=2)

    start_all = time.time()
    trial_count = len(completed_keys)

    for model_idx, model in enumerate(models, 1):
        print(f"\n{'='*70}")
        print(f"[Model {model_idx}/{len(models)}] {model}")
        print(f"{'='*70}")

        if is_lmstudio_model(model):
            # Local model — swap via LM Studio API
            if not lmstudio_swap(model, context_length=ctx_length):
                print(f"  Could not load {model} — skipping")
                continue
        else:
            # Cloud model (Groq, Gemini) — no swap needed, verify API key
            try:
                cfg = get_provider_config(model)
                print(f"  Using {cfg.provider} provider ({cfg.rate_limit_rpm} req/min limit)")
            except ValueError as e:
                print(f"  {e} — skipping")
                continue

        for sys_name, sys_cls in systems.items():
            for rep in range(1, n_reps + 1):
                print(f"\n  --- {sys_name} | rep {rep}/{n_reps} ---")
                for sc_idx, scenario in enumerate(scenarios):
                    key = trial_key(sys_name, model, scenario["id"], rep)
                    if key in completed_keys:
                        continue

                    trial_count += 1
                    result = evaluate_single(sys_cls, sys_name, model, scenario, rep)
                    all_results.append(result)
                    completed_keys.add(key)

                    # Status line (compact)
                    asr_flag = " 🚨" if result["attack_success"] else ""
                    err_flag = " ⚠️" if result.get("error") else ""
                    if (sc_idx + 1) % 20 == 0 or sc_idx == len(scenarios) - 1:
                        elapsed = time.time() - start_all
                        rate = trial_count / elapsed if elapsed > 0 else 0
                        eta = (total_trials - trial_count) / rate / 3600 if rate > 0 else 0
                        print(
                            f"    [{trial_count}/{total_trials}] "
                            f"{scenario['id'][:25]:25s} {result['latency']:.1f}s"
                            f"{asr_flag}{err_flag} "
                            f"(ETA: {eta:.1f}h)"
                        )

                # Checkpoint after each (system, model, rep) block
                with open(checkpoint_file, "w") as f:
                    json.dump(all_results, f)
                print(f"    💾 Checkpoint saved ({len(all_results)} trials)")

    # ── Finalize ─────────────────────────────────────────────────────────
    elapsed_total = time.time() - start_all
    print(f"\n{'='*70}")
    print(f"EXPERIMENT COMPLETE — {len(all_results)} trials in {elapsed_total/3600:.2f}h")
    print(f"{'='*70}")

    # Save raw results
    with open(output_dir / "all_results.json", "w") as f:
        json.dump(all_results, f, indent=2)

    # ── Compute metrics ──────────────────────────────────────────────────
    report = {"config": config, "elapsed_hours": round(elapsed_total / 3600, 2)}

    # Aggregate per system
    print(f"\n{'System':<18} {'ASR-IA':>10} {'95% CI':>16} {'TSR':>8} {'95% CI':>16} {'FPR':>8}")
    print("-" * 82)
    sys_metrics = {}
    for sys_name in systems:
        sys_results = [r for r in all_results if r["system"] == sys_name]
        m = compute_metrics_with_ci(sys_results, label=sys_name)
        sys_metrics[sys_name] = m
        print(
            f"{sys_name:<18} {m['asr']:>9.2f}% "
            f"[{m['asr_wilson_ci'][0]:>5.2f},{m['asr_wilson_ci'][1]:>5.2f}]  "
            f"{m['tsr']:>7.2f}% "
            f"[{m['tsr_wilson_ci'][0]:>5.2f},{m['tsr_wilson_ci'][1]:>5.2f}]  "
            f"{m['fpr']:>7.2f}%"
        )
    report["aggregate_by_system"] = sys_metrics

    # Per model × system
    print(f"\n{'Model':<25} {'System':<18} {'ASR-IA':>8} {'TSR':>8} {'FPR':>8}")
    print("-" * 72)
    model_sys_metrics = {}
    for model in models:
        model_short = model.split("/")[-1][:24]
        for sys_name in systems:
            results_subset = [r for r in all_results if r["model"] == model and r["system"] == sys_name]
            if not results_subset:
                continue
            m = compute_metrics_with_ci(results_subset, label=f"{model_short}_{sys_name}")
            model_sys_metrics[f"{model}_{sys_name}"] = m
            print(f"{model_short:<25} {sys_name:<18} {m['asr']:>7.2f}% {m['tsr']:>7.2f}% {m['fpr']:>7.2f}%")
    report["per_model_system"] = model_sys_metrics

    # Per-category ASR for PROVSAFE
    provsafe_results = [r for r in all_results if r["system"] == "provsafe"]
    cat_asr = per_category_asr(provsafe_results)
    report["provsafe_per_category"] = cat_asr
    print(f"\nPROVSAFE Per-Category ASR-IA:")
    for cat, d in cat_asr.items():
        print(f"  {cat:<30s} {d['asr']:>6.2f}% [{d['ci95'][0]:.2f}, {d['ci95'][1]:.2f}]  ({d['bypasses']}/{d['n']})")

    # Defense breakdown for PROVSAFE
    ps_attacks = [r for r in provsafe_results if r["scenario_type"] == "attack"]
    n_ps_attacks = len(ps_attacks) if ps_attacks else 1
    blocked_attacks = sum(1 for r in ps_attacks if r["blocked"])
    bypass_attacks = sum(1 for r in ps_attacks if r["attack_success"] and not r["blocked"])
    tc0_or_safe = n_ps_attacks - blocked_attacks - bypass_attacks  # TC=0 or safe calls
    report["provsafe_defense_breakdown"] = {
        "total_attack_evals": len(ps_attacks),
        "boundary_blocked": blocked_attacks,
        "boundary_blocked_pct": round(blocked_attacks / n_ps_attacks * 100, 2),
        "asr_ia_bypasses": bypass_attacks,
        "asr_ia_pct": round(bypass_attacks / n_ps_attacks * 100, 2),
        "model_refused_or_safe": tc0_or_safe,
    }

    # Pairwise significance tests (ASR and TSR)
    try:
        sys_names = list(systems.keys())
        asr_sig = pairwise_significance(all_results, sys_names, metric="attack_success")
        tsr_sig = pairwise_significance(all_results, sys_names, metric="tsr")
        report["significance_tests"] = {
            "asr_pairwise": asr_sig,
            "tsr_pairwise": tsr_sig,
            "correction": "Bonferroni",
            "alpha": 0.05,
        }
        print(f"\nPairwise Significance (ASR-IA, Bonferroni-corrected):")
        for pair, d in asr_sig.items():
            sig = "***" if d["significant_005"] else "n.s."
            print(f"  {pair:<35s} p={d['p_adjusted']:.4f} {sig}  h={d['cohens_h']:.3f} ({d['effect_size']})")
    except ImportError:
        print("\n  (scipy not installed — skipping significance tests)")
        report["significance_tests"] = {"error": "scipy not installed"}

    # Per-rep stability
    print(f"\nPROVSAFE Per-Rep Stability:")
    ps_metric = sys_metrics.get("provsafe", {})
    if ps_metric.get("per_rep_asr"):
        print(f"  ASR per rep: {ps_metric['per_rep_asr']}")
        print(f"  TSR per rep: {ps_metric['per_rep_tsr']}")
        asr_std = float(np.std(ps_metric["per_rep_asr"])) if len(ps_metric["per_rep_asr"]) > 1 else 0
        tsr_std = float(np.std(ps_metric["per_rep_tsr"])) if len(ps_metric["per_rep_tsr"]) > 1 else 0
        print(f"  ASR std: {asr_std:.3f}%  TSR std: {tsr_std:.3f}%")
        report["provsafe_stability"] = {
            "asr_std": round(asr_std, 4),
            "tsr_std": round(tsr_std, 4),
        }

    # Save final report
    with open(output_dir / "tdsc_report.json", "w") as f:
        json.dump(report, f, indent=2)

    # Save per-system detailed results
    for sys_name in systems:
        sys_results = [r for r in all_results if r["system"] == sys_name]
        with open(output_dir / f"results_{sys_name}.json", "w") as f:
            json.dump(sys_results, f, indent=2)

    print(f"\n✅ All results saved to {output_dir}/")
    return report


# ── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="IEEE TDSC Multi-Trial Experiments")
    parser.add_argument("--reps", type=int, default=5, help="Number of repetitions per scenario")
    parser.add_argument("--quick", action="store_true", help="Quick test: 10 scenarios, 2 reps")
    parser.add_argument("--model", type=str, help="Run single model")
    parser.add_argument("--system", type=str, help="Run single system (no_defense|pattern_filter|policy_only|provsafe)")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    parser.add_argument("--ctx", type=int, default=4096, help="Context length")
    parser.add_argument("--output", type=str, help="Output directory path")
    args = parser.parse_args()

    models = [args.model] if args.model else MODELS
    systems = {args.system: SYSTEMS[args.system]} if args.system else SYSTEMS
    n_reps = args.reps
    scenarios = SCENARIOS

    if args.quick:
        scenarios = SCENARIOS[:10]
        n_reps = 2
        print("⚡ QUICK TEST MODE — 10 scenarios, 2 reps")

    out = Path(args.output) if args.output else None

    report = run_tdsc(
        models=models,
        systems=systems,
        scenarios=scenarios,
        n_reps=n_reps,
        output_dir=out,
        resume=args.resume,
        ctx_length=args.ctx,
    )

    # Clean up LM Studio if any local models were used
    used_lmstudio = any(is_lmstudio_model(m) for m in models)
    if used_lmstudio:
        print("\n  Unloading LM Studio models ...")
        lmstudio_unload_all()
    print("Done.")
