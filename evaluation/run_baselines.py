#!/usr/bin/env python3
"""
Run baseline systems (No Defense, Pattern Filter, Policy-Only) on the same
4 models and 200 scenarios used for the PROVSAFE evaluation.

Uses the LM Studio REST API to auto-load/unload models sequentially.

Usage:
    python run_baselines.py                 # Full run, all 4 models
    python run_baselines.py --quick         # Quick test (10 scenarios)
    python run_baselines.py --skip-done     # Skip models with existing results
    python run_baselines.py --model X       # Single model
"""

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import requests

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from baseline_systems import NoDefenseSystem, PatternFilterSystem, PolicyOnlySystem

# ── Configuration ────────────────────────────────────────────────────────────
LMSTUDIO_URL = "http://localhost:1234/v1/chat/completions"
LMSTUDIO_KEY = "lm-studio"
LMSTUDIO_API = "http://localhost:1234/api/v1"

# 4 models that produce tool calls reliably
MODELS = [
    "meta-llama-3.1-8b-instruct",  # 8B — Meta
    "qwen2.5-7b-instruct",  # 7B — Alibaba
    "gemma-2-9b-it",  # 9B — Google
    "phi-3.5-mini-instruct",  # 3B — Microsoft
]

BASELINES = {
    "no_defense": NoDefenseSystem,
    "pattern_filter": PatternFilterSystem,
    "policy_only": PolicyOnlySystem,
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


def lmstudio_unload(instance_id: str) -> bool:
    try:
        resp = requests.post(
            f"{LMSTUDIO_API}/models/unload",
            json={"instance_id": instance_id},
            timeout=30,
        )
        resp.raise_for_status()
        print(f"  🗑️  Unloaded {instance_id}")
        return True
    except requests.RequestException as e:
        print(f"  ⚠️  Failed to unload {instance_id}: {e}")
        return False


def lmstudio_unload_all() -> int:
    loaded = lmstudio_list_loaded()
    count = 0
    for inst_id in loaded:
        if lmstudio_unload(inst_id):
            count += 1
    if count:
        time.sleep(2)
    return count


def lmstudio_load(model: str, context_length: int = 4096) -> bool:
    print(f"  📥 Loading {model} (ctx={context_length}) ...")
    try:
        resp = requests.post(
            f"{LMSTUDIO_API}/models/load",
            json={
                "model": model,
                "context_length": context_length,
                "flash_attention": True,
            },
            timeout=300,
        )
        resp.raise_for_status()
        print(f"  ✅ {model} loaded")
        return True
    except requests.RequestException as e:
        print(f"  ❌ Failed to load {model}: {e}")
        return False


def lmstudio_swap(model: str, context_length: int = 4096) -> bool:
    print(f"\n🔄 Swapping to {model} ...")
    lmstudio_unload_all()
    if not lmstudio_load(model, context_length):
        return False
    for _ in range(6):
        loaded = lmstudio_list_loaded()
        if any(model in inst or inst in model for inst in loaded):
            print(f"  ✅ Verified {model} is ready")
            return True
        time.sleep(5)
    print("  ⚠️  Could not verify — proceeding anyway")
    return True


# ── Evaluation ───────────────────────────────────────────────────────────────
def evaluate_single(
    system_obj, system_name: str, model: str, scenario: Dict[str, Any]
) -> Dict[str, Any]:
    """Evaluate a single scenario with a given baseline system."""
    _model_short = model.split("/")[-1][:20]  # noqa: F841
    try:
        start_time = time.time()
        result = system_obj.execute_scenario(scenario)
        latency = time.time() - start_time

        eval_result = {
            "scenario_id": scenario["id"],
            "scenario_type": scenario["type"],
            "scenario_category": scenario.get("category", "N/A"),
            "system": system_name,
            "model": model,
            "latency": round(latency, 2),
            "tool_calls": len(result.get("tool_calls", [])),
            "dangerous_calls": result.get("dangerous_calls", []),
            "blocked": result.get("blocked", False),
            "attack_success": result.get("attack_success", False),
            "error": result.get("error"),
        }

        tc = eval_result["tool_calls"]
        status = "✓" if not eval_result["error"] else "✗"
        asr_flag = " 🚨ASR" if eval_result["attack_success"] else ""
        print(f"    {status} {system_name:16s} {latency:.1f}s TC:{tc}{asr_flag}")
        return eval_result

    except Exception as e:
        print(f"    ✗ {system_name:16s} ERROR: {str(e)[:60]}")
        return {
            "scenario_id": scenario["id"],
            "scenario_type": scenario["type"],
            "scenario_category": scenario.get("category", "N/A"),
            "system": system_name,
            "model": model,
            "latency": 0,
            "tool_calls": 0,
            "dangerous_calls": [],
            "blocked": False,
            "attack_success": False,
            "error": str(e),
        }


def compute_metrics(results: List[Dict], label: str) -> Dict[str, Any]:
    benign = [r for r in results if r["scenario_type"] == "benign"]
    attacks = [r for r in results if r["scenario_type"] == "attack"]

    successful_benign = sum(1 for r in benign if not r["blocked"] and r["error"] is None)
    successful_attacks = sum(1 for r in attacks if r["attack_success"] and not r["blocked"])

    valid_lats = [r["latency"] for r in results if r["latency"] > 0]

    tsr = (successful_benign / len(benign) * 100) if benign else 0
    asr = (successful_attacks / len(attacks) * 100) if attacks else 0
    avg_lat = (sum(valid_lats) / len(valid_lats)) if valid_lats else 0

    return {
        "system": label,
        "total_evaluations": len(results),
        "benign_count": len(benign),
        "attack_count": len(attacks),
        "tsr": round(tsr, 2),
        "asr": round(asr, 2),
        "avg_latency": round(avg_lat, 2),
        "successful_benign": successful_benign,
        "successful_attacks": successful_attacks,
        "errors": sum(1 for r in results if r.get("error")),
    }


def run_baselines_for_model(
    model: str,
    scenarios: List[Dict],
    output_dir: Path,
):
    """Run all 3 baselines for one model."""
    all_results: List[Dict[str, Any]] = []

    for i, scenario in enumerate(scenarios):
        print(
            f"\n  [{i+1}/{len(scenarios)}] {scenario['id']} "
            f"({scenario['type']}, {scenario.get('category', 'N/A')})"
        )

        for sys_name, sys_cls in BASELINES.items():
            system_obj = sys_cls(model, LMSTUDIO_URL, LMSTUDIO_KEY)
            result = evaluate_single(system_obj, sys_name, model, scenario)
            all_results.append(result)

        # Checkpoint
        with open(output_dir / "detailed_results.json", "w") as f:
            json.dump(all_results, f, indent=2)

    # Per-system metrics
    metrics = {}
    for sys_name in BASELINES:
        sys_results = [r for r in all_results if r["system"] == sys_name]
        metrics[sys_name] = compute_metrics(sys_results, sys_name)

    with open(output_dir / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    # Print summary
    print(f"\n{'='*60}")
    print(f"{'System':<18} {'ASR':>8} {'TSR':>8} {'Latency':>8}")
    print(f"{'-'*60}")
    for sys_name, m in metrics.items():
        print(f"{sys_name:<18} {m['asr']:>7.2f}% {m['tsr']:>7.2f}% {m['avg_latency']:>7.2f}s")
    print(f"{'='*60}")

    with open(output_dir / "summary_report.json", "w") as f:
        json.dump(
            {
                "model": model,
                "scenarios": len(scenarios),
                "baselines": list(BASELINES.keys()),
                "metrics": metrics,
            },
            f,
            indent=2,
        )

    print(f"✓ Saved to {output_dir}")
    return metrics


# ── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run baseline systems")
    parser.add_argument("--quick", action="store_true", help="First 10 scenarios only")
    parser.add_argument(
        "--skip-done", action="store_true", help="Skip models with existing results"
    )
    parser.add_argument("--model", type=str, help="Run a single model")
    parser.add_argument("--ctx", type=int, default=4096, help="Context length")
    args = parser.parse_args()

    models = [args.model] if args.model else MODELS
    scenarios = SCENARIOS[:10] if args.quick else SCENARIOS

    total = len(models)
    print(
        f"📊 Baseline evaluation — {total} models × {len(scenarios)} scenarios × {len(BASELINES)} baselines"
    )
    print(f"   Total evaluations: {total * len(scenarios) * len(BASELINES)}")
    print()

    start_all = time.time()

    for idx, model in enumerate(models, 1):
        model_tag = model.split("/")[-1].replace(":", "-")
        output_dir = Path(f"results/baselines_{model_tag}")

        if args.skip_done and output_dir.exists():
            print(f"⏭️  [{idx}/{total}] {model} — already done, skipping")
            continue

        print(f"\n{'='*70}")
        print(f"[{idx}/{total}] {model}")
        print(f"{'='*70}")

        # Auto-swap model
        if not lmstudio_swap(model, context_length=args.ctx):
            print(f"❌ Could not load {model} — skipping")
            continue

        output_dir.mkdir(parents=True, exist_ok=True)
        run_baselines_for_model(model, scenarios, output_dir)

    # Clean up
    print("\n🧹 Unloading last model ...")
    lmstudio_unload_all()

    elapsed = time.time() - start_all
    print(f"\n🏁 All baselines complete — {elapsed/60:.1f} minutes")

    # Aggregate summary across all models
    print(f"\n{'='*70}")
    print("AGGREGATE RESULTS (all models)")
    print(f"{'='*70}")
    print(f"{'System':<18} {'ASR':>8} {'TSR':>8}")
    print(f"{'-'*40}")

    for sys_name in BASELINES:
        all_r = []
        for model in models:
            tag = model.split("/")[-1].replace(":", "-")
            rdir = Path(f"results/baselines_{tag}")
            if not rdir.exists():
                continue
            with open(rdir / "detailed_results.json") as f:
                data = json.load(f)
            all_r.extend([r for r in data if r["system"] == sys_name])
        if all_r:
            m = compute_metrics(all_r, sys_name)
            print(f"{sys_name:<18} {m['asr']:>7.2f}% {m['tsr']:>7.2f}%")

    print(f"{'='*70}")
