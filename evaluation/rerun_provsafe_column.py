#!/usr/bin/env python3
"""
Re-run PROVSAFE column only (Option B).

After the conservative default fix (Stage 3: TRUSTED → UNTRUSTED),
we re-run only the PROVSAFE system to get updated numbers.
Baselines (No Defense, Pattern Filter, Policy-Only) are unaffected
since they don't use provenance resolution.

Supports two backends:
  - Local LM Studio  (default): http://localhost:1234/v1/chat/completions
  - Remote CCI Cluster:         --remote flag

Usage:
    python rerun_provsafe_column.py                  # Full re-run (local LM Studio)
    python rerun_provsafe_column.py --quick           # Quick test (10 scenarios)
    python rerun_provsafe_column.py --embedding       # Enable embedding provenance
    python rerun_provsafe_column.py --compare         # Compare old vs new results
    python rerun_provsafe_column.py --remote          # Use CCI cluster instead

Estimated time: ~2-4 hours local (2 models), ~4-6 hours remote (4 models)
"""

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import requests

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from baseline_systems import PROVSAFESystem

# ── Backend Configuration ────────────────────────────────────────────────────
# Local LM Studio (default)
LMSTUDIO_URL = "http://localhost:1234/v1/chat/completions"
LMSTUDIO_KEY = "lm-studio"  # LM Studio ignores this but the header is required

LMSTUDIO_MODELS = [
    "meta-llama-3.1-8b-instruct",  # 8B — Meta Llama 3.1
    "qwen2.5-7b-instruct",  # 7B — Qwen/Alibaba
    "gemma-2-9b-it",  # 9B — Google DeepMind
    "mistralai/mistral-7b-instruct-v0.3",  # 7B — Mistral AI
]

# Option A (sequential, one-by-one in LM Studio)
SEQUENTIAL_MODELS = [
    "meta-llama-3.1-8b-instruct",  # 8B  — Meta Llama 3.1
    "qwen2.5-7b-instruct",  # 7B  — Qwen/Alibaba
    "gemma-2-9b-it",  # 9B  — Google DeepMind
    "mistralai/mistral-7b-instruct-v0.3",  # 7B  — Mistral AI
    "phi-3.5-mini-instruct",  # 3B  — Microsoft Phi-3.5
    "openai/gpt-oss-20b",  # 20B — OpenAI (largest, run last)
]

# Remote CCI Cluster (--remote flag)
CCI_URL = "http://cci-siscluster1.charlotte.edu:8080/api/chat/completions"
CCI_KEY = os.getenv(
    "OPENWEBUI_API_KEY",
    "sk-a6af2053d49649d2925ff91fef71cb65",
)

CCI_MODELS = [
    "openai/gpt-oss-120b",
    "OpenGVLab/InternVL3_5-30B-A3B",
    "Qwen/Qwen3-30B-A3B-Thinking-2507-FP8",
    "openai/gpt-oss-20b",
]

# Resolved at runtime based on --remote flag
API_URL = LMSTUDIO_URL
API_KEY = LMSTUDIO_KEY
MODELS = LMSTUDIO_MODELS

# Load scenarios
with open(Path(__file__).parent / "scenarios_expanded.json", "r") as f:
    SCENARIOS = json.load(f)

# ── LM Studio REST API helpers ───────────────────────────────────────────────
LMSTUDIO_API = "http://localhost:1234/api/v1"


def lmstudio_list_loaded() -> List[str]:
    """Return instance IDs of all currently loaded LLMs."""
    try:
        resp = requests.get(f"{LMSTUDIO_API}/models", timeout=10)
        resp.raise_for_status()
        models = resp.json().get("models", [])
        loaded = []
        for m in models:
            if m.get("type") == "llm":
                for inst in m.get("loaded_instances", []):
                    loaded.append(inst["id"])
        return loaded
    except requests.RequestException as e:
        print(f"  ⚠️  Could not list models: {e}")
        return []


def lmstudio_unload(instance_id: str) -> bool:
    """Unload a specific model instance."""
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
    """Unload every loaded LLM to free RAM. Returns count unloaded."""
    loaded = lmstudio_list_loaded()
    count = 0
    for inst_id in loaded:
        if lmstudio_unload(inst_id):
            count += 1
    if count:
        time.sleep(2)  # give LM Studio a moment to release memory
    return count


def lmstudio_load(model: str, context_length: int = 4096) -> bool:
    """Load a model into LM Studio with flash_attention enabled."""
    print(f"  📥 Loading {model} (ctx={context_length}) ...")
    try:
        resp = requests.post(
            f"{LMSTUDIO_API}/models/load",
            json={
                "model": model,
                "context_length": context_length,
                "flash_attention": True,
            },
            timeout=300,  # large models can take minutes to load
        )
        resp.raise_for_status()
        print(f"  ✅ {model} loaded")
        return True
    except requests.RequestException as e:
        print(f"  ❌ Failed to load {model}: {e}")
        return False


def lmstudio_swap(model: str, context_length: int = 4096) -> bool:
    """Unload everything, then load the given model. Returns True on success."""
    print(f"\n🔄 Swapping to {model} ...")
    lmstudio_unload_all()
    if not lmstudio_load(model, context_length):
        return False
    # Quick health-check: verify it shows up as loaded
    for attempt in range(6):
        loaded = lmstudio_list_loaded()
        # LM Studio may shorten the instance id (e.g. drop publisher prefix)
        if any(model in inst or inst in model for inst in loaded):
            print(f"  ✅ Verified {model} is ready")
            return True
        time.sleep(5)
    print("  ⚠️  Model loaded but could not verify — proceeding anyway")
    return True  # optimistic: the load call succeeded


def evaluate_single(model: str, scenario: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate a single scenario with PROVSAFE."""
    model_short = model.split("/")[-1][:20]

    try:
        system = PROVSAFESystem(model, API_URL, API_KEY)
        start_time = time.time()
        result = system.execute_scenario(scenario)
        latency = time.time() - start_time

        eval_result = {
            "scenario_id": scenario["id"],
            "scenario_type": scenario["type"],
            "scenario_category": scenario.get("category", "N/A"),
            "system": "provsafe",
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
        print(f"  {status} {model_short:20s} provsafe        {latency:.1f}s TC:{tc}{asr_flag}")
        return eval_result

    except Exception as e:
        print(f"  ✗ {model_short:20s} provsafe        ERROR: {str(e)[:60]}")
        return {
            "scenario_id": scenario["id"],
            "scenario_type": scenario["type"],
            "scenario_category": scenario.get("category", "N/A"),
            "system": "provsafe",
            "model": model,
            "latency": 0,
            "tool_calls": 0,
            "dangerous_calls": [],
            "blocked": False,
            "attack_success": False,
            "error": str(e),
        }


def compute_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute PROVSAFE-only metrics."""
    benign = [r for r in results if r["scenario_type"] == "benign"]
    attacks = [r for r in results if r["scenario_type"] == "attack"]

    successful_benign = sum(1 for r in benign if not r["blocked"] and r["error"] is None)
    successful_attacks = sum(1 for r in attacks if r["attack_success"] and not r["blocked"])

    valid_lats = [r["latency"] for r in results if r["latency"] > 0]

    tsr = (successful_benign / len(benign) * 100) if benign else 0
    asr = (successful_attacks / len(attacks) * 100) if attacks else 0
    avg_lat = (sum(valid_lats) / len(valid_lats)) if valid_lats else 0

    return {
        "total_evaluations": len(results),
        "benign_count": len(benign),
        "attack_count": len(attacks),
        "tsr": round(tsr, 2),
        "asr": round(asr, 2),
        "avg_latency": round(avg_lat, 2),
        "successful_benign": successful_benign,
        "successful_attacks": successful_attacks,
        "errors": sum(1 for r in results if r.get("error")),
        "code_version": "conservative_default_v2",
        "embedding_enabled": os.environ.get("PROVSAFE_EMBEDDING", "1"),
    }


def compare_with_old(new_metrics: Dict, old_results_dir: str = None):
    """Compare new vs old PROVSAFE results."""
    if not old_results_dir:
        # Find most recent full eval
        results_dir = Path(__file__).parent / "results"
        candidates = sorted(results_dir.glob("full_eval_*"), reverse=True)
        if not candidates:
            print("No old results found for comparison.")
            return
        old_results_dir = candidates[0]

    old_metrics_path = Path(old_results_dir) / "metrics.json"
    if not old_metrics_path.exists():
        print(f"No metrics.json in {old_results_dir}")
        return

    with open(old_metrics_path) as f:
        old_metrics = json.load(f)

    old_ps = old_metrics.get("provsafe", {})

    print("\n" + "=" * 60)
    print("COMPARISON: Old (TRUSTED default) vs New (UNTRUSTED default)")
    print("=" * 60)
    print(f"{'Metric':<20} {'Old':>12} {'New':>12} {'Delta':>12}")
    print("-" * 60)

    for key in ["asr", "tsr", "avg_latency"]:
        old_val = old_ps.get(key, 0)
        new_val = new_metrics.get(key, 0)
        delta = new_val - old_val
        sign = "+" if delta > 0 else ""
        print(f"{key:<20} {old_val:>11.2f}% {new_val:>11.2f}% {sign}{delta:>10.2f}%")

    print("-" * 60)
    print()

    if new_metrics["asr"] <= old_ps.get("asr", 999):
        print("✅ ASR same or improved (expected — conservative default blocks more)")
    else:
        print("⚠️  ASR increased — investigate which scenarios now succeed")

    if new_metrics["tsr"] >= old_ps.get("tsr", 0) * 0.95:
        print("✅ TSR within 5% of old (acceptable)")
    else:
        print("⚠️  TSR dropped >5% — false positive increase, investigate")


def run_rerun(
    models: List[str],
    quick_test: bool = False,
    do_compare: bool = False,
    output_tag: str | None = None,
):
    """Re-run PROVSAFE column."""
    print("=" * 80)
    print("PROVSAFE Re-Run (Conservative Default Fix)")
    print("=" * 80)
    print("Code change: Stage 3 _resolve_argument() now returns UNTRUSTED (was TRUSTED)")
    print(f"Embedding enabled: {os.environ.get('PROVSAFE_EMBEDDING', '1')}")
    print()

    if quick_test:
        print("⚠️  QUICK TEST — first 10 scenarios only")
        scenarios = SCENARIOS[:10]
    else:
        scenarios = SCENARIOS

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag = f"_{output_tag}" if output_tag else ""
    output_dir = Path(f"results/provsafe_rerun_{timestamp}{tag}")
    output_dir.mkdir(parents=True, exist_ok=True)

    all_results: List[Dict[str, Any]] = []

    print(f"Scenarios: {len(scenarios)}")
    print(f"Models: {len(models)}")
    print(f"Total evaluations: {len(scenarios) * len(models)}")
    est_hours = len(scenarios) * len(models) * 15 / 3600
    print(f"Estimated time: {est_hours:.1f} hours")
    print()

    start_time = time.time()

    for i, scenario in enumerate(scenarios):
        print(
            f"\n[{i+1}/{len(scenarios)}] {scenario['id']} ({scenario['type']}, {scenario.get('category', 'N/A')})"
        )

        for model in models:
            result = evaluate_single(model, scenario)
            all_results.append(result)

        # Checkpoint after each scenario
        with open(output_dir / "detailed_results.json", "w") as f:
            json.dump(all_results, f, indent=2)

    # Compute final metrics
    metrics = compute_metrics(all_results)
    elapsed = time.time() - start_time

    print("\n" + "=" * 80)
    print("RESULTS")
    print("=" * 80)
    print(f"ASR:  {metrics['asr']:.2f}%")
    print(f"TSR:  {metrics['tsr']:.2f}%")
    print(f"Avg Latency: {metrics['avg_latency']:.2f}s")
    print(f"Errors: {metrics['errors']}")
    print(f"Time: {elapsed/3600:.2f} hours")

    # Per-category breakdown
    from collections import defaultdict

    cat_results = defaultdict(lambda: {"total": 0, "success": 0})
    for r in all_results:
        if r["scenario_type"] == "attack":
            cat = r["scenario_category"]
            cat_results[cat]["total"] += 1
            if r["attack_success"] and not r["blocked"]:
                cat_results[cat]["success"] += 1

    print("\nPer-Category ASR:")
    for cat, data in sorted(cat_results.items()):
        cat_asr = data["success"] / data["total"] * 100 if data["total"] > 0 else 0
        print(f"  {cat:30s} {cat_asr:6.2f}% ({data['success']}/{data['total']})")

    # Save
    report = {
        "timestamp": timestamp,
        "code_version": "conservative_default_v2",
        "embedding_enabled": os.environ.get("PROVSAFE_EMBEDDING", "1"),
        "scenarios": len(scenarios),
        "models": models,
        "total_evaluations": len(all_results),
        "elapsed_seconds": round(elapsed, 2),
        "metrics": metrics,
    }

    with open(output_dir / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    with open(output_dir / "summary_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n✓ Saved to {output_dir}")

    if do_compare:
        compare_with_old(metrics)

    return metrics


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Re-run PROVSAFE column")
    parser.add_argument("--quick", action="store_true", help="Run only first 10 scenarios")
    parser.add_argument("--embedding", action="store_true", help="Enable embedding provenance")
    parser.add_argument("--compare", action="store_true", help="Compare with previous results")
    parser.add_argument("--remote", action="store_true", help="Use CCI cluster backend")
    parser.add_argument("--model", type=str, help="Run a single model id")
    parser.add_argument(
        "--sequential",
        action="store_true",
        help="Run models one-by-one, auto-loading via LM Studio API",
    )
    parser.add_argument(
        "--skip-done",
        action="store_true",
        help="Skip models that already have result dirs in results/",
    )
    parser.add_argument(
        "--ctx",
        type=int,
        default=4096,
        help="Context length for LM Studio model loading (default 4096)",
    )
    args = parser.parse_args()

    if args.remote:
        API_URL = CCI_URL
        API_KEY = CCI_KEY
        base_models = CCI_MODELS
        print("🌐 Using REMOTE CCI Cluster")
    else:
        API_URL = LMSTUDIO_URL
        API_KEY = LMSTUDIO_KEY
        base_models = LMSTUDIO_MODELS
        print("💻 Using LOCAL LM Studio (localhost:1234)")

    if args.embedding:
        os.environ["PROVSAFE_EMBEDDING"] = "1"
        print("🔬 Embedding provenance ENABLED")

    print(f"📡 API: {API_URL}")

    if args.sequential:
        models_to_run = SEQUENTIAL_MODELS if not args.remote else CCI_MODELS
        total = len(models_to_run)
        print(f"🧭 Sequential mode — {total} models, auto-load via LM Studio API")
        print(f"   Context length: {args.ctx}")
        print()

        for idx, model in enumerate(models_to_run, 1):
            model_tag = model.split("/")[-1].replace(":", "-")

            # --skip-done: check if results already exist for this model
            if args.skip_done:
                existing = list(Path("results").glob(f"provsafe_rerun_*_{model_tag}"))
                if existing:
                    print(
                        f"⏭️  [{idx}/{total}] {model} — already done ({existing[0].name}), skipping"
                    )
                    continue

            print(f"\n{'='*70}")
            print(f"[{idx}/{total}] {model}")
            print(f"{'='*70}")

            # Auto-swap: unload previous, load this model
            if not args.remote:
                if not lmstudio_swap(model, context_length=args.ctx):
                    print(f"❌ Could not load {model} — skipping")
                    continue

            run_rerun(
                models=[model],
                quick_test=args.quick,
                do_compare=args.compare,
                output_tag=model_tag,
            )

        # Clean up: unload last model to free RAM
        if not args.remote:
            print("\n🧹 Unloading last model to free RAM ...")
            lmstudio_unload_all()

        print(f"\n🏁 Sequential run complete — {total} models")
        sys.exit(0)

    models = [args.model] if args.model else base_models
    print(f"🤖 Models: {models}")
    print()

    run_rerun(models=models, quick_test=args.quick, do_compare=args.compare)
