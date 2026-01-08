"""
Full evaluation script for PROVSAFE publication.

Runs 100 scenarios across 4 models and 4 systems:
- No Defense (baseline)
- Pattern Filter (naive defense)
- Policy-Only (ablation)
- PROVSAFE (full system)

Total: 100 scenarios × 4 models × 4 systems = 1,600 evaluations
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
from baseline_systems import create_system


# Configuration
API_URL = "http://cci-siscluster1.charlotte.edu:8080/api/chat/completions"
API_KEY = "sk-a6af2053d49649d2925ff91fef71cb65"

MODELS = [
    "openai/gpt-oss-120b",
    "OpenGVLab/InternVL3_5-30B-A3B",
    "Qwen/Qwen3-30B-A3B-Thinking-2507-FP8",
    "openai/gpt-oss-20b"
]

SYSTEMS = ["no_defense", "pattern_filter", "policy_only", "provsafe", "provsafe_hybrid"]

# Load scenarios
with open("scenarios_expanded.json", "r") as f:
    SCENARIOS = json.load(f)


def evaluate_single(system_type: str, model: str, scenario: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate single scenario with given system and model."""
    
    model_short = model.split('/')[-1][:20]
    
    try:
        # Create system instance
        system = create_system(system_type, model, API_URL, API_KEY)
        
        # Execute scenario
        start_time = time.time()
        result = system.execute_scenario(scenario)
        latency = time.time() - start_time
        
        # Compile evaluation result
        eval_result = {
            "scenario_id": scenario["id"],
            "scenario_type": scenario["type"],
            "scenario_category": scenario.get("category", "N/A"),
            "system": system_type,
            "model": model,
            "latency": round(latency, 2),
            "tool_calls": len(result.get("tool_calls", [])),
            "dangerous_calls": result.get("dangerous_calls", []),
            "blocked": result.get("blocked", False),
            "attack_success": result.get("attack_success", False),
            "error": result.get("error")
        }
        
        tc = eval_result["tool_calls"]
        status = '✓' if not eval_result["error"] else '✗'
        print(f"  {status} {model_short:20s} {system_type:15s} {latency:.1f}s TC:{tc}")
        return eval_result
        
    except Exception as e:
        print(f"  ✗ {model_short:20s} {system_type:15s} ERROR: {str(e)[:40]}")
        return {
            "scenario_id": scenario["id"],
            "scenario_type": scenario["type"],
            "scenario_category": scenario.get("category", "N/A"),
            "system": system_type,
            "model": model,
            "latency": 0,
            "tool_calls": 0,
            "dangerous_calls": [],
            "blocked": False,
            "attack_success": False,
            "error": str(e)
        }


def compute_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute evaluation metrics."""
    
    metrics = {}
    
    # Group by system and scenario type
    for system in SYSTEMS:
        system_results = [r for r in results if r["system"] == system]
        
        # Benign scenarios
        benign_results = [r for r in system_results if r["scenario_type"] == "benign"]
        successful_benign = sum(1 for r in benign_results if not r["blocked"] and r["error"] is None)
        tsr = (successful_benign / len(benign_results) * 100) if benign_results else 0
        
        # Attack scenarios
        attack_results = [r for r in system_results if r["scenario_type"] == "attack"]
        successful_attacks = sum(1 for r in attack_results if r["attack_success"] and not r["blocked"])
        asr = (successful_attacks / len(attack_results) * 100) if attack_results else 0
        
        # Latency
        valid_latencies = [r["latency"] for r in system_results if r["latency"] > 0]
        avg_latency = (sum(valid_latencies) / len(valid_latencies)) if valid_latencies else 0
        
        metrics[system] = {
            "total_scenarios": len(system_results),
            "benign_count": len(benign_results),
            "attack_count": len(attack_results),
            "tsr": round(tsr, 2),
            "asr": round(asr, 2),
            "avg_latency": round(avg_latency, 2),
            "successful_benign": successful_benign,
            "successful_attacks": successful_attacks
        }
    
    return metrics


def run_full_evaluation(quick_test: bool = False, resume: bool = True):
    """Run full evaluation across all systems and models."""
    
    print("=" * 80)
    print("PROVSAFE Full Evaluation")
    print("=" * 80)
    print()
    
    if quick_test:
        print("⚠️  QUICK TEST MODE - Using first 10 scenarios only")
        scenarios = SCENARIOS[:10]
        mode = "quick"
    else:
        scenarios = SCENARIOS
        mode = "full"
    
    # Setup output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(f"results/{mode}_eval_{timestamp}")
    
    # Check for existing run to resume
    all_results = []
    start_scenario_idx = 0
    
    if resume:
        # Find most recent run
        existing_runs = sorted(Path("results").glob(f"{mode}_eval_*"), reverse=True)
        if existing_runs and (existing_runs[0] / "detailed_results.json").exists():
            output_dir = existing_runs[0]
            with open(output_dir / "detailed_results.json") as f:
                all_results = json.load(f)
            
            # Find last completed scenario
            if all_results:
                completed_scenarios = set(r["scenario_id"] for r in all_results)
                start_scenario_idx = next(
                    (i for i, s in enumerate(scenarios) if s["id"] not in completed_scenarios),
                    len(scenarios)
                )
                print(f"📁 RESUMING from {output_dir.name}")
                print(f"   Already completed: {len(all_results)} evaluations")
                print(f"   Starting from scenario {start_scenario_idx + 1}/{len(scenarios)}")
                print()
    
    if start_scenario_idx == 0:
        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"📁 New evaluation: {output_dir.name}")
        print()
    
    print(f"Scenarios: {len(scenarios)}")
    print(f"Models: {len(MODELS)}")
    print(f"Systems: {len(SYSTEMS)}")
    print(f"Total evaluations: {len(scenarios) * len(MODELS) * len(SYSTEMS)}")
    print(f"Remaining: {(len(scenarios) - start_scenario_idx) * len(MODELS) * len(SYSTEMS)}")
    print()
    
    # Estimate time
    avg_time_per_eval = 15  # seconds
    remaining_evals = (len(scenarios) - start_scenario_idx) * len(MODELS) * len(SYSTEMS)
    total_time = remaining_evals * avg_time_per_eval
    hours = total_time / 3600
    print(f"Estimated time: {hours:.1f} hours")
    print()
    print("Starting evaluation...")
    print()
    
    start_time = time.time()
    
    # Run evaluations
    for i in range(start_scenario_idx, len(scenarios)):
        scenario = scenarios[i]
        print(f"\n[{i+1}/{len(scenarios)}] Scenario: {scenario['id']} ({scenario['type']})")
        
        for model in MODELS:
            model_short = model.split('/')[-1][:20]
            
            for system_type in SYSTEMS:
                # Skip if already evaluated (in case of partial scenario completion)
                existing = next(
                    (r for r in all_results 
                     if r["scenario_id"] == scenario["id"] 
                     and r["model"] == model 
                     and r["system"] == system_type),
                    None
                )
                
                if existing:
                    print(f"  ↻ {model_short:20s} {system_type:15s} (cached)")
                    continue
                
                result = evaluate_single(system_type, model, scenario)
                all_results.append(result)
        
        # Save progress after each scenario
        with open(output_dir / "detailed_results.json", "w") as f:
            json.dump(all_results, f, indent=2)
        
        with open(output_dir / "progress.json", "w") as f:
            json.dump({
                "completed_scenarios": i + 1,
                "total_scenarios": len(scenarios),
                "total_evaluations": len(all_results),
                "last_update": datetime.now().isoformat()
            }, f, indent=2)
    
    # Compute metrics
    print("\n" + "=" * 80)
    print("Computing Metrics...")
    print("=" * 80)
    print()
    
    metrics = compute_metrics(all_results)
    
    # Print summary
    print("\nResults Summary:")
    print("-" * 80)
    print(f"{'System':<20} {'TSR':<10} {'ASR':<10} {'Avg Latency':<15}")
    print("-" * 80)
    
    for system in SYSTEMS:
        m = metrics[system]
        print(f"{system:<20} {m['tsr']:>9.2f}% {m['asr']:>9.2f}% {m['avg_latency']:>14.2f}s")
    
    print("-" * 80)
    
    # Save metrics
    with open(output_dir / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    
    # Save summary report
    elapsed = time.time() - start_time
    report = {
        "timestamp": timestamp,
        "scenarios": len(scenarios),
        "models": MODELS,
        "systems": SYSTEMS,
        "total_evaluations": len(all_results),
        "elapsed_time": round(elapsed, 2),
        "metrics": metrics
    }
    
    with open(output_dir / "summary_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n✓ Results saved to {output_dir}")
    print(f"✓ Total time: {elapsed/3600:.2f} hours")
    
    # Key findings
    print("\n" + "=" * 80)
    print("KEY FINDINGS")
    print("=" * 80)
    
    no_def_asr = metrics["no_defense"]["asr"]
    provsafe_asr = metrics["provsafe"]["asr"]
    reduction = ((no_def_asr - provsafe_asr) / no_def_asr * 100) if no_def_asr > 0 else 0
    
    print(f"\n1. Attack Success Rate (ASR):")
    print(f"   - No Defense: {no_def_asr:.1f}%")
    print(f"   - Pattern Filter: {metrics['pattern_filter']['asr']:.1f}%")
    print(f"   - Policy-Only: {metrics['policy_only']['asr']:.1f}%")
    print(f"   - PROVSAFE: {provsafe_asr:.1f}%")
    print(f"   → PROVSAFE reduces ASR by {reduction:.1f}% vs No Defense")
    
    print(f"\n2. Task Success Rate (TSR):")
    print(f"   - No Defense: {metrics['no_defense']['tsr']:.1f}%")
    print(f"   - Pattern Filter: {metrics['pattern_filter']['tsr']:.1f}%")
    print(f"   - Policy-Only: {metrics['policy_only']['tsr']:.1f}%")
    print(f"   - PROVSAFE: {metrics['provsafe']['tsr']:.1f}%")
    
    print(f"\n3. Performance:")
    print(f"   - Average latency: {metrics['provsafe']['avg_latency']:.2f}s")
    print(f"   - Overhead vs No Defense: +{metrics['provsafe']['avg_latency'] - metrics['no_defense']['avg_latency']:.2f}s")


if __name__ == "__main__":
    import sys
    
    # Check for flags
    quick_test = "--quick" in sys.argv
    no_resume = "--no-resume" in sys.argv
    
    run_full_evaluation(quick_test=quick_test, resume=not no_resume)
