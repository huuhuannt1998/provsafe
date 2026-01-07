#!/usr/bin/env python3
"""
Full Evaluation: 100 scenarios × 4 models × 4 systems = 1,600 evaluations
Estimated time: 6-7 hours
"""
import json
import time
from pathlib import Path
from datetime import datetime, timedelta
import baseline_systems

# Load scenarios
with open('scenarios_expanded.json') as f:
    ALL_SCENARIOS = json.load(f)

# Configuration
MODELS = [
    "openai/gpt-oss-120b",
    "OpenGVLab/InternVL3_5-30B-A3B",
    "Qwen/Qwen3-30B-A3B",
    "openai/gpt-oss-20b"
]
SYSTEMS = ["no_defense", "pattern_filter", "policy_only", "provsafe"]
API_URL = "http://cci-siscluster1.charlotte.edu:8080/api/chat/completions"
API_KEY = "sk-a6af2053d49649d2925ff91fef71cb65"

# Setup
scenarios = ALL_SCENARIOS
total_evals = len(scenarios) * len(MODELS) * len(SYSTEMS)
output_dir = Path("results/full_evaluation")
output_dir.mkdir(parents=True, exist_ok=True)
checkpoint_file = output_dir / f"checkpoint_{int(time.time())}.json"
results_file = output_dir / f"results_{int(time.time())}.json"

print(f"\n{'='*60}")
print(f"FULL EVALUATION - PROVSAFE Baseline Comparison")
print(f"{'='*60}")
print(f"Scenarios:  {len(scenarios)} (20 benign + 80 attacks)")
print(f"Models:     {len(MODELS)}")
print(f"Systems:    {len(SYSTEMS)}")
print(f"Total:      {total_evals} evaluations")
print(f"Estimated:  6-7 hours")
print(f"Started:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"{'='*60}\n")

results = []
start_time = time.time()
completed = 0

# Main evaluation loop
for scenario_idx, scenario in enumerate(scenarios, 1):
    print(f"\n[{scenario_idx}/{len(scenarios)}] {scenario['id']} ({scenario['category']})")
    
    for model in MODELS:
        model_short = model.split('/')[-1][:20]
        
        for sys_name in SYSTEMS:
            eval_start = time.time()
            
            try:
                # Create system
                system = baseline_systems.create_system(sys_name, model, API_URL, API_KEY)
                
                # Execute scenario
                result = system.execute_scenario(scenario)
                elapsed = time.time() - eval_start
                
                # Store result
                results.append({
                    "scenario_id": scenario["id"],
                    "scenario_category": scenario["category"],
                    "system": sys_name,
                    "model": model,
                    "attack_success": result.get("attack_success", False),
                    "blocked": result.get("blocked", False),
                    "error": result.get("error"),
                    "num_tool_calls": len(result.get("tool_calls", [])),
                    "num_dangerous_calls": len(result.get("dangerous_calls", [])),
                    "elapsed_sec": elapsed,
                    "timestamp": datetime.now().isoformat()
                })
                
                # Update progress
                completed += 1
                elapsed_total = time.time() - start_time
                avg_per_eval = elapsed_total / completed
                remaining = total_evals - completed
                eta_seconds = avg_per_eval * remaining
                eta = datetime.now() + timedelta(seconds=eta_seconds)
                
                status = "✓" if not result.get("error") else "✗"
                print(f"  {status} {sys_name:15} {model_short:20} {elapsed:5.1f}s  "
                      f"[{completed}/{total_evals}] ETA: {eta.strftime('%H:%M')}")
                
            except Exception as e:
                elapsed = time.time() - eval_start
                print(f"  ✗ {sys_name:15} {model_short:20} Error: {str(e)[:40]}")
                results.append({
                    "scenario_id": scenario["id"],
                    "scenario_category": scenario["category"],
                    "system": sys_name,
                    "model": model,
                    "error": str(e),
                    "elapsed_sec": elapsed,
                    "timestamp": datetime.now().isoformat()
                })
                completed += 1
    
    # Checkpoint every 10 scenarios
    if scenario_idx % 10 == 0:
        with open(checkpoint_file, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n  💾 Checkpoint saved ({len(results)} results)")

# Final save
with open(results_file, "w") as f:
    json.dump(results, f, indent=2)

# Compute comprehensive metrics
print(f"\n{'='*60}")
print("FINAL RESULTS")
print(f"{'='*60}\n")

# Overall metrics by system
print("Attack Success Rate (ASR) by System:")
print(f"{'System':<15} {'Overall':<10} {'By Model'}")
print(f"{'-'*60}")

for sys_name in SYSTEMS:
    sys_results = [r for r in results if r["system"] == sys_name and not r.get("error")]
    attack_results = [r for r in sys_results if r["scenario_category"] != "benign"]
    
    if attack_results:
        # Overall ASR
        attacks_succeeded = sum(1 for r in attack_results if r["attack_success"])
        overall_asr = attacks_succeeded / len(attack_results) * 100
        
        # Per-model ASR
        model_asrs = []
        for model in MODELS:
            model_attack_results = [r for r in attack_results if r["model"] == model]
            if model_attack_results:
                model_attacks = sum(1 for r in model_attack_results if r["attack_success"])
                model_asr = model_attacks / len(model_attack_results) * 100
                model_asrs.append(f"{model_asr:.1f}%")
            else:
                model_asrs.append("N/A")
        
        print(f"{sys_name:<15} {overall_asr:>5.1f}%     {', '.join(model_asrs)}")

# ASR by attack category
print(f"\n{'='*60}")
print("Attack Success Rate by Category:")
print(f"{'Category':<20} {'No Def':<10} {'Pattern':<10} {'Policy':<10} {'PROVSAFE':<10}")
print(f"{'-'*60}")

categories = sorted(set(r["scenario_category"] for r in results if r["scenario_category"] != "benign"))
for category in categories:
    cat_line = f"{category:<20}"
    for sys_name in SYSTEMS:
        sys_cat_results = [r for r in results 
                          if r["system"] == sys_name 
                          and r["scenario_category"] == category
                          and not r.get("error")]
        if sys_cat_results:
            attacks = sum(1 for r in sys_cat_results if r["attack_success"])
            asr = attacks / len(sys_cat_results) * 100
            cat_line += f" {asr:>5.1f}%    "
        else:
            cat_line += "   N/A     "
    print(cat_line)

# Error summary
print(f"\n{'='*60}")
errors = [r for r in results if r.get("error")]
if errors:
    print(f"Errors: {len(errors)} / {total_evals}")
    error_counts = {}
    for err in errors:
        key = f"{err['system']} - {err.get('error', 'Unknown')[:50]}"
        error_counts[key] = error_counts.get(key, 0) + 1
    for key, count in sorted(error_counts.items(), key=lambda x: -x[1])[:5]:
        print(f"  {count:3d}x {key}")
else:
    print("No errors!")

# Timing
elapsed_total = time.time() - start_time
print(f"\n{'='*60}")
print(f"✓ Complete in {elapsed_total/3600:.2f} hours")
print(f"✓ Results saved to {results_file}")
print(f"{'='*60}\n")
