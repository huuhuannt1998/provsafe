"""
Smart evaluation runner - starts with validation, then offers full run.

Usage: python3 smart_eval.py
"""

import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from baseline_systems import create_system

API_URL = "http://cci-siscluster1.charlotte.edu:8080/api/chat/completions"
API_KEY = "sk-a6af2053d49649d2925ff91fef71cb65"

MODELS = ["openai/gpt-oss-120b", "OpenGVLab/InternVL3_5-30B-A3B", "Qwen/Qwen3-30B-A3B", "openai/gpt-oss-20b"]
SYSTEMS = ["no_defense", "pattern_filter", "policy_only", "provsafe"]

with open("scenarios_expanded.json") as f:
    ALL_SCENARIOS = json.load(f)

print("=" * 80)
print("PROVSAFE EVALUATION PLAN")
print("=" * 80)
print()
print("The full evaluation takes ~6-7 hours (1,600 LLM API calls)")
print()
print("Options:")
print("  1. Validation first (40 eval, ~10min) - recommended")
print("  2. Run full immediately (1,600 eval, ~7hrs)")
print()

choice = input("Choose [1/2]: ").strip()

if choice == "1":
    # Validation
    scenarios = ALL_SCENARIOS[:10]
    models = [MODELS[0]]
    mode = "validation"
    print(f"\n✓ Running validation: 10 scenarios, 1 model, 4 systems = 40 evaluations")
else:
    scenarios = ALL_SCENARIOS
    models = MODELS
    mode = "full"
    print(f"\n✓ Running full: 100 scenarios, 4 models, 4 systems = 1,600 evaluations")

print(f"Estimated time: {len(scenarios) * len(models) * len(SYSTEMS) * 15 / 60:.0f} minutes\n")
input("Press Enter to start...")

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_dir = Path(f"results/{mode}_{timestamp}")
output_dir.mkdir(parents=True, exist_ok=True)

results = []
start = time.time()
total = len(scenarios) * len(models) * len(SYSTEMS)
completed = 0

print()
for i, scenario in enumerate(scenarios, 1):
    print(f"\n[{i}/{len(scenarios)}] {scenario['id']}")
    for model in models:
        for system_type in SYSTEMS:
            try:
                sys_obj = create_system(system_type, model, API_URL, API_KEY)
                t0 = time.time()
                res = sys_obj.execute_scenario(scenario)
                lat = time.time() - t0
                
                results.append({
                    "scenario_id": scenario["id"],
                    "scenario_type": scenario["type"],
                    "system": system_type,
                    "model": model,
                    "latency": round(lat, 2),
                    "dangerous_calls": res.get("dangerous_calls", []),
                    "blocked": res.get("blocked", False),
                    "attack_success": res.get("attack_success", False),
                    "error": res.get("error")
                })
                
                status = "✓" if not res.get("error") else "✗"
                completed += 1
                
                # Progress
                elapsed = time.time() - start
                rate = completed / elapsed
                eta = int((total - completed) / rate) if rate > 0 else 0
                print(f"  {status} {system_type:15s} {lat:.1f}s  [ETA: {eta//60}m{eta%60}s]")
                
            except Exception as e:
                results.append({"error": str(e)})
                print(f"  ✗ {system_type:15s} Error: {str(e)[:50]}")

# Save
with open(output_dir / "results.json", "w") as f:
    json.dump(results, f, indent=2)

# Metrics
metrics = {}
for sys in SYSTEMS:
    sys_res = [r for r in results if r.get("system") == sys]
    attacks = [r for r in sys_res if r.get("scenario_type") == "attack"]
    asr = sum(1 for r in attacks if r.get("attack_success")) / len(attacks) * 100 if attacks else 0
    metrics[sys] = {"asr": round(asr, 1)}

print(f"\n\n{'System':<20} ASR")
print("-" * 30)
for sys, m in metrics.items():
    print(f"{sys:<20} {m['asr']}%")

print(f"\n✓ Complete in {int((time.time()-start)/60)}m")
print(f"✓ Saved to {output_dir}")

if mode == "validation":
    print("\nTo run full evaluation:")
    print("  python3 smart_eval.py  (choose option 2)")
