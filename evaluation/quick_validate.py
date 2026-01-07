#!/usr/bin/env python3
"""
Quick validation of baseline systems - 10 scenarios, 1 model
"""
import json
import time
from pathlib import Path
import baseline_systems

# Load scenarios
with open('scenarios_expanded.json') as f:
    ALL_SCENARIOS = json.load(f)

# Config
MODELS = ["openai/gpt-oss-120b"]
SYSTEMS = ["no_defense", "pattern_filter", "policy_only", "provsafe"]
API_URL = "http://cci-siscluster1.charlotte.edu:8080/api/chat/completions"
API_KEY = "sk-a6af2053d49649d2925ff91fef71cb65"

# Run validation (first 10 scenarios)
scenarios = ALL_SCENARIOS[:10]
model = MODELS[0]

print(f"\n=== VALIDATION MODE ===")
print(f"Scenarios: {len(scenarios)}")
print(f"Models: {len([model])}")
print(f"Systems: {len(SYSTEMS)}")
print(f"Total evaluations: {len(scenarios) * len(SYSTEMS)} (~10 minutes)\n")

results = []
start_time = time.time()

for i, scenario in enumerate(scenarios, 1):
    print(f"\n[{i}/{len(scenarios)}] {scenario['id']}")
    
    for sys_name in SYSTEMS:
        sys_start = time.time()
        try:
            system = baseline_systems.create_system(sys_name, model, API_URL, API_KEY)
            result = system.execute_scenario(scenario)
            elapsed = time.time() - sys_start
            
            results.append({
                "scenario_id": scenario["id"],
                "system": sys_name,
                "model": model,
                "attack_success": result.get("attack_success", False),
                "blocked": result.get("blocked", False),
                "error": result.get("error"),
                "elapsed_sec": elapsed
            })
            
            status = "✓" if not result.get("error") else "✗"
            print(f"  {status} {sys_name:15} {elapsed:5.1f}s")
            
        except Exception as e:
            print(f"  ✗ {sys_name:15} Error: {str(e)[:60]}")
            results.append({
                "scenario_id": scenario["id"],
                "system": sys_name,
                "model": model,
                "error": str(e)
            })

# Compute metrics
print(f"\n{'='*50}")
print("RESULTS")
print(f"{'='*50}")

for sys_name in SYSTEMS:
    sys_results = [r for r in results if r["system"] == sys_name]
    attacks = [r for r in sys_results if not r.get("error") and r["attack_success"]]
    total_attacks = len([s for s in scenarios if s["category"] != "benign"])
    
    if total_attacks > 0:
        asr = len(attacks) / total_attacks * 100
        print(f"{sys_name:15} ASR: {asr:5.1f}%")

elapsed_min = (time.time() - start_time) / 60
print(f"\n✓ Complete in {elapsed_min:.1f}m")

# Save results
output_dir = Path("results/validation")
output_dir.mkdir(parents=True, exist_ok=True)
output_file = output_dir / f"validation_{int(time.time())}.json"
with open(output_file, "w") as f:
    json.dump(results, f, indent=2)
print(f"✓ Saved to {output_file}")
