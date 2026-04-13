#!/usr/bin/env python3
"""
Re-run ONLY the 3 failed scenarios (type comparison bug now fixed)
and patch the existing results file in-place.

Failed scenarios (all meta-llama-3.1-8b-instruct):
  - benign_004
  - attack_direct_006
  - benign_040
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from baseline_systems import PROVSAFESystem

RESULTS_DIR = Path(__file__).parent / "results" / "provsafe_rerun_20260304_031927"
SCENARIOS_FILE = Path(__file__).parent / "scenarios_expanded.json"

API_URL = "http://localhost:1234/v1/chat/completions"
API_KEY = "lm-studio"
MODEL = "meta-llama-3.1-8b-instruct"

FAILED_IDS = ["benign_004", "attack_direct_006", "benign_040"]


def main():
    # Load scenarios
    with open(SCENARIOS_FILE) as f:
        all_scenarios = json.load(f)

    failed_scenarios = [s for s in all_scenarios if s["id"] in FAILED_IDS]
    assert len(failed_scenarios) == 3, f"Expected 3, got {len(failed_scenarios)}"

    # Load existing results
    results_path = RESULTS_DIR / "detailed_results.json"
    with open(results_path) as f:
        results = json.load(f)

    print(f"Loaded {len(results)} existing results")
    print(f"Re-running {len(FAILED_IDS)} failed scenarios with {MODEL}...")
    print()

    # Re-run each failed scenario
    new_results = []
    for scenario in failed_scenarios:
        sid = scenario["id"]
        print(f"  Running {sid}...", end=" ", flush=True)

        system = PROVSAFESystem(MODEL, API_URL, API_KEY)
        start_time = time.time()

        try:
            result = system.execute_scenario(scenario)
            latency = time.time() - start_time

            eval_result = {
                "scenario_id": sid,
                "scenario_type": scenario["type"],
                "scenario_category": scenario.get("category", "N/A"),
                "system": "provsafe",
                "model": MODEL,
                "latency": round(latency, 2),
                "tool_calls": len(result.get("tool_calls", [])),
                "dangerous_calls": result.get("dangerous_calls", []),
                "blocked": result.get("blocked", False),
                "attack_success": result.get("attack_success", False),
                "error": result.get("error"),
            }
            status = "✓" if not eval_result["error"] else "✗"
            tc = eval_result["tool_calls"]
            print(f"{status} TC:{tc} latency:{latency:.1f}s error:{eval_result['error']}")
            new_results.append(eval_result)

        except Exception as e:
            latency = time.time() - start_time
            print(f"✗ EXCEPTION: {e}")
            new_results.append(
                {
                    "scenario_id": sid,
                    "scenario_type": scenario["type"],
                    "scenario_category": scenario.get("category", "N/A"),
                    "system": "provsafe",
                    "model": MODEL,
                    "latency": round(latency, 2),
                    "tool_calls": 0,
                    "dangerous_calls": [],
                    "blocked": False,
                    "attack_success": False,
                    "error": str(e),
                }
            )

    # Patch results: replace old entries with new ones
    patched = []
    replaced = 0
    for r in results:
        if r["scenario_id"] in FAILED_IDS and r["model"] == MODEL:
            # Find matching new result
            new_r = next(n for n in new_results if n["scenario_id"] == r["scenario_id"])
            patched.append(new_r)
            replaced += 1
        else:
            patched.append(r)

    print(f"\nReplaced {replaced}/3 entries in results")

    # Recompute metrics
    benign = [r for r in patched if r["scenario_type"] == "benign"]
    attacks = [r for r in patched if r["scenario_type"] == "attack"]

    successful_benign = sum(1 for r in benign if not r["blocked"] and r["error"] is None)
    successful_attacks = sum(1 for r in attacks if r["attack_success"] and not r["blocked"])
    valid_lats = [r["latency"] for r in patched if r["latency"] > 0]

    tsr = successful_benign / len(benign) * 100
    asr = successful_attacks / len(attacks) * 100
    avg_lat = sum(valid_lats) / len(valid_lats) if valid_lats else 0

    errors = sum(1 for r in patched if r.get("error"))

    metrics = {
        "total_evaluations": len(patched),
        "benign_count": len(benign),
        "attack_count": len(attacks),
        "tsr": round(tsr, 2),
        "asr": round(asr, 2),
        "avg_latency": round(avg_lat, 2),
        "successful_benign": successful_benign,
        "successful_attacks": successful_attacks,
        "errors": errors,
        "code_version": "conservative_default_v2_bugfix",
        "patched_scenarios": FAILED_IDS,
    }

    # Save
    with open(results_path, "w") as f:
        json.dump(patched, f, indent=2)

    with open(RESULTS_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    # Print summary
    print()
    print("=" * 60)
    print("UPDATED METRICS (after bugfix)")
    print("=" * 60)
    print(f"  Total evaluations: {len(patched)}")
    print(f"  Errors remaining:  {errors}")
    print(f"  TSR: {tsr:.2f}% ({successful_benign}/{len(benign)})")
    print(f"  ASR: {asr:.2f}% ({successful_attacks}/{len(attacks)})")
    print(f"  Avg Latency: {avg_lat:.2f}s")
    print()

    # Per-model breakdown
    for model in sorted(set(r["model"] for r in patched)):
        mr = [r for r in patched if r["model"] == model]
        mb = [r for r in mr if r["scenario_type"] == "benign"]
        ma = [r for r in mr if r["scenario_type"] == "attack"]
        m_tsr = sum(1 for r in mb if not r["blocked"] and r["error"] is None) / len(mb) * 100
        m_asr = sum(1 for r in ma if r["attack_success"] and not r["blocked"]) / len(ma) * 100
        m_err = sum(1 for r in mr if r.get("error"))
        print(f"  {model}: TSR={m_tsr:.1f}% ASR={m_asr:.1f}% Errors={m_err}")


if __name__ == "__main__":
    main()
