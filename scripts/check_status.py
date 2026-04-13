#!/usr/bin/env python3
"""Quick experiment status checker."""
import json, os, time, glob

print("=== EXPERIMENT CHECKPOINTS ===")
for p in sorted(glob.glob("results/*/checkpoint.json")):
    try:
        d = json.load(open(p))
        n = len(d)
        age = (time.time() - os.path.getmtime(p)) / 3600
        name = os.path.basename(os.path.dirname(p))
        print(f"  {name}: {n} trials, modified {age:.1f}h ago")
    except Exception as e:
        print(f"  {p}: ERROR {e}")

print("\n=== RUNNING EXPERIMENT PROCESSES ===")
os.system("ps aux | grep -E 'run_injecagent|run_experiments|adaptive|encoding_rob|run_agentdojo' | grep -v grep | grep python || echo '  No experiment processes running'")
