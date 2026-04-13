---
description: "Check the current status of all InjecAgent and 212-scenario experiments"
agent: "experiment-monitor"
---
Check the progress of all running PROVSAFE experiments:

1. Run `python check_injecagent_progress.py` to see InjecAgent coverage
2. Check if any experiment processes are running (`ps aux | grep run_injecagent`)
3. Show the latest lines from `results/injecagent_rerun.log`
4. Summarize: what's complete, what's in progress, what's still missing
