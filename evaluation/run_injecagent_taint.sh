#!/bin/bash
export OPENWEBUI_API_KEY=sk-a6af2053d49649d2925ff91fef71cb65
export OPENWEBUI_URL=http://cci-siscluster1.charlotte.edu:8080/api/chat/completions
cd /Users/huanbui/Desktop/provsafe/evaluation
/Users/huanbui/Desktop/provsafe/.venv/bin/python run_injecagent.py --quick --model qwen3.5-122b --output /Users/huanbui/Desktop/provsafe/results/injecagent_taint_test
