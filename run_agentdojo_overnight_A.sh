#!/bin/bash
# AgentDojo Option A (scoped): workspace suite × important_instructions × FULL user tasks × 2 defenses
# - 1 attack (important_instructions) — matches CaMeL's flagship protocol
# - 1 suite (workspace) — AgentDojo's largest and most commonly cited
# - 40 user_tasks × 14 injection_tasks × 2 defenses = 1,120 security trials + 28 utility trials
# - Estimated: 5-6 hours (safe overnight)
# - Cost: ~$3-5 in GPT-4o-mini API
# - Directly comparable to CaMeL's reported 0% ASR on AgentDojo workspace
#
# Usage:
#   bash run_agentdojo_overnight_A.sh            # Fresh run
#   bash run_agentdojo_overnight_A.sh --resume   # Resume from checkpoint if interrupted

set -e
cd "$(dirname "$0")/evaluation"

# Load OpenAI API key from .env
if [ -f .env ]; then
  set -a; source .env; set +a
fi

# Verify API key is set
if [ -z "$OPENAI_API_KEY" ]; then
  echo "ERROR: OPENAI_API_KEY not set. Check evaluation/.env"
  exit 1
fi

mkdir -p ../results/agentdojo_overnight_A
LOG_FILE="../results/agentdojo_overnight_A.log"

echo "======================================================================"
echo "AgentDojo Option A (scoped): workspace x important_instructions x FULL"
echo "======================================================================"
echo "Started:     $(date)"
echo "Log file:    $LOG_FILE"
echo "Checkpoint:  ../results/agentdojo_overnight_A/checkpoint.json"
echo "Est. time:   5-6 hours"
echo "Est. trials: 1,148 (1,120 security + 28 utility)"
echo ""
echo "To monitor progress from another terminal:"
echo "  tail -f $LOG_FILE | grep -E 'user_task|Completed|ASR|TSR'"
echo ""
echo "To resume if interrupted:"
echo "  bash run_agentdojo_overnight_A.sh --resume"
echo ""

python run_agentdojo.py \
  --model gpt-4o-mini \
  --suite workspace \
  --attack important_instructions \
  --defense no_defense provsafe \
  --output ../results/agentdojo_overnight_A \
  "$@" 2>&1 | tee "$LOG_FILE"

EXIT_CODE=${PIPESTATUS[0]}

echo ""
echo "======================================================================"
if [ "$EXIT_CODE" = "0" ]; then
  echo "COMPLETED SUCCESSFULLY: $(date)"
  echo ""
  echo "Results checkpoint: ../results/agentdojo_overnight_A/checkpoint.json"
  echo "Summary JSON:       ../results/agentdojo_overnight_A/results.json"
  echo ""
  echo "Quick view:"
  cat ../results/agentdojo_overnight_A/checkpoint.json 2>/dev/null | \
    python -c "import json,sys; d=json.load(sys.stdin); [print(f'  {k}: ASR={v[\"asr\"]*100:.2f}%  TSR={v[\"tsr\"]*100:.2f}%  (n={v[\"n_security_trials\"]})') for k,v in d.items()]" 2>/dev/null || true
else
  echo "FAILED with exit code $EXIT_CODE at $(date)"
  echo "To resume: bash $0 --resume"
fi
echo "======================================================================"

exit $EXIT_CODE
