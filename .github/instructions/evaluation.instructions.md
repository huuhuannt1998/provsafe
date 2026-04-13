---
description: "Use when writing or modifying evaluation scripts, experiment runners, InjecAgent runner, or baseline system implementations. Covers evaluation conventions and known pitfalls."
applyTo: "evaluation/**"
---
# Evaluation Script Instructions

## Critical Bug Pattern
NEVER compare PolicyDecision enum directly to strings:
```python
# WRONG — always False
if decision.decision in ("deny", "require_confirmation"):

# CORRECT — compare .value
if decision.decision.value in ("deny", "require_confirmation"):
```
`baseline_systems.py` already does it correctly. `run_injecagent.py` was fixed at lines 465 and 559.

## Provider Architecture
- `model_providers.py` auto-detects provider from model name
- Local models: LM Studio at `localhost:1234` (no API key)
- Cloud: OpenAI (gpt-4o-mini), Groq, Gemini — keys in `evaluation/.env`
- Rate limiting handled automatically per provider

## Checkpointing
- All runners save to `checkpoint.json` every 50 trials
- Use `--resume` to continue from checkpoint — ALWAYS use for long runs
- Checkpoint key format: `case_id|system|model|rep`

## 5 Defense Systems (in order)
1. `no_defense` — bare LLM
2. `pattern_filter` — 47 Rebuff-derived regex rules
3. `policy_only` — YAML policy, no provenance
4. `taint_everything` — all args UNTRUSTED
5. `provsafe` — full system with provenance DAG

## Seed Derivation
`SHA-256(scenario_id || system || model || rep)` → deterministic per trial.
Temperature always T=0.0.
