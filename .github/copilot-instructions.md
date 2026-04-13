# PROVSAFE — Workspace Instructions

## Project

PROVSAFE is a provenance-gated tool-call policy enforcement system for LLM agents, targeting ACM CCS submission. See `CLAUDE.md` for full context.

## Code Style

- Python 3.9+ syntax — use `Union[X, Y]` not `X | Y`, no `match` statements
- Line length: 100 chars (black)
- Use `dataclass` for data containers, `Enum` for categorical values
- Pydantic v2 for external-facing schemas
- `evaluation/` scripts use `sys.path.insert` — they're standalone, not part of the package

## Key Architecture

- `src/enforcement_proxy.py` — 7-stage enforcement proxy (the core)
- `src/provenance_graph.py` — W3C PROV-DM DAG with trust lattice {TRUSTED, UNTRUSTED}
- `src/policy_engine.py` — First-match YAML policy engine
- `evaluation/baseline_systems.py` — All 5 defense systems
- `evaluation/run_experiments.py` — 212-scenario experiment runner
- `evaluation/run_injecagent.py` — InjecAgent external benchmark runner

## Critical Invariants

- PolicyDecision enum: always compare with `.decision.value`, never raw strings
- Trust propagation: lattice meet — any UNTRUSTED ancestor taints descendants
- Provenance resolution: substring → embedding cosine → conservative default (UNTRUSTED)
- 212 scenarios (172 attack in 9 categories + 40 benign), NOT 200

## Build & Test

```bash
pytest                          # Full test suite
python scripts/quick_test.py    # Smoke test (no LLM needed)
black src/ tests/ evaluation/   # Format
ruff check src/ tests/ evaluation/  # Lint
```

## Experiment Management

- Local models: LM Studio at `localhost:1234` (Llama-3.1-8B, Qwen2.5-7B, Gemma-2-9B, Phi-3.5-Mini)
- Cloud: GPT-4o-mini via OpenAI API (key in `evaluation/.env`)
- Check progress: `python check_injecagent_progress.py`
- Canonical results: `results/full_212/` (local), `results/gpt4omini_200scenario/` (GPT-4o-mini)
- InjecAgent results: `results/injecagent/` (local), `results/injecagent_gpt4omini/`

## ACM CCS Sprint (April 9–30, 2026)

Deadline ~April 30. See full plan in `CLAUDE.md` → "ACM CCS Submission Plan" section.

### Completed
- ✅ Adaptive adversary N=60 (`evaluation/adaptive_adversary.py`)
- ✅ Encoding robustness 36/36 (`evaluation/encoding_robustness.py`) + improved decoder
- ✅ Deployment architecture sketch (09_discussion.tex)
- ✅ Related work updated with 2025-2026 defenses (10_related_work.tex)
- ✅ Contribution claims tightened 4→3 (01_intro.tex)
- ✅ InjecAgent GPT-4o-mini complete (15,810/15,810)
- ✅ InjecAgent local reruns complete (63,240/63,240)
- ✅ InjecAgent paper tables updated (Tables 8–9 in 08_evaluation.tex)
- ✅ All paper sections updated with final InjecAgent numbers
- ✅ RQ10/AgentDojo dropped from paper (too slow to run)

### Active Tasks
1. Run adaptive_adversary.py, encoding_robustness.py with LLM
2. Add new experiment results to paper (adaptive adversary, encoding robustness)
3. Final audit: `compute_paper_numbers.py` + `audit_paper.py` — zero mismatches

### NOT doing
- GPT-4o evaluation (too expensive)
- AgentDojo benchmark (too slow to run)
- Formal verification, user study, trust lattice redesign
