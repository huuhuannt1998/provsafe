---
description: "Comprehensive handoff prompt for continuing PROVSAFE work — ACM CCS 3-week sprint"
---
# PROVSAFE — Continuation Prompt (ACM CCS Sprint, April 9–30 2026)

You are picking up ongoing work on PROVSAFE, a provenance-gated tool-call policy enforcement system for LLM agents targeting ACM CCS submission (~April 30 deadline). Read `CLAUDE.md` for full project context — it contains a detailed 3-week sprint plan in "ACM CCS Submission Plan" section.

## Current State (as of April 9, 2026)

### What's DONE
- **212-scenario experiments**: COMPLETE — local 21,200 trials, GPT-4o-mini 5,300 trials
- **Paper numbers updated**: All 212-scenario numbers verified in `overleaf/sections/*.tex`
- **Critical bug fixed**: `run_injecagent.py` lines 465, 559 — `.decision` → `.decision.value`
- **CLAUDE.md, .github/ customizations**: All updated

### What's IN PROGRESS
- **InjecAgent local reruns**: ~35% done (22K/63K). `run_all_injecagent_local.sh` running.
- **InjecAgent GPT-4o-mini reruns**: ~31% done (4.9K/15.8K). Separate `--resume` process.
- Check: `python check_injecagent_progress.py` and `ps aux | grep run_injecagent`

### 3-Week Sprint Tasks (in priority order)

#### Week 1: Finish experiments + add second benchmark
| # | Task | Status |
|---|------|--------|
| 1 | Finish InjecAgent local reruns (63,240 trials) | IN PROGRESS |
| 2 | Finish InjecAgent GPT-4o-mini reruns (15,810 trials) | IN PROGRESS |
| 3 | Merge taint-everything data from `results/injecagent_taint_*/` | NOT STARTED |
| 4 | **Add 2nd external benchmark (AgentDojo or InjectBench)** — write adapter | NOT STARTED |
| 5 | Update InjecAgent paper tables (Tables 9–10 in 08_evaluation.tex) | NOT STARTED |

#### Week 2: Strengthen evaluation weaknesses
| # | Task | Status |
|---|------|--------|
| 6 | **Expand adaptive adversary (RQ7) to N=50+** — create `evaluation/adaptive_adversary.py` | NOT STARTED |
| 7 | Add encoding robustness experiment (double/mixed encoding) | NOT STARTED |
| 8 | Run `compute_paper_numbers.py` + `audit_paper.py` — full verification | NOT STARTED |
| 9 | Write deployment architecture sketch in `09_discussion.tex` | NOT STARTED |

#### Week 3: Polish paper + submit
| # | Task | Status |
|---|------|--------|
| 10 | Tighten contribution claims (3 bullets max) in intro + abstract | NOT STARTED |
| 11 | Update related work — add 2025-2026 defenses (AgentDojo, etc.) | NOT STARTED |
| 12 | Final `audit_paper.py` — zero mismatches | NOT STARTED |
| 13 | `pytest` all green, `black`/`ruff` clean | NOT STARTED |
| 14 | Proofread abstract + introduction | NOT STARTED |

### NOT doing (budget/time)
- GPT-4o evaluation (too expensive)
- Formal verification
- User study
- Multi-level trust lattice redesign

## Key Commands

```bash
python check_injecagent_progress.py          # Experiment progress
ps aux | grep run_injecagent | grep -v grep  # Running processes
python compute_paper_numbers.py              # Verified stats (Wilson CIs, Fisher)
python audit_paper.py                        # Paper vs data mismatches
python scripts/update_injecagent_numbers.py  # InjecAgent → LaTeX
pytest                                       # Test suite
black src/ tests/ evaluation/ && ruff check src/ tests/ evaluation/  # Format & lint
```

## Critical Invariants
- PolicyDecision enum: always `.decision.value`, never raw strings
- Trust propagation: lattice meet — any UNTRUSTED ancestor taints descendants
- 212 scenarios (172 attack in 9 categories + 40 benign), NOT 200
- Python 3.9+ syntax: `Union[X, Y]` not `X | Y`, no `match` statements
- DO NOT kill running experiment processes — they use `--resume`

## Key Files for Sprint
| File | Purpose |
|------|---------|
| `CLAUDE.md` | Full developer guide + sprint plan (read first) |
| `evaluation/run_agentdojo.py` | TO CREATE — AgentDojo benchmark adapter |
| `evaluation/adaptive_adversary.py` | TO CREATE — expanded RQ7 evaluation |
| `overleaf/sections/08_evaluation.tex` | InjecAgent tables + new benchmark results |
| `overleaf/sections/09_discussion.tex` | Deployment architecture sketch |
| `overleaf/sections/10_related_work.tex` | 2025-2026 additions |
| `check_injecagent_progress.py` | Progress checker |
| `compute_paper_numbers.py` | Verified stats from checkpoints |
| `audit_paper.py` | Paper vs data mismatches |
| `run_all_injecagent_local.sh` | Local rerun script (running) |
| `results/injecagent/checkpoint.json` | InjecAgent local results |
| `results/injecagent_gpt4omini/checkpoint.json` | InjecAgent GPT-4o-mini results |
