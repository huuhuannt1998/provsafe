# CLAUDE.md — PROVSAFE Developer Guide

This file provides context for AI coding assistants (e.g., Claude, Copilot) working on this codebase.

---

## What is PROVSAFE?

**PROVSAFE** is a research prototype for *provenance-gated tool-call policy enforcement* for LLM agents. When an LLM decides to call a tool (e.g., `file_system.delete`, `device.reboot`), PROVSAFE intercepts the call, traces where each argument came from using a provenance DAG, evaluates declarative YAML policies, and either allows, denies, or requires user confirmation before execution.

The system is being prepared for an **ACM CCS** submission. It was evaluated across **212 scenarios** (172 attack + 40 benign) × **5 LLMs** (4 local 3B–9B + GPT-4o-mini) × **5 defense systems** × **5 repetitions** = **26,500+ primary trials**, plus **1,054 InjecAgent** external benchmark cases × 5 systems × 5 models × 3 reps.

Each repetition uses temperature T=0.0 (deterministic) with a unique cryptographic seed derived from `SHA-256(scenario_id || system || model || rep)`, ensuring statistically independent trials.

**Key results (verified, 212-scenario benchmark):**
- **ASR-IA** (attack success rate, intent-aligned): **1.02% ± 0.34** (4 local models aggregate)
- **TSR** (task success rate): **95.00% ± 1.52**
- **FPR** (false positive rate): **5.00%**
- **GPT-4o-mini**: ASR 0.35%, TSR 99.50%
- **Taint-Everything**: 0.00% ASR but collapses TSR to 9.00% (91% FPR) — PROVSAFE matches security while preserving usability
- **InjecAgent** (1,054 cases × 5 systems × 5 models × 3 reps = 79,050 trials): LOCAL ASR — No Defense 25.75%, Policy-Only 12.34%, PROVSAFE 4.22%, Taint-Everything 0.00%; GPT-4o-mini — No Defense 2.53%, PROVSAFE 1.17%

---

## Environment Setup

### Prerequisites

- Python 3.9+
- [LM Studio](https://lmstudio.ai/) for local LLM inference (API at `http://localhost:1234`)

### Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

The package is installed as `provsafe` v0.1.0 in editable mode from `pyproject.toml`.

### Dependencies (from pyproject.toml)

| Package | Version | Purpose |
|---------|---------|---------|
| pyyaml | >=6.0 | Policy YAML parsing |
| pydantic | >=2.0 | Schema validation |
| networkx | >=3.0 | Provenance DAG |
| numpy | (transitive) | Embedding cosine similarity |
| python-dateutil | >=2.8 | Temporal policy rules |
| pytest | >=7.0 | Test runner |

Dev extras: `pytest-cov`, `black`, `mypy`, `ruff`

### LLM Provider Configuration

The evaluation supports multiple OpenAI-compatible providers via `evaluation/model_providers.py`:

| Provider | Models | Rate Limit | Cost |
|----------|--------|-----------|------|
| **LM Studio** (local) | meta-llama-3.1-8b-instruct, qwen2.5-7b-instruct, gemma-2-9b-it, phi-3.5-mini-instruct | Unlimited | Free (Apple Silicon) |
| **OpenAI** (cloud) | gpt-4o-mini | 500 req/min | Pay-per-use |
| **Groq** (cloud) | llama-3.1-70b-versatile | 30 req/min | Free tier |
| **Google Gemini** (cloud) | gemini-1.5-flash | 15 req/min | Free tier |
| **Open WebUI** (cluster) | qwen3.5-122b, gpt-oss-120b, qwen3.5-397b | Unlimited | University GPU |

In `evaluation/`, copy `.env.example` → `.env` and set your keys:

```bash
# Local LM Studio (no key needed)
LMSTUDIO_URL=http://localhost:1234/v1/chat/completions
LMSTUDIO_KEY=lm-studio

# OpenAI (for gpt-4o-mini)
OPENAI_API_KEY=sk-...

# Groq free tier (get key at console.groq.com)
GROQ_API_KEY=gsk_...

# Google Gemini free tier (get key at aistudio.google.com)
GEMINI_API_KEY=AIza...

# Open WebUI (university cluster)
OPENWEBUI_URL=http://cci-siscluster1.charlotte.edu:8080/api/chat/completions
OPENWEBUI_API_KEY=your_openwebui_api_key_here
```

Rate limiting is handled automatically by `model_providers.py` (sliding-window per provider, with retry on 429).

---

## Build / Test Commands

```bash
# Run full test suite
pytest

# Run with coverage
pytest --cov=provsafe tests/

# Quick smoke test (no LM Studio required)
python scripts/quick_test.py

# Format code
black src/ tests/ evaluation/

# Lint
ruff check src/ tests/ evaluation/

# Type check
mypy src/

# Full setup + test
bash scripts/setup.sh
```

---

## Evaluation Commands

All evaluation scripts live in `evaluation/`. Local models require LM Studio running at `http://localhost:1234`. GPT-4o-mini requires `OPENAI_API_KEY` in `evaluation/.env`.

```bash
# === 212-Scenario Full Experiment ===
cd evaluation/
python run_experiments.py                                 # Full run (all models, 5 reps)
python run_experiments.py --reps 3                        # Fewer repetitions
python run_experiments.py --quick                         # 10 scenarios, 2 reps
python run_experiments.py --model qwen2.5-7b-instruct     # One model only
python run_experiments.py --model gpt-4o-mini             # GPT-4o-mini via API
python run_experiments.py --system provsafe               # One system only
python run_experiments.py --resume                        # Resume from checkpoint

# === Benchmark Suite Evaluation (provsafe module) ===
python -m provsafe.eval.run_suite \
  --suite configs/suites/injection.yaml \
  --policy configs/policies/provsafe.yaml \
  --out runs/my_run

# === Statistical / multi-trial run ===
python -m provsafe.eval.run_statistical \
  --suite configs/suites/injection.yaml \
  --policy configs/policies/provsafe.yaml \
  --out runs/statistical \
  --trials 30 \
  --start-seed 42

# === Comparative baselines run ===
python -m provsafe.eval.run_comparative \
  --suite configs/suites/default.yaml \
  --out runs/comparative

# === Ablation study ===
python -m provsafe.eval.run_ablation \
  --suite configs/suites/comprehensive_attacks.yaml \
  --out runs/ablation

# === Full evaluation pipeline ===
bash scripts/run_full_evaluation.sh
```

Results are written to `results/full_212/` (canonical 212-scenario run), `results/gpt4omini_200scenario/` (GPT-4o-mini), or `runs/` for ad-hoc runs.

### InjecAgent External Benchmark

```bash
# === InjecAgent evaluation (1,054 cases × 5 systems × N models × 3 reps) ===
cd evaluation/
python run_injecagent.py                            # Full run (base setting)
python run_injecagent.py --reps 3 --setting base    # 3 reps, base setting only
python run_injecagent.py --model gpt-4o-mini        # GPT-4o-mini via API
python run_injecagent.py --model meta-llama-3.1-8b-instruct --system provsafe  # One combo
python run_injecagent.py --quick                    # Quick test (20 cases)
python run_injecagent.py --resume                   # Resume from checkpoint
```

InjecAgent data lives in `evaluation/injecagent_data/` (4 JSON files from Zhan et al., ACL 2024).
Results go to `results/injecagent/` (local models) or `results/injecagent_gpt4omini/` (GPT-4o-mini).

### AgentDojo External Benchmark (NeurIPS 2024)

```bash
# === AgentDojo evaluation (97 tasks × 35 injections × 17 attack types) ===
cd evaluation/
pip install agentdojo  # Requires agentdojo v0.1.35+
python run_agentdojo.py                                    # Full run (all suites)
python run_agentdojo.py --suite workspace                  # One suite only
python run_agentdojo.py --model gpt-4o-mini                # GPT-4o-mini via API
python run_agentdojo.py --quick                            # Quick test (1 suite, 1 attack)
python run_agentdojo.py --resume                           # Resume from checkpoint
```

AgentDojo suites: workspace, travel, banking, slack. Results go to `results/agentdojo/`.

### Adaptive Adversary (RQ7)

```bash
# === Expanded adaptive adversary evaluation (60 scenarios: 50 attack + 10 benign) ===
cd evaluation/
python adaptive_adversary.py                               # Full run (all models)
python adaptive_adversary.py --model meta-llama-3.1-8b-instruct  # One model
python adaptive_adversary.py --quick                       # Quick test (5 scenarios)
python adaptive_adversary.py --resume                      # Resume from checkpoint
```

5 attack categories × 10 each: provenance_laundering, policy_aware_evasion, embedding_evasion, toctou_amplification, multi_vector_chaining.

### Encoding Robustness

```bash
# === Encoding robustness (36 test vectors, decoder-only or full LLM) ===
cd evaluation/
python encoding_robustness.py --decoder-only               # No LLM needed (unit test)
python encoding_robustness.py                              # Full LLM evaluation
python encoding_robustness.py --model meta-llama-3.1-8b-instruct  # One model
```

4 categories: single encoding (8), double/chained (10), mixed encoding (8), novel/adversarial (10).

### Monitoring Experiment Progress

```bash
# Quick status of all experiments
python scripts/check_status.py

# Check InjecAgent progress across all checkpoints
python check_injecagent_progress.py

# Tail the rerun log
tail -20 results/injecagent_rerun.log
```

### Paper Number Auto-Update

```bash
# Watch experiment and auto-fill paper numbers when done
bash scripts/watch_and_update.sh <PID>

# Watch InjecAgent experiment and auto-fill placeholders
bash scripts/watch_injecagent.sh <PID>

# Manually update paper numbers from results
python scripts/update_paper_numbers.py          # 212-scenario → 08_evaluation.tex
python scripts/update_injecagent_numbers.py     # InjecAgent → 08_evaluation.tex

# Compute all verified paper numbers from checkpoint data
python compute_paper_numbers.py                 # Wilson CIs, Fisher exact tests
python audit_paper.py                           # Compare paper vs actual data
```

---

## Project Structure

```
provsafe/
├── src/
│   ├── enforcement_proxy.py      # Legacy top-level enforcement proxy (used by evaluation/)
│   ├── policy_engine.py          # Legacy top-level policy engine
│   ├── provenance_graph.py       # Legacy top-level provenance DAG
│   ├── llm_agent.py              # LLM agent wrapper (OpenAI-compatible)
│   ├── tools.py                  # 11 mock tool implementations
│   ├── real_evaluation.py        # Real-device evaluation helpers
│   └── provsafe/                 # Production Python package
│       ├── __init__.py
│       ├── attacks/              # Attack scenario generators
│       ├── bench/                # Benchmark task definitions + mock tool registry
│       ├── eval/                 # Evaluation runners and metrics
│       │   ├── runner.py         # Core EvaluationRunner class
│       │   ├── metrics.py        # TSR, ASR, FPR, latency computations
│       │   ├── statistics.py     # Wilson CI, bootstrapping
│       │   ├── run_suite.py      # CLI: run a benchmark suite
│       │   ├── run_attacks.py    # CLI: run attack-only evaluation
│       │   ├── run_comparative.py# CLI: run 4-system comparison
│       │   ├── run_ablation.py   # CLI: run ablation study
│       │   ├── run_statistical.py# CLI: multi-trial statistical run
│       │   ├── ablation.py       # Ablation helper
│       │   └── comparative.py    # Comparative helper
│       ├── policy/               # Policy language
│       │   ├── language.py       # CapabilityPolicy, PolicyRule, constraints
│       │   └── engine.py         # PolicyEngine, RateLimiter
│       ├── provenance/           # Provenance tracking
│       │   ├── graph.py          # Provenance DAG (W3C PROV-DM)
│       │   └── tracker.py        # ProvenanceTracker (middleware layer)
│       ├── proxy/                # Tool-call proxy
│       │   ├── proxy.py          # ToolCallProxy (validate → policy → provenance)
│       │   └── schema.py         # ToolCallRequest, PolicyDecision, RiskTier, etc.
│       └── replay/               # Audit log replay and verification
│
├── evaluation/                   # Research evaluation scripts (ACM CCS)
│   ├── run_experiments.py        # MAIN: 212-scenario experiment runner
│   ├── run_injecagent.py         # InjecAgent external benchmark runner
│   ├── baseline_systems.py       # NoDefense, PatternFilter, PolicyOnly, TaintEverything, PROVSAFE
│   ├── model_providers.py        # Unified multi-provider LLM config (LMStudio/OpenAI/Groq/Gemini/OpenWebUI)
│   ├── injecagent_tools.py       # InjecAgent tool schemas + risk classifications
│   ├── injecagent_data/          # InjecAgent test cases (1,054 from Zhan et al. ACL 2024)
│   ├── scenarios_expanded.json   # 212 scenario definitions (172 attacks + 40 benign)
│   ├── smart_home_simulator.py   # Mock smart home environment
│   ├── simple_tools.py           # SmartHomeTool, FileSystemTool implementations
│   ├── embedding_provenance.py   # all-MiniLM-L6-v2 embedding-based provenance
│   ├── paraphrase_attack_eval.py # Paraphrase robustness evaluation
│   ├── llm_judge.py              # LLM-as-Judge attack verification (Cohen's kappa)
│   ├── run_baselines.py          # Standalone baseline runner
│   ├── run_agentdojo.py          # AgentDojo external benchmark adapter (NeurIPS 2024)
│   ├── adaptive_adversary.py     # Expanded RQ7: 60 adaptive adversary scenarios
│   ├── encoding_robustness.py    # Encoding robustness: 36 test vectors, 4 categories
│   └── .env.example              # Environment variable template
│
├── configs/
│   ├── policies/
│   │   ├── provsafe.yaml         # Default capability policy
│   │   ├── permissive.yaml       # Loose policy (fewer denials)
│   │   └── strict.yaml           # Strict policy (more denials)
│   └── suites/
│       ├── default.yaml          # General benchmark suite
│       ├── injection.yaml        # Prompt injection focused suite
│       └── comprehensive_attacks.yaml  # All 9 attack categories
│
├── tests/
│   ├── test_attacks.py           # Attack generation and detection tests
│   ├── test_integration.py       # End-to-end integration tests
│   ├── test_policy.py            # Policy engine unit tests
│   ├── test_provenance.py        # Provenance DAG unit tests
│   └── test_proxy.py             # Proxy enforcement unit tests
│
├── scripts/
│   ├── quick_test.py             # Smoke test (no LM Studio needed)
│   ├── setup.sh                  # Full setup + test script
│   ├── run_eval.sh               # Basic evaluation run
│   ├── run_full_evaluation.sh    # Full pipeline
│   ├── update_paper_numbers.py   # Auto-fill numbers into LaTeX
│   ├── update_injecagent_numbers.py # Auto-fill InjecAgent numbers into LaTeX
│   ├── watch_and_update.sh       # Watch experiment PID → auto-update paper
│   ├── watch_injecagent.sh       # Watch InjecAgent PID → auto-update paper
│   └── check_status.py           # Experiment progress checker (all checkpoints)
│
├── results/                      # Experiment results (see "Results Layout" below)
│   ├── full_212/                 # Canonical 212-scenario results (4 local models)
│   ├── gpt4omini_200scenario/    # GPT-4o-mini 212-scenario results
│   ├── tdsc_taint_v3/            # Taint-Everything results (4 local models)
│   ├── injecagent/               # InjecAgent local model results
│   ├── injecagent_gpt4omini/     # InjecAgent GPT-4o-mini results
│   └── ...                       # Various taint/rerun directories
│
├── overleaf/                     # ACM CCS paper (LaTeX source)
│   ├── main.tex                  # acmart sigconf format
│   ├── sections/                 # 01_intro.tex … 11_conclusion.tex
│   │   └── 08_evaluation.tex     # Contains InjecAgent tables + all RQs
│   └── README.md
│
├── check_injecagent_progress.py  # Progress checker for InjecAgent experiments
├── compute_paper_numbers.py      # Compute all paper numbers from checkpoint data
├── audit_paper.py                # Compare paper numbers vs actual data
├── run_all_injecagent_local.sh   # Comprehensive InjecAgent rerun (all 5 systems × 4 local models)
│
├── pyproject.toml                # Package config, dependencies, tool settings
├── requirements.txt              # Flat requirements list
└── README.md                     # User-facing quickstart
```

---

## Architecture

### Core Data Flow

```
User Prompt
    │
    ▼
┌─────────────┐
│  LLM Agent  │  (llm_agent.py / LMStudio API)
└──────┬──────┘
       │ tool call request
       ▼
┌──────────────────────────────────────────┐
│           EnforcementProxy               │
│                                          │
│  1. Decode arguments (iterative multi-pass)│
│     ├─ 3-pass fixpoint: NFKD, hex, octal  │
│     ├─ Base64, ROT13, URL, \uXXXX escape  │
│     ├─ binary, HTML entities, tab-hex     │
│     └─ Unicode confusable mapping (final)  │
│  2. Resolve argument provenance          │
│     └─ ProvenanceGraph (DAG lookup)      │
│  3. Evaluate policy                      │
│     └─ PolicyEngine (YAML rules)         │
│  4. Apply trust-lattice gate             │
│     └─ UNTRUSTED args → DENY high-risk   │
│  5. Require confirmation if needed       │
│  6. Execute tool (if allowed)            │
│  7. SHA-256 chain audit log              │
└──────┬───────────────────────────────────┘
       │
       ▼
┌─────────────┐
│  Tool APIs  │  (mock: tools.py / real: smart_home_simulator.py)
└─────────────┘
```

### Provenance DAG (W3C PROV-DM)

- Each datum entering the system is a **PROV-DM Entity** node with a trust label from the two-element lattice **L = {⊤ (TRUSTED), ⊥ (UNTRUSTED)}**
- Edges represent `wasDerivedFrom` relations
- Trust propagates via **lattice meet**: any UNTRUSTED ancestor makes a derived value UNTRUSTED
- Resolution pipeline (3 stages):
  1. **Substring match** — O(n) verbatim lookup
  2. **Embedding cosine** — all-MiniLM-L6-v2, handles paraphrases (optional, requires `sentence-transformers`)
  3. **Conservative default** — unresolved args → UNTRUSTED

Key classes:
- `src/provenance_graph.py`: `ProvenanceGraph`, `TrustLabel`, `trust_meet()`
- `src/provsafe/provenance/graph.py`: production package version
- `src/provsafe/provenance/tracker.py`: `ProvenanceTracker` middleware

### Policy Engine

Policies are declarative YAML files with **first-match semantics** (rules evaluated in order by priority). The engine supports:

- **Risk tiers**: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- **Resource scope constraints**: regex path patterns
- **Temporal rules**: time-of-day windows
- **Rate limits**: per-tool call quotas
- **Evidence requirements**: provenance trust gating

Policy decisions: `ALLOW` | `DENY` | `REQUIRE_CONFIRMATION`

Default behavior: `default_allow: false` (deny-by-default)

Example rule structure (from `configs/policies/provsafe.yaml`):
```yaml
rules:
  - name: "allow_file_read"
    tool: "file_system"
    action: "read"
    resource_pattern: "^/home/user/.*"
    allow: true
    risk_tier: "low"
```

Key classes:
- `src/policy_engine.py`: `PolicyEngine`, `PolicyDecision`, `RiskTier`, `PolicyRule`
- `src/provsafe/policy/language.py`: `CapabilityPolicy`, `PolicyRule`, constraint types
- `src/provsafe/policy/engine.py`: `PolicyEngine`, `RateLimiter`

### Mock Tools (11 total)

Defined in `src/tools.py`:

| Tool | Actions | Risk |
|------|---------|------|
| `fs` | read, write, delete, list | LOW/MEDIUM/HIGH/LOW |
| `calendar` | add, list | MEDIUM/LOW |
| `notify` | send | MEDIUM |
| `email` | send | HIGH |
| `device` | list, control, reboot | LOW/HIGH/CRITICAL |

### Baseline Systems (for evaluation)

Defined in `evaluation/baseline_systems.py`:

| System | Description |
|--------|-------------|
| `NoDefenseSystem` | Bare LLM, no protection |
| `PatternFilterSystem` | Keyword/regex blocking (47 Rebuff-derived rules) |
| `PolicyOnlySystem` | YAML policy, no provenance (all args treated as unknown) |
| `TaintEverythingSystem` | All arguments marked UNTRUSTED regardless of lineage |
| `PROVSAFESystem` | Full system: policy + provenance DAG + 3-stage resolution |

### Known Issues & Fixes

- **InjecAgent enum bug** (FIXED): `run_injecagent.py` lines 465, 559 compared `PolicyDecision` enum to raw strings
  (`decision.decision in ("deny", ...)` was always `False`). Fixed to `.decision.value`. This made `policy_only` and
  `taint_everything` act like `no_defense` in all InjecAgent experiments prior to the fix.
  `baseline_systems.py` (used by 212-scenario runner) was NOT affected — it already used `.decision.value`.
- **Taint-Everything in full_212**: The `taint_everything` column in `results/full_212/` has `blocked=0` (buggy).
  Valid taint data exists in `results/tdsc_taint_v3/` (4,240 trials, ASR=0.00%, TSR=9.00%, FPR=91.00%).

---

## Evaluation Methodology

### Scenario Types (212 total in `scenarios_expanded.json`)

- **172 attack scenarios** across 9 categories:
  1. Direct injection (20)
  2. Device name injection (22)
  3. File content injection (22)
  4. Multi-turn chaining (20)
  5. Encoding obfuscation (18)
  6. Roleplay jailbreak (20)
  7. Confused deputy (18)
  8. Privilege escalation (20)
  9. NL argument injection (12)
- **40 benign scenarios** (normal legitimate requests)

### Metrics

| Metric | Definition | Target |
|--------|-----------|--------|
| **ASR-IA** | Attack Success Rate (intent-aligned) | < 5% |
| **TSR** | Task Success Rate (benign tasks) | > 90% |
| **FPR** | False Positive Rate | < 10% |

### External Benchmark: InjecAgent (ACL 2024)

- **1,054 test cases** of indirect prompt injection attacks
- **17 user tools** + **63 attacker tools** mapped to PROVSAFE risk tiers
- **2 attack types**: Direct Harm (DH), Data Stealing (DS)
- **2 settings**: Base (simple injection), Enhanced (sophisticated injection)
- Evaluation: multi-turn conversation — Turn 1 executes user tool, Turn 2 contains injection in tool response
- PROVSAFE intercepts attacker tool calls using risk-tier + provenance gating

### Defense Breakdown (PROVSAFE, 3B–9B aggregate)

| Stage | % Attacks Stopped |
|-------|------------------|
| Boundary blocked (proxy) | 23.5% |
| Model refusal (TC=0) | 27.2% |
| Safe tool calls | 48.3% |
| **Bypasses (ASR-IA)** | **1.02%** |

### GPT-4o-mini Results (cloud model)

| System | ASR-IA | TSR |
|--------|--------|-----|
| No Defense | 25.93% | 100% |
| Pattern Filter | 9.77% | 100% |
| Policy-Only | 1.51% | 99.50% |
| Taint-Everything | 0.00% | 9.00% |
| **PROVSAFE** | **0.35%** | **99.50%** |

### InjecAgent Results (COMPLETE — 79,050 trials)

**Local models (4 models × 1,054 cases × 3 reps = 12,648 trials/system):**

| System | ASR-IA ± 95% CI | Key Finding |
|--------|-----------------|-------------|
| No Defense | 25.75% ± 0.8 | Baseline |
| Pattern Filter | 14.41% ± 0.6 | Regex helps; 14% parse errors |
| Policy-Only | 12.34% ± 0.6 | Risk tiers help; DS still 21.7% |
| **PROVSAFE** | **4.22% ± 0.4** | **6.1× reduction via provenance** |
| Taint-Everything | 0.00% ± 0.0 | Security upper bound |

**GPT-4o-mini (1,054 × 3 reps = 3,162 trials/system):**

| System | ASR-IA |
|--------|--------|
| No Defense | 2.53% |
| Policy-Only | 2.06% |
| **PROVSAFE** | **1.17%** |
| Taint-Everything | 0.00% |

**Per-model PROVSAFE ASR (local):** Gemma 1.61%, Llama 3.45%, Phi 9.30%, Qwen 2.53%

**Note:** InjecAgent enum comparison bug was fixed in `run_injecagent.py` (lines 465, 559: `.decision` → `.decision.value`). All reruns complete as of April 2026.

---

## Code Style & Conventions

### Formatting

- **Line length**: 100 characters (black + ruff)
- **Formatter**: `black` — run `black src/ tests/ evaluation/`
- **Linter**: `ruff` — run `ruff check src/ tests/ evaluation/`
- **Type checker**: `mypy` — run `mypy src/`

### Python Style

- Python 3.9+ syntax (no `match` statements, use `Union[X, Y]` not `X | Y` in signatures for 3.9 compat)
- Use `dataclass` for data containers
- Use `Enum` for categorical values (decisions, risk tiers, trust labels)
- Pydantic v2 for external-facing schemas (proxy module)
- All public APIs should have docstrings

### Imports

- Absolute imports preferred within the `provsafe` package
- `evaluation/` scripts use `sys.path.insert` to add the project root (they are standalone scripts, not part of the package)

### Testing

- Tests live in `tests/`, use `pytest`
- Markers: `--strict-markers` enforced
- Use `@pytest.mark.parametrize` for scenario-based tests
- Mock LLM calls where possible (tests should not require LM Studio)

---

## Important Files to Know

| File | Why It Matters |
|------|---------------|
| `src/enforcement_proxy.py` | 7-stage enforcement proxy; the heart of the system |
| `src/provenance_graph.py` | W3C PROV-DM DAG; 9-encoding decoder; trust lattice |
| `src/policy_engine.py` | First-match YAML policy evaluator |
| `src/provsafe/proxy/schema.py` | All data types: `ToolCallRequest`, `PolicyDecision`, `RiskTier` |
| `evaluation/run_experiments.py` | Main experiment runner; read this for evaluation logic |
| `evaluation/run_injecagent.py` | InjecAgent external benchmark runner |
| `evaluation/baseline_systems.py` | All 5 evaluated systems in one file (NoDefense, PatternFilter, PolicyOnly, TaintEverything, PROVSAFE) |
| `evaluation/model_providers.py` | Unified LLM provider config (LMStudio/OpenAI/Groq/Gemini/OpenWebUI) |
| `evaluation/injecagent_tools.py` | InjecAgent tool schemas and risk classifications |
| `evaluation/scenarios_expanded.json` | 212 attack + benign scenario definitions |
| `configs/policies/provsafe.yaml` | Default policy file; shows YAML rule syntax |
| `results/full_212/checkpoint.json` | Canonical local-model experiment results |
| `results/gpt4omini_200scenario/checkpoint.json` | GPT-4o-mini experiment results |
| `evaluation/run_agentdojo.py` | AgentDojo external benchmark adapter |
| `evaluation/adaptive_adversary.py` | Expanded RQ7 adaptive adversary (60 scenarios) |
| `evaluation/encoding_robustness.py` | Encoding robustness test (36 vectors) |
| `overleaf/main.tex` | ACM CCS submission (acmart sigconf format) |

---

## Paper (ACM CCS)

The paper source is in `overleaf/`.

- Format: `acmart` sigconf (anonymous)
- Sections: 11 sections + appendix
- All numbers verified against checkpoint data via `compute_paper_numbers.py`
- Compile on Overleaf or locally with `pdflatex` + `bibtex`

```bash
# Local compilation (requires LaTeX installation)
cd overleaf/
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

---

## ACM CCS Submission Plan (3-Week Sprint, April 9–30 2026)

### Submission Deadline: ~April 30 2026

### Week 1: Finish experiments + add second benchmark

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Finish InjecAgent local reruns (63,240 trials) | **DONE** | 63,240/63,240 (100%) — all 5 systems × 4 models complete |
| 2 | Finish InjecAgent GPT-4o-mini reruns (15,810 trials) | **DONE** | 15,810/15,810 (100%) |
| 3 | Merge taint-everything data from `results/injecagent_taint_*/` | **DONE** | All 4 models in main checkpoint |
| 4 | ~~Add 2nd external benchmark (AgentDojo)~~ | **DROPPED** | Too slow; InjecAgent sufficient for CCS |
| 5 | Update InjecAgent paper tables (Tables 8–9) | **DONE** | All sections updated with final numbers |

### Week 2: Strengthen evaluation weaknesses

| # | Task | Status | Notes |
|---|------|--------|-------|
| 6 | **Expand adaptive adversary (RQ7) to N=50+** | **DONE** | `evaluation/adaptive_adversary.py` (60 scenarios). Needs LLM run. |
| 7 | Add encoding robustness experiment | **DONE** | `evaluation/encoding_robustness.py` (36 vectors). Decoder: 24/36→36/36. Needs LLM run. |
| 8 | Run `compute_paper_numbers.py` + `audit_paper.py` | NOT STARTED | After all experiments complete |
| 9 | Write deployment architecture sketch subsection | **DONE** | Added to `09_discussion.tex` |

### Week 2.5: Paper improvements (completed)

| # | Task | Status | Notes |
|---|------|--------|-------|
| 9a | Improved enforcement proxy decoder | **DONE** | Iterative multi-pass, confusable mapping, \\uXXXX |
| 9b | Updated related work (2025-2026 defenses) | **DONE** | CaMeL, Jatmo, TensorTrust, AgentMonitor, HijackRAG |
| 9c | Tightened contribution claims (4→3) | **DONE** | `01_intro.tex` |

### Week 3: Polish paper + submit

| # | Task | Status | Notes |
|---|------|--------|-------|
| 10 | Tighten contribution claims (3 bullets max) | **DONE** | Merged into architecture contribution |
| 11 | Update related work — add 2025-2026 defenses | **DONE** | 5 new refs + 2 table rows |
| 12 | Final `audit_paper.py` — zero mismatches | NOT STARTED | |
| 13 | `pytest` all green, `black`/`ruff` clean | IN PROGRESS | 76/76 tests pass, formatting TBD |
| 14 | Proofread abstract + introduction | NOT STARTED | First impression for reviewers |

### Explicitly NOT doing (budget/time constraints)
- GPT-4o evaluation (too expensive)
- Formal verification of security properties
- User study
- Multi-level trust lattice redesign
- AgentDojo benchmark (too slow to run; InjecAgent + 212-scenario sufficient)

### Key files for this sprint
- `evaluation/adaptive_adversary.py` — **CREATED** (expanded RQ7, 60 scenarios)
- `evaluation/encoding_robustness.py` — **CREATED** (36 test vectors, 4 categories)
- `overleaf/sections/08_evaluation.tex` — InjecAgent tables + RQ7-RQ9 results
- `overleaf/sections/10_related_work.tex` — **UPDATED** with 5 new 2025-2026 references
- `overleaf/sections/09_discussion.tex` — **UPDATED** with deployment architecture sketch
- `overleaf/sections/01_intro.tex` — **UPDATED** contributions tightened to 3

---

## Git

- Remote: `https://github.com/huuhuannt1998/provsafe.git`
- Branch: `main`

```bash
git add -A && git commit -m "your message"
git push origin main
```

---

## Multi-Provider LLM Architecture

`evaluation/model_providers.py` provides a unified interface for calling LLMs across providers:

```python
from model_providers import get_provider_config, call_llm, ALL_MODELS

# Automatic provider resolution from model name
result = call_llm(
    messages=[{"role": "user", "content": "Hello"}],
    model="llama-3.1-70b-versatile",  # → Groq
    tools=[...],
    temperature=0.1,
    seed=42,
)
```

The provider is auto-detected from the model name. Rate limiting (Groq: 30 RPM, Gemini: 15 RPM) is handled transparently with sliding-window throttling and 429 retry. Open WebUI models (qwen3.5-122b, etc.) auto-bump `max_tokens` to 2000 for thinking models.

Both `run_experiments.py` and `run_injecagent.py` use this unified provider.

---

## Common Tasks

### Run a quick smoke test (no LLM needed)
```bash
python scripts/quick_test.py
```

### Run the full test suite
```bash
pytest
```

### Run one attack scenario manually
```bash
cd evaluation/
python run_experiments.py --quick --model meta-llama-3.1-8b-instruct --system provsafe
```

### Resume an interrupted experiment
```bash
cd evaluation/
python run_experiments.py --resume
```

### Run InjecAgent benchmark
```bash
cd evaluation/
python run_injecagent.py --reps 3 --setting base --output ../results/injecagent
```

### Run with GPT-4o-mini, Groq, Gemini, or university cluster
```bash
# GPT-4o-mini (set OPENAI_API_KEY in evaluation/.env)
cd evaluation/
python run_experiments.py --model gpt-4o-mini
python run_injecagent.py --model gpt-4o-mini --output ../results/injecagent_gpt4omini

# Groq / Gemini
export GROQ_API_KEY=gsk_...
export GEMINI_API_KEY=AIza...
python run_experiments.py --model llama-3.1-70b-versatile
python run_experiments.py --model gemini-1.5-flash

# University cluster (Open WebUI) — set API key in evaluation/.env
python run_experiments.py --model qwen3.5-122b
python run_injecagent.py --model qwen3.5-122b
```

### Add a new policy rule
Edit `configs/policies/provsafe.yaml` following the existing rule format. Run `pytest tests/test_policy.py` to validate.

### Add a new attack scenario
Add an entry to `evaluation/scenarios_expanded.json` following the existing schema (attack categories: `direct_injection`, `device_name_injection`, `file_content_injection`, `multi_turn_chaining`, `encoding_obfuscation`, `roleplay_jailbreak`, `confused_deputy`, `privilege_escalation`, `nl_argument_injection`).

### Add a new tool
1. Add implementation to `src/tools.py`
2. Register schema in `src/provsafe/eval/run_suite.py` → `setup_tool_schemas()`
3. Add to policy files in `configs/policies/`
4. Add tests in `tests/test_proxy.py`
