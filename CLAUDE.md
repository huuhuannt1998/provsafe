# CLAUDE.md — PROVSAFE Developer Guide

This file provides context for AI coding assistants (e.g., Claude, Copilot) working on this codebase.

---

## What is PROVSAFE?

**PROVSAFE** is a research prototype for *provenance-gated tool-call policy enforcement* for LLM agents. When an LLM decides to call a tool (e.g., `file_system.delete`, `device.reboot`), PROVSAFE intercepts the call, traces where each argument came from using a provenance DAG, evaluates declarative YAML policies, and either allows, denies, or requires user confirmation before execution.

The system was evaluated in an IEEE TDSC submission across 200 attack/benign scenarios × 6 LLMs × 4 systems × 5 repetitions = **24,000 trials**, plus **1,054 InjecAgent** external benchmark cases.

Each repetition uses a different temperature (T=0.0 greedy for rep 1, T=0.05–0.20 for reps 2–5) with a unique cryptographic seed derived from `SHA-256(scenario_id || system || model || rep)`, ensuring statistically independent trials.

Key results:
- **ASR-IA** (attack success rate, intent-aligned): 1.09% ± 0.36
- **TSR** (task success rate): 95.00% ± 1.52
- **FPR** (false positive rate): 5.00%

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

The evaluation supports three OpenAI-compatible providers via `evaluation/model_providers.py`:

| Provider | Models | Rate Limit | Cost |
|----------|--------|-----------|------|
| **LM Studio** (local) | meta-llama-3.1-8b-instruct, qwen2.5-7b-instruct, gemma-2-9b-it, phi-3.5-mini-instruct | Unlimited | Free (local GPU) |
| **Groq** (cloud) | llama-3.1-70b-versatile | 30 req/min | Free tier |
| **Google Gemini** (cloud) | gemini-1.5-flash | 15 req/min | Free tier |

In `evaluation/`, copy `.env.example` → `.env` and set your keys:

```bash
# Local LM Studio (no key needed)
LMSTUDIO_URL=http://localhost:1234/v1/chat/completions
LMSTUDIO_KEY=lm-studio

# Groq free tier (get key at console.groq.com)
GROQ_API_KEY=gsk_...

# Google Gemini free tier (get key at aistudio.google.com)
GEMINI_API_KEY=AIza...
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

All evaluation scripts live in `evaluation/`. They require LM Studio running locally with a model loaded.

```bash
# === TDSC Full Experiment (16,000 trials, ~12 hours) ===
cd evaluation/
python run_tdsc_experiments.py

# CLI flags:
python run_tdsc_experiments.py --reps 3              # Fewer repetitions
python run_tdsc_experiments.py --quick               # 10 scenarios, 2 reps
python run_tdsc_experiments.py --model qwen2.5-7b-instruct  # One model only
python run_tdsc_experiments.py --system provsafe     # One system only
python run_tdsc_experiments.py --resume              # Resume from checkpoint

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

Results are written to `results/tdsc_full/` (canonical TDSC run) or `runs/` for ad-hoc runs.

### InjecAgent External Benchmark

```bash
# === InjecAgent evaluation (1,054 cases × 4 systems × N models × 3 reps) ===
cd evaluation/
python run_injecagent.py                            # Full run (base setting)
python run_injecagent.py --reps 3 --setting base    # 3 reps, base setting only
python run_injecagent.py --model llama-3.1-70b-versatile  # Single model (Groq)
python run_injecagent.py --quick                    # Quick test (10 cases)
```

InjecAgent data lives in `evaluation/injecagent_data/` (4 JSON files from Zhan et al., ACL 2024).
Results go to `results/injecagent/`.

### Paper Number Auto-Update

```bash
# Watch TDSC experiment and auto-fill paper numbers when done
bash scripts/watch_and_update.sh <PID>

# Watch InjecAgent experiment and auto-fill placeholders
bash scripts/watch_injecagent.sh <PID>

# Manually update paper numbers from results
python scripts/update_paper_numbers.py          # TDSC → 08_evaluation.tex
python scripts/update_injecagent_numbers.py     # InjecAgent → 08_evaluation.tex
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
├── evaluation/                   # Research evaluation scripts (IEEE TDSC)
│   ├── run_tdsc_experiments.py   # MAIN: 16,000-trial experiment runner
│   ├── run_injecagent.py         # InjecAgent external benchmark runner
│   ├── baseline_systems.py       # NoDefense, PatternFilter, PolicyOnly, PROVSAFE
│   ├── model_providers.py        # Unified multi-provider LLM config (LMStudio/Groq/Gemini)
│   ├── injecagent_tools.py       # InjecAgent tool schemas + risk classifications
│   ├── injecagent_data/          # InjecAgent test cases (1,054 from Zhan et al. ACL 2024)
│   ├── scenarios_expanded.json   # 200 scenario definitions (160 attacks + 40 benign)
│   ├── smart_home_simulator.py   # Mock smart home environment
│   ├── simple_tools.py           # SmartHomeTool, FileSystemTool implementations
│   ├── embedding_provenance.py   # all-MiniLM-L6-v2 embedding-based provenance
│   ├── paraphrase_attack_eval.py # Paraphrase robustness evaluation
│   ├── llm_judge.py              # LLM-as-Judge attack verification (Cohen's kappa)
│   ├── run_baselines.py          # Standalone baseline runner
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
│       └── comprehensive_attacks.yaml  # All 8 attack categories
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
│   ├── update_paper_numbers.py   # Auto-fill TDSC numbers into LaTeX
│   ├── update_injecagent_numbers.py # Auto-fill InjecAgent numbers into LaTeX
│   ├── watch_and_update.sh       # Watch TDSC PID → auto-update paper
│   └── watch_injecagent.sh       # Watch InjecAgent PID → auto-update paper
│
├── results/
│   ├── tdsc_full/                # Canonical TDSC experiment results
│   │   ├── all_results.json      # All 16,000 trial results
│   │   ├── tdsc_report.json      # Aggregate statistics + CIs
│   │   ├── checkpoint.json       # Resume checkpoint
│   │   └── *.json                # Per-system result files
│   ├── tdsc_full_v2/             # Re-run with temperature/seed fix
│   └── injecagent/               # InjecAgent benchmark results
│
├── overleaf/                     # IEEE TDSC paper (LaTeX source)
│   ├── main.tex                  # IEEEtran two-column format
│   ├── sections/                 # 01_intro.tex … 11_conclusion.tex
│   │   └── 08_evaluation.tex     # Contains InjecAgent RQ8 + \PLACEHOLDER{} tokens
│   └── README.md
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
│  1. Decode arguments (9 encodings)       │
│     ├─ Unicode NFKD, hex, octal          │
│     ├─ Base64, ROT13, URL encoding       │
│     └─ binary, HTML entities, Unicode    │
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
| `PatternFilterSystem` | Keyword/regex blocking |
| `PolicyOnlySystem` | YAML policy, no provenance |
| `PROVSAFESystem` | Full system: policy + provenance |

---

## Evaluation Methodology

### Scenario Types (200 total in `scenarios_expanded.json`)

- **160 attack scenarios** across 8 categories:
  1. Direct injection
  2. Indirect injection (tool output)
  3. Goal hijacking
  4. Permission escalation
  5. Data exfiltration
  6. Multi-step attacks
  7. Jailbreaks
  8. Encoding-based obfuscation
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

### Defense Breakdown (PROVSAFE, aggregate)

| Stage | % Attacks Stopped |
|-------|------------------|
| Pre-LLM (prompt analysis) | 6.9% |
| Proxy enforcement | 30.2% |
| Tool call = 0 (no action taken) | 16.6% |
| Safe execution | 45.3% |
| **Bypasses (ASR-IA)** | **1.09%** |

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
| `evaluation/run_tdsc_experiments.py` | Main experiment runner; read this for evaluation logic |
| `evaluation/run_injecagent.py` | InjecAgent external benchmark runner |
| `evaluation/baseline_systems.py` | All 4 evaluated systems in one file |
| `evaluation/model_providers.py` | Unified LLM provider config (LMStudio/Groq/Gemini) |
| `evaluation/injecagent_tools.py` | InjecAgent tool schemas and risk classifications |
| `evaluation/scenarios_expanded.json` | 200 attack + benign scenario definitions |
| `configs/policies/provsafe.yaml` | Default policy file; shows YAML rule syntax |
| `results/tdsc_full/tdsc_report.json` | Canonical experiment results |
| `overleaf/main.tex` | IEEE TDSC submission (IEEEtran format) |

---

## Paper (IEEE TDSC)

The paper source is in `overleaf/` (previously `overleaf/`).

- Format: `IEEEtran` two-column
- Sections: 11 sections + appendix
- All numbers are filled from `results/tdsc_full/tdsc_report.json`
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

## Git

- Remote: `https://github.com/huuhuannt1998/provsafe.git`
- Branch: `main`
- Last commit: `3699b71` (164 files — paper + all code fixes)

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

The provider is auto-detected from the model name. Rate limiting (Groq: 30 RPM, Gemini: 15 RPM) is handled transparently with sliding-window throttling and 429 retry.

Both `run_tdsc_experiments.py` and `run_injecagent.py` use this unified provider.

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
python run_tdsc_experiments.py --quick --model meta-llama-3.1-8b-instruct --system provsafe
```

### Resume an interrupted experiment
```bash
cd evaluation/
python run_tdsc_experiments.py --resume
```

### Run InjecAgent benchmark
```bash
cd evaluation/
python run_injecagent.py --reps 3 --setting base --output ../results/injecagent
```

### Run with Groq (70B) or Gemini
```bash
# Set API keys first
export GROQ_API_KEY=gsk_...
export GEMINI_API_KEY=AIza...

cd evaluation/
python run_tdsc_experiments.py --model llama-3.1-70b-versatile
python run_tdsc_experiments.py --model gemini-1.5-flash
```

### Add a new policy rule
Edit `configs/policies/provsafe.yaml` following the existing rule format. Run `pytest tests/test_policy.py` to validate.

### Add a new attack scenario
Add an entry to `evaluation/scenarios_expanded.json` following the existing schema (attack categories: `direct_injection`, `indirect_injection`, `goal_hijacking`, `permission_escalation`, `data_exfiltration`, `multi_step`, `jailbreak`, `encoding_obfuscation`).

### Add a new tool
1. Add implementation to `src/tools.py`
2. Register schema in `src/provsafe/eval/run_suite.py` → `setup_tool_schemas()`
3. Add to policy files in `configs/policies/`
4. Add tests in `tests/test_proxy.py`
