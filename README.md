# PROVSAFE: Provenance-Gated Policy Enforcement for Tool-Using LLM Agents

**PROVSAFE** is a provenance-gated capability enforcement framework that defends tool-using LLM agents against prompt injection attacks. It tracks where every tool-call argument originated via a W3C PROV-DM provenance DAG, resolves arguments to their sources through a three-stage pipeline (substring matching → embedding similarity → conservative default), and enforces declarative YAML policies at the tool-call boundary — blocking attacker-injected operations while allowing legitimate ones.

> Submitted to **ACM CCS 2026** (under review).

## Key Results

### 212-Scenario Benchmark (26,500+ trials, 5 LLMs × 5 systems × 5 reps)

| System | ASR-IA ↓ | TSR ↑ | Notes |
|--------|----------|-------|-------|
| No Defense | 24.56% | 98.38% | Baseline |
| Pattern Filter | 7.33% | 99.12% | Rebuff-derived regex |
| Policy-Only | 1.72% | 96.75% | No provenance context |
| Taint-Everything | 0.00% | 9.00% | 91% FPR — unusable |
| **PROVSAFE** | **1.02%** | **95.00%** | Best security–usability tradeoff |
| PROVSAFE (GPT-4o-mini) | **0.35%** | **99.50%** | Cloud model |

### InjecAgent External Benchmark (79,050 trials, ACL 2024)

| System | ASR-IA ↓ | Key Finding |
|--------|----------|-------------|
| No Defense | 25.75% | Baseline |
| Pattern Filter | 14.41% | Regex helps; 14% parse errors |
| Policy-Only | 12.34% | Risk tiers help; DS still 21.7% |
| **PROVSAFE** | **4.22%** | **6.1× reduction via provenance** |
| Taint-Everything | 0.00% | Security upper bound (unusable) |
| PROVSAFE (GPT-4o-mini) | **1.17%** | Cloud model, 1,054 cases × 3 reps |

**Key insight:** Provenance is essential when attacker tools are syntactically legitimate. Policy-Only reduces ASR to 12.34% on InjecAgent but still fails on Data Stealing (21.7%) because exfiltration tools like `GmailSendEmail` are MEDIUM-risk. PROVSAFE closes this gap by tracing arguments to their untrusted source regardless of tool risk tier.

## Architecture

```
User Command (TRUSTED)
    │
    ▼
┌─────────────┐
│  LLM Agent  │  (unmodified — no model changes needed)
└──────┬──────┘
       │ tool call
       ▼
┌──────────────────────────────────────────┐
│           Enforcement Proxy              │
│  1. Intercept tool call                  │
│  2. Decode args (12 encodings, 3-pass)   │
│  3. Resolve provenance (3-stage DAG)     │
│  4. Evaluate YAML policy (first-match)   │
│  5. User confirmation (if needed)        │
│  6. SHA-256 chained audit log            │
│  7. Execute or deny                      │
└──────┬───────────────────────────────────┘
       │
       ▼
┌─────────────┐    ┌───────────────────────┐
│  Tool APIs  │◄───│ External APIs          │ (always UNTRUSTED)
└─────────────┘    │ Devices, files, email  │
                   └───────────────────────┘
```

**Three-stage provenance resolution** handles LLM paraphrasing without restricting data flow:
1. **Substring match** — O(n) verbatim lookup
2. **Embedding similarity** — all-MiniLM-L6-v2, θ=0.45, handles paraphrases (<5 ms)
3. **Conservative default** — unresolved → UNTRUSTED (fail-safe)

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Requirements: Python 3.9+, [LM Studio](https://lmstudio.ai/) for local LLM inference (or any OpenAI-compatible API).

## Quick Start

```bash
# Smoke test (no LLM needed)
python scripts/quick_test.py

# Run test suite
pytest

# Quick evaluation (10 scenarios, 2 reps)
cd evaluation/
python run_experiments.py --quick
```

## Full Evaluation

### 212-Scenario Benchmark

```bash
cd evaluation/
python run_experiments.py                                    # Full run (all models, 5 reps)
python run_experiments.py --resume                          # Resume from checkpoint
python run_experiments.py --quick                           # Quick test (10 scenarios)
python run_experiments.py --model gpt-4o-mini               # GPT-4o-mini via OpenAI API
python run_experiments.py --model qwen2.5-7b-instruct       # Single local model
python run_experiments.py --system provsafe                  # Single defense system
```

### InjecAgent External Benchmark

```bash
cd evaluation/
python run_injecagent.py --reps 3 --setting base             # Full run (1,054 cases)
python run_injecagent.py --quick                             # Quick test (20 cases)
python run_injecagent.py --model gpt-4o-mini                 # GPT-4o-mini
python run_injecagent.py --resume                            # Resume from checkpoint
```

### Adaptive Adversary & Encoding Robustness

```bash
cd evaluation/
python adaptive_adversary.py                                 # 60 white-box scenarios (RQ7)
python encoding_robustness.py --decoder-only                 # 36 encoding vectors (RQ9)
```

## Supported LLM Providers

| Provider | Models | Cost |
|----------|--------|------|
| **LM Studio** (local) | Llama-3.1-8B, Qwen2.5-7B, Gemma-2-9B, Phi-3.5-Mini | Free (Apple Silicon) |
| **OpenAI** (cloud) | gpt-4o-mini | Pay-per-use |
| **Groq** (cloud) | Llama-3.1-70B | Free tier |
| **Google Gemini** (cloud) | Gemini-1.5-Flash | Free tier |

```bash
# Copy and fill in API keys
cp evaluation/.env.example evaluation/.env
```

## Project Structure

```
provsafe/
├── src/
│   ├── enforcement_proxy.py      # 7-stage enforcement pipeline (heart of the system)
│   ├── provenance_graph.py       # W3C PROV-DM DAG, 12-encoding decoder, trust lattice
│   ├── policy_engine.py          # First-match YAML policy evaluator
│   └── provsafe/                 # Production Python package (policy, provenance, proxy)
├── evaluation/
│   ├── run_experiments.py        # Main 212-scenario experiment runner
│   ├── run_injecagent.py         # InjecAgent external benchmark (ACL 2024)
│   ├── baseline_systems.py       # 5 defense systems (NoDefense → PROVSAFE)
│   ├── model_providers.py        # Unified multi-provider LLM config
│   ├── adaptive_adversary.py     # White-box adaptive adversary (60 scenarios)
│   ├── encoding_robustness.py    # Encoding robustness (36 test vectors)
│   └── scenarios_expanded.json   # 212 scenario definitions (172 attacks + 40 benign)
├── configs/policies/             # YAML policy files (default, permissive, strict)
├── overleaf/                     # ACM CCS 2026 paper (LaTeX, acmart sigconf)
├── results/                      # Experiment checkpoints and results
├── scripts/                      # Utility scripts (update paper numbers, status checks)
└── tests/                        # Test suite (76 tests)
```

## Paper Numbers

All numbers in the paper are verified against checkpoint data:

```bash
# Verify paper numbers match actual results (should show 0 mismatches)
python audit_paper.py

# Recompute all numbers from checkpoints (Wilson CIs, Fisher exact tests)
python compute_paper_numbers.py

# Auto-fill numbers into LaTeX source
python scripts/update_paper_numbers.py
python scripts/update_injecagent_numbers.py
```

