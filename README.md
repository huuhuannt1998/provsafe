# PROVSAFE: Provenance-Gated Policy Enforcement for Tool-Using LLM Agents

**PROVSAFE** is a provenance-gated capability enforcement framework that defends tool-using LLM agents against prompt injection attacks. It tracks where every tool-call argument originated and enforces declarative policies at the tool-call boundary — blocking attacker-injected operations while allowing legitimate ones.

## Key Results

| System | ASR-IA ↓ | TSR ↑ | Benchmark |
|--------|----------|-------|-----------|
| No Defense | 25.94% | 99.38% | TDSC (16K trials) |
| Pattern Filter | 7.50% | 99.38% | TDSC |
| Policy-Only | 1.88% | 97.50% | TDSC |
| **PROVSAFE** | **1.09%** | **95.00%** | **TDSC** |
| Policy-Only | 22.67% | — | InjecAgent (1,054 cases) |
| **PROVSAFE** | **4.12%** | — | **InjecAgent** |

Provenance is the deciding factor: Policy-Only matches No Defense on InjecAgent (22.67% vs 20.83%) because attacker tools are not syntactically dangerous. PROVSAFE reduces ASR to 4.12% by tracing arguments to their untrusted source.

## Architecture

```
User Command (TRUSTED)
    │
    ▼
┌─────────────┐
│  LLM Agent  │
└──────┬──────┘
       │ tool call
       ▼
┌──────────────────────────────────────┐
│        Enforcement Proxy             │
│  1. Decode args (9 encodings)        │
│  2. Resolve provenance (DAG)         │
│  3. Evaluate YAML policy             │
│  4. Trust-lattice gate               │
│  5. User confirmation (if needed)    │
│  6. SHA-256 audit log                │
└──────┬───────────────────────────────┘
       │
       ▼
┌─────────────┐    ┌──────────────┐
│  Tool APIs  │◄───│ External APIs │ (UNTRUSTED)
└─────────────┘    └──────────────┘
```

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Requirements: Python 3.9+, [LM Studio](https://lmstudio.ai/) for local LLM inference.

## Quick Start

```bash
# Smoke test (no LLM needed)
python scripts/quick_test.py

# Run tests
pytest

# Quick evaluation (10 scenarios, 2 reps)
cd evaluation/
python run_tdsc_experiments.py --quick
```

## Full Evaluation

### TDSC Benchmark (16,000 trials)

```bash
cd evaluation/
python run_tdsc_experiments.py                    # Full run (~24 hours)
python run_tdsc_experiments.py --resume           # Resume from checkpoint
python run_tdsc_experiments.py --quick            # Quick test (10 scenarios)
python run_tdsc_experiments.py --model qwen2.5-7b-instruct  # Single model
```

### InjecAgent External Benchmark

```bash
cd evaluation/
python run_injecagent.py --reps 3 --setting base  # Full run
python run_injecagent.py --quick                   # Quick test
```

### LLM-as-Judge Verification

```bash
cd evaluation/
python llm_judge.py --results ../results/tdsc_full_v2/all_results.json --sample 200
```

## Supported LLM Providers

| Provider | Models | Cost |
|----------|--------|------|
| LM Studio (local) | Llama-3.1-8B, Qwen2.5-7B, Gemma-2-9B, Phi-3.5-Mini | Free |
| Groq (cloud) | Llama-3.1-70B | Free tier |
| Google Gemini (cloud) | Gemini-1.5-Flash | Free tier |

```bash
# Set API keys for cloud providers (optional)
export GROQ_API_KEY=gsk_...
export GEMINI_API_KEY=AIza...
```

## Project Structure

```
provsafe/
├── src/                          # Core framework
│   ├── enforcement_proxy.py      # 7-stage enforcement pipeline
│   ├── provenance_graph.py       # W3C PROV-DM DAG with trust lattice
│   ├── policy_engine.py          # YAML policy evaluator
│   └── provsafe/                 # Python package
├── evaluation/                   # Research evaluation
│   ├── run_tdsc_experiments.py   # Main 16K-trial experiment
│   ├── run_injecagent.py         # InjecAgent benchmark
│   ├── baseline_systems.py       # 4 defense systems
│   ├── model_providers.py        # Multi-provider LLM config
│   └── llm_judge.py              # LLM-as-Judge verification
├── configs/policies/             # YAML policy files
├── overleaf/                     # IEEE TDSC paper (LaTeX)
├── results/                      # Experiment results
├── scripts/                      # Utility scripts
└── tests/                        # Test suite
```

## Paper

The paper targets **IEEE Transactions on Dependable and Secure Computing (TDSC)**. Source is in `overleaf/`.

```bash
# Auto-update paper numbers from results
python scripts/update_paper_numbers.py
python scripts/update_injecagent_numbers.py
```

## Citation

```bibtex
@article{provsafe2026,
  title={PROVSAFE: Provenance-Gated Policy Enforcement for Tool-Using LLM Agents},
  author={Anonymous},
  journal={IEEE Transactions on Dependable and Secure Computing},
  year={2026},
  note={Under review}
}
```

## License

MIT
