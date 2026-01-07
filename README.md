# PROVSAFE

**Tool-Call Policy Enforcement Proxy with Provenance Logging and Prompt Injection Benchmark**

PROVSAFE is a research prototype implementing:
- **Policy-based tool-call filtering** with capability constraints
- **Provenance tracking** linking tool calls to source inputs
- **Prompt injection benchmark suite** for evaluating agent safety

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Agent     │────▶│  Proxy       │────▶│ Tool API    │
│   Request   │     │  + Policy    │     │             │
└─────────────┘     └──────────────┘     └─────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  Provenance  │
                    │  Graph       │
                    └──────────────┘
```

## Installation

```bash
pip install -e .
```

## Usage

### Quick Start

Run a simple test:
```bash
python scripts/quick_test.py
```

### Basic Evaluation

Run benign tasks:
```bash
python -m provsafe.eval.run_suite \
  --suite configs/suites/default.yaml \
  --policy configs/policies/provsafe.yaml \
  --out runs/test \
  --seed 123
```

Run attack suite:
```bash
python -m provsafe.eval.run_attacks \
  --suite configs/suites/injection.yaml \
  --policy configs/policies/provsafe.yaml \
  --out runs/attacks \
  --seed 123
```

### Research-Grade Evaluation

For publication-quality results:

**1. Comparative Baseline Evaluation:**
```bash
python -m provsafe.eval.run_comparative \
  --suite configs/suites/comprehensive_attacks.yaml \
  --policy configs/policies/provsafe.yaml \
  --out runs/comparative \
  --seed 42
```

**2. Ablation Study:**
```bash
python -m provsafe.eval.run_ablation \
  --suite configs/suites/default.yaml \
  --policy configs/policies/provsafe.yaml \
  --out runs/ablation \
  --seed 42
```

**3. Statistical Analysis (Multiple Trials):**
```bash
python -m provsafe.eval.run_statistical \
  --suite configs/suites/injection.yaml \
  --policy configs/policies/provsafe.yaml \
  --out runs/statistical \
  --trials 30 \
  --start-seed 42
```

**4. Full Evaluation Pipeline:**
```bash
bash scripts/run_full_evaluation.sh
```

See [RESEARCH_EVALUATION.md](RESEARCH_EVALUATION.md) for detailed methodology and interpretation.

## Metrics

### Primary Metrics

- **TSR (Task Success Rate)**: Fraction of benign tasks that completed successfully (measures usability)
- **ASR (Attack Success Rate)**: Fraction of attacks that successfully executed high-risk actions (measures security)
- **UAR (Unwanted Action Rate)**: Fraction of benign tasks incorrectly blocked (measures false positives)

### Secondary Metrics

- **Confirmations/Task**: Average number of user confirmations required
- **Latency**: Average decision latency per tool call

### Target Performance

| Metric | Target | Interpretation |
|--------|--------|----------------|
| TSR | > 90% | High usability |
| ASR | < 10% | Strong security |
| UAR | < 10% | Low false positives |
| Conf/Task | < 0.5 | Minimal user burden |
| Latency | < 100ms | Acceptable overhead |

## Project Structure

```
provsafe/
├── src/provsafe/
│   ├── proxy/          # Tool-call validation and enforcement
│   ├── policy/         # YAML policy parser and evaluator
│   ├── provenance/     # Provenance graph and tracking
│   ├── bench/          # Benchmark task definitions
│   ├── attacks/        # Attack patterns and injection strings
│   ├── eval/           # Evaluation runner and metrics
│   └── replay/         # Deterministic replay
├── configs/
│   ├── policies/       # Policy YAML files
│   ├── suites/         # Test suite definitions
│   └── tools/          # Tool schemas
├── scripts/            # Utility scripts
└── tests/              # pytest test suite
```

## License

MIT
