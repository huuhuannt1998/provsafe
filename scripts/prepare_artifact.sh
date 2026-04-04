#!/usr/bin/env bash
# prepare_artifact.sh — Package PROVSAFE for DOI-bearing archival artifact
#
# Usage: bash scripts/prepare_artifact.sh [output_dir]
#
# Creates a self-contained archive suitable for Zenodo/Figshare deposit.
# The archive includes: source code, configs, evaluation scripts, benchmark
# scenarios, canonical results, and documentation.

set -euo pipefail

ARTIFACT_DIR="${1:-artifact_provsafe}"
VERSION="1.0.0"
TIMESTAMP=$(date +%Y%m%d)

echo "=== PROVSAFE Artifact Preparation ==="
echo "Output: ${ARTIFACT_DIR}"
echo "Version: ${VERSION}"
echo ""

# Clean and create artifact directory
rm -rf "${ARTIFACT_DIR}"
mkdir -p "${ARTIFACT_DIR}"

# --- Source code ---
echo "[1/7] Copying source code..."
cp -r src/ "${ARTIFACT_DIR}/src/"
cp pyproject.toml "${ARTIFACT_DIR}/"
cp requirements.txt "${ARTIFACT_DIR}/"

# --- Configs ---
echo "[2/7] Copying policy configs..."
cp -r configs/ "${ARTIFACT_DIR}/configs/"

# --- Evaluation scripts ---
echo "[3/7] Copying evaluation scripts..."
mkdir -p "${ARTIFACT_DIR}/evaluation/"
for f in evaluation/*.py evaluation/*.sh evaluation/.env.example; do
    [ -f "$f" ] && cp "$f" "${ARTIFACT_DIR}/evaluation/"
done
# Benchmark scenarios
cp evaluation/scenarios_expanded.json "${ARTIFACT_DIR}/evaluation/"
# InjecAgent data (if present)
[ -d evaluation/injecagent_data ] && cp -r evaluation/injecagent_data/ "${ARTIFACT_DIR}/evaluation/injecagent_data/"

# --- Tests ---
echo "[4/7] Copying tests..."
cp -r tests/ "${ARTIFACT_DIR}/tests/"

# --- Canonical results ---
echo "[5/7] Copying canonical results..."
mkdir -p "${ARTIFACT_DIR}/results/"
# Primary TDSC results (v2 = canonical)
[ -d results/tdsc_full_v2 ] && cp -r results/tdsc_full_v2/ "${ARTIFACT_DIR}/results/tdsc_full_v2/"
# 122B validation
[ -d results/tdsc_122b ] && cp -r results/tdsc_122b/ "${ARTIFACT_DIR}/results/tdsc_122b/"
# InjecAgent results
[ -d results/injecagent ] && cp -r results/injecagent/ "${ARTIFACT_DIR}/results/injecagent/"
# Stage analysis
[ -d results/stage_analysis ] && cp -r results/stage_analysis/ "${ARTIFACT_DIR}/results/stage_analysis/"

# --- Scripts ---
echo "[6/7] Copying utility scripts..."
cp -r scripts/ "${ARTIFACT_DIR}/scripts/"

# --- Documentation ---
echo "[7/7] Creating artifact documentation..."
cat > "${ARTIFACT_DIR}/README_ARTIFACT.md" << 'HEREDOC'
# PROVSAFE Artifact

**PROVSAFE: Provenance-Gated Policy Enforcement for Tool-Using LLM Agents**

This artifact accompanies the IEEE TDSC submission and contains all code, data,
and results needed to reproduce the paper's experiments.

## Contents

| Directory | Description |
|-----------|-------------|
| `src/` | PROVSAFE source code (enforcement proxy, provenance DAG, policy engine) |
| `configs/` | YAML policy files (provsafe, permissive, strict) |
| `evaluation/` | Experiment runners, baseline systems, benchmark scenarios |
| `tests/` | pytest test suite |
| `results/` | Canonical experiment results (JSON) |
| `scripts/` | Setup, evaluation, and paper-number update scripts |

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
pytest                      # Run tests (no LLM needed)
python scripts/quick_test.py  # Smoke test
```

## Reproducing Results

### Primary Evaluation (25,000 trials)
Requires LM Studio with models loaded:
```bash
cd evaluation/
python run_experiments.py          # Full run
python run_experiments.py --quick  # Quick test (10 scenarios)
```

### InjecAgent Benchmark (1,054 cases)
```bash
cd evaluation/
python run_injecagent.py --reps 3 --setting base
```

### Pre-computed Results
Canonical results are in `results/`:
- `tdsc_full_v2/tdsc_report.json` — Primary 20,000-trial aggregate
- `tdsc_122b/` — 122B large-model validation (5,000 trials)
- `injecagent/` — InjecAgent benchmark results

## Requirements

- Python 3.9+
- LM Studio (for LLM inference) or Groq/Gemini API keys
- See `requirements.txt` for Python dependencies

## License

See LICENSE file in the repository root.
HEREDOC

# --- Create archive ---
echo ""
echo "Creating archive..."
ARCHIVE_NAME="provsafe-artifact-v${VERSION}-${TIMESTAMP}.tar.gz"
tar -czf "${ARCHIVE_NAME}" "${ARTIFACT_DIR}/"
echo ""
echo "=== Artifact Ready ==="
echo "Directory: ${ARTIFACT_DIR}/"
echo "Archive:   ${ARCHIVE_NAME}"
echo "Size:      $(du -sh "${ARCHIVE_NAME}" | cut -f1)"
echo ""
echo "Next steps:"
echo "  1. Review contents in ${ARTIFACT_DIR}/"
echo "  2. Upload ${ARCHIVE_NAME} to Zenodo (zenodo.org/deposit/new)"
echo "  3. Obtain DOI and add to camera-ready paper"
