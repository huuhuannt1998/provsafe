# PROVSAFE: Provenance-Verified Capability Sandboxing for Tool-Using LLM Agents

PROVSAFE is a research prototype that defends tool-using LLM agents (e.g., smart-home assistants)
against prompt injection and untrusted-content attacks by enforcing:
- capability contracts at a tool-call proxy, and
- provenance-based gating decisions with auditable traces.

## Repository Layout

```text
provsafe/
  src/provsafe/
    proxy/              # tool-call gateway + request/response schema
    policy/             # capability contracts + decision engine
    provenance/         # provenance graph data model + trust labeling
    attacks/            # attack suite generators
    bench/              # benchmark tasks + success criteria
    eval/               # metrics + runners
    replay/             # deterministic replays with manifests
  configs/              # capability policies, tool schemas, risk tiers
  scripts/              # run benchmark, run attacks, generate tables
  tests/                # policy tests, provenance tests, replay tests
Quickstart
bash
Copy code
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .

# Run benchmark suite (no real IoT needed; uses mock tools)
python -m provsafe.eval.run_suite \
  --suite configs/suites/default.yaml \
  --policy configs/policies/provsafe.yaml \
  --out runs/default \
  --seed 123
Outputs:

runs/.../metrics.json (ASR/UAR/TSR, confirmations, latency)

runs/.../provenance.jsonl (auditable traces)

runs/.../manifest.json (seed, policy hash, suite hash)

Tool-Call Proxy
All tool calls must route through PROVSAFE:

The proxy validates schema, applies capability contracts, and records provenance.

When blocked, the proxy returns a structured denial with reason codes.

Policies
Policies are YAML:

allowed tools/actions/resources

constraints (time windows, rate limits, user approvals)

risk tiers and evidence requirements

Attack Suite
Includes:

device-name injection

notification injection

multi-user conflict prompts

chained tool-call injections

Run:

bash
Copy code
python -m provsafe.eval.run_attacks \
  --suite configs/suites/injection.yaml \
  --policy configs/policies/provsafe.yaml \
  --out runs/injection
Reproducibility
Every run logs:

deterministic seeds

suite hash

policy hash

tool schema hash

replayable transcripts

Re-run with the same seed should reproduce identical decisions in mock mode.

License