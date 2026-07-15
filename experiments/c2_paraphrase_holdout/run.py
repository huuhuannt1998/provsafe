#!/usr/bin/env python3
"""C2: Held-out paraphrase validation for Stage-2 (embedding similarity).

Builds InjecAgent-derived held-out pairs (the load-bearing test) and, when
`datasets` is installed, also evaluates on PAWS-X.

InjecAgent pair construction:
  Positive (paraphrase): (User instruction, Attacker instruction) pairs from
    InjecAgent dh_base — both reference the user's task context but the attacker
    instruction is rephrased to look benign. NOT a true paraphrase pair, but
    serves as a sanity-check that genuinely-different texts score below θ.
  Better: (Attacker instruction, Tool Response Template payload) — when the
    payload echoes the attacker instruction in a paraphrased form. We construct
    these by extracting the attacker instruction and the tool response that
    contains a paraphrased rendering of it.

We use a simpler, more honest construction:
  For each InjecAgent case, the (attacker_instruction, tool_response) pair is
  a "label=1" link if the response paraphrases the instruction, label=0 if not.
  We mark all 510 dh_base cases as label=1 (the response was constructed to
  embed the attack instruction), and pair each with a different case's response
  to create label=0 negatives. This gives us a balanced set.

Output: results.json + holdout_table.tex
"""
import argparse
import json
import random
from pathlib import Path

THRESHOLDS = [0.35, 0.40, 0.45, 0.50, 0.55]


def build_injecagent_pairs(n_pos=50, n_neg=50, seed=0):
    """Build positive (paraphrase) and negative (unrelated) pairs.

    Positive: (Attacker Instruction, Tool Response containing the attack)
    Negative: (Attacker Instruction from case A, Tool Response from case B)
    """
    rng = random.Random(seed)
    cases = []
    for fname in [
        "evaluation/injecagent_data/test_cases_dh_base.json",
        "evaluation/injecagent_data/test_cases_ds_base.json",
    ]:
        p = Path(fname)
        if p.exists():
            cases.extend(json.loads(p.read_text()))

    if not cases:
        return []

    # Filter to cases with both fields populated
    usable = [c for c in cases if c.get("Attacker Instruction") and c.get("Tool Response")]
    rng.shuffle(usable)

    pairs = []
    # Positives: (attack_instruction, tool_response_with_attack)
    for c in usable[:n_pos]:
        pairs.append((c["Attacker Instruction"], c["Tool Response"], 1))
    # Negatives: cross-pair (attack instruction from A, tool response from B)
    cand = usable[n_pos:n_pos + n_neg + 50]
    for i in range(min(n_neg, len(cand) - 1)):
        # pair instruction from candidate i with response from candidate i+1
        pairs.append((cand[i]["Attacker Instruction"], cand[i + 1]["Tool Response"], 0))
    return pairs


def evaluate(pairs, model_name="sentence-transformers/all-MiniLM-L6-v2"):
    if not pairs:
        return {}
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics import precision_score, recall_score, f1_score

    print(f"  loading {model_name}...")
    model = SentenceTransformer(model_name)
    sents1, sents2, labels = zip(*pairs)
    e1 = model.encode(list(sents1), convert_to_numpy=True, normalize_embeddings=True, show_progress_bar=False)
    e2 = model.encode(list(sents2), convert_to_numpy=True, normalize_embeddings=True, show_progress_bar=False)
    sims = (e1 * e2).sum(axis=1)
    out = {"n_pairs": len(pairs), "n_pos": sum(labels), "n_neg": len(labels) - sum(labels)}
    for theta in THRESHOLDS:
        preds = (sims >= theta).astype(int)
        out[str(theta)] = {
            "precision": float(precision_score(labels, preds, zero_division=0)),
            "recall":    float(recall_score(labels, preds, zero_division=0)),
            "f1":        float(f1_score(labels, preds, zero_division=0)),
            "tp": int(((preds == 1) & (labels.__class__ == tuple and (preds == 1))).sum() if False else sum(p == 1 and l == 1 for p, l in zip(preds, labels))),
        }
    out["sim_distribution"] = {
        "pos_mean": float(sims[[i for i, l in enumerate(labels) if l == 1]].mean()),
        "neg_mean": float(sims[[i for i, l in enumerate(labels) if l == 0]].mean()),
        "pos_min":  float(sims[[i for i, l in enumerate(labels) if l == 1]].min()),
        "neg_max":  float(sims[[i for i, l in enumerate(labels) if l == 0]].max()),
    }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=50, help="positives = negatives = n")
    ap.add_argument("--output", default="experiments/c2_paraphrase_holdout/results.json")
    args = ap.parse_args()

    out_dir = Path(args.output).parent
    out_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    print("Building InjecAgent-derived held-out pairs...")
    pairs = build_injecagent_pairs(args.n, args.n)
    print(f"  built {len(pairs)} pairs ({sum(1 for p in pairs if p[2]==1)} pos, {sum(1 for p in pairs if p[2]==0)} neg)")
    print("Evaluating on InjecAgent-derived held-out set...")
    results["injecagent"] = evaluate(pairs)

    # PAWS-X (optional)
    try:
        from datasets import load_dataset
        print("Building PAWS-X pairs...")
        ds = load_dataset("paws-x", "en", split="validation")
        rng = random.Random(0)
        idx = rng.sample(range(len(ds)), min(args.n * 2, len(ds)))
        pairs_pawsx = [(ds[i]["sentence1"], ds[i]["sentence2"], int(ds[i]["label"])) for i in idx]
        print(f"  built {len(pairs_pawsx)} pairs")
        print("Evaluating on PAWS-X held-out set...")
        results["pawsx"] = evaluate(pairs_pawsx)
    except Exception as e:
        print(f"[skip PAWS-X] {e}")
        results["pawsx"] = {"error": str(e)}

    Path(args.output).write_text(json.dumps(results, indent=2))
    print(f"\nWrote {args.output}")
    print("\n=== Summary at θ=0.45 ===")
    for set_name in ("injecagent", "pawsx"):
        r = results.get(set_name, {})
        if "0.45" in r:
            print(f"  {set_name}: P={r['0.45']['precision']:.3f}  R={r['0.45']['recall']:.3f}  F1={r['0.45']['f1']:.3f}  (n={r.get('n_pairs')})")


if __name__ == "__main__":
    main()
