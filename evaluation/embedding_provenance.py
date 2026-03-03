#!/usr/bin/env python3
"""
Embedding-Based Provenance Resolution for PROVSAFE

Augments substring matching with cosine-similarity over sentence embeddings
so that paraphrased NL arguments can still be linked to their untrusted source.
"""

import numpy as np
from typing import List, Dict, Any, Optional, Tuple

# Lazy-load to avoid slow import at module level
_model = None

def _get_model():
    """Lazy-load the sentence-transformers model."""
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer("all-MiniLM-L6-v2")
    return _model


def embed(texts: List[str]) -> np.ndarray:
    """Encode a list of strings into normalized embeddings."""
    model = _get_model()
    return model.encode(texts, normalize_embeddings=True, show_progress_bar=False)


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity between two vectors (already L2-normalized)."""
    return float(np.dot(a, b))


def find_best_match(
    query: str,
    candidates: List[str],
    threshold: float = 0.45,
) -> Tuple[Optional[int], float]:
    """
    Return (index, score) of the best matching candidate above threshold.
    Returns (None, best_score) if no candidate exceeds the threshold.
    """
    if not candidates:
        return None, 0.0
    all_texts = [query] + candidates
    vecs = embed(all_texts)
    q_vec = vecs[0]
    c_vecs = vecs[1:]
    scores = c_vecs @ q_vec          # dot product on L2-normed = cosine sim
    best_idx = int(np.argmax(scores))
    best_score = float(scores[best_idx])
    if best_score >= threshold:
        return best_idx, best_score
    return None, best_score


# ── Drop-in replacement for ProvenanceGraph.trace_argument_provenance ──

def trace_argument_provenance_with_embeddings(
    graph,                         # ProvenanceGraph instance
    tool_call_args: Dict[str, Any],
    similarity_threshold: float = 0.45,
) -> Dict[str, Any]:
    """
    Same interface as ProvenanceGraph.trace_argument_provenance but adds
    a third resolution stage: embedding-based semantic similarity.

    Resolution order (same as original + one new stage):
      Stage 1  exact / substring match   (original code)
      Stage 2  embedding similarity       *** NEW ***
      Stage 3  conservative default       (unresolved → untrusted)
    """
    from src.provenance_graph import TrustLabel

    provenance_by_arg: Dict[str, Dict] = {}
    untrusted_arg_names: List[str] = []

    for arg_name, arg_value in tool_call_args.items():
        arg_value_str = str(arg_value).lower()

        # ── Stage 1: substring match (original) ────────────────────────
        matching_nodes = graph._find_nodes_containing(arg_value)
        if matching_nodes:
            node_id = matching_nodes[0]
            prov = graph.query_provenance(node_id)
            provenance_by_arg[arg_name] = {**prov, "resolution": "substring"}
            if prov["is_untrusted"]:
                untrusted_arg_names.append(arg_name)
            continue

        # ── Stage 2: embedding similarity ──────────────────────────────
        # Collect content from all nodes
        node_ids = list(graph.nodes.keys())
        contents = [str(graph.nodes[nid].content) for nid in node_ids]

        best_idx, best_score = find_best_match(
            str(arg_value), contents, threshold=similarity_threshold
        )

        if best_idx is not None:
            matched_nid = node_ids[best_idx]
            prov = graph.query_provenance(matched_nid)
            provenance_by_arg[arg_name] = {
                **prov,
                "resolution": "embedding",
                "similarity": best_score,
            }
            if prov["is_untrusted"]:
                untrusted_arg_names.append(arg_name)
            continue

        # ── Stage 3: conservative default — treat as untrusted ─────────
        provenance_by_arg[arg_name] = {
            "is_untrusted": True,
            "resolution": "conservative_default",
            "similarity": best_score if contents else 0.0,
        }
        untrusted_arg_names.append(arg_name)

    return {
        "has_untrusted_args": len(untrusted_arg_names) > 0,
        "untrusted_arg_names": untrusted_arg_names,
        "provenance_by_arg": provenance_by_arg,
    }
