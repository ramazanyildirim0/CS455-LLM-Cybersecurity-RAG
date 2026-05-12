"""
Layer 2: Parallel RAG retrieval across three FAISS indexes.

Two-stage retrieval:
  Stage 1 — Bi-encoder (all-MiniLM-L6-v2): retrieve top-20 per index via FAISS
  Stage 2 — Cross-encoder (ms-marco-MiniLM-L-6-v2): re-rank to top-5

Usage:
    from layer1.static_analysis import run_static_analysis
    from layer2.retrieval import Retriever

    findings  = run_static_analysis(code)
    retriever = Retriever()                       # load once; reuse across calls
    results   = retriever.query(code, findings)   # top-5 per index

Return value:
    {
        "security":    [ { ...chunk fields..., "score": float, "ce_score": float }, ... ],
        "style":       [ ... ],
        "bug_pattern": [ ... ],
    }
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import faiss
import numpy as np
from sentence_transformers import CrossEncoder, SentenceTransformer

from faiss_index.search import load_index

_MODEL_PATH       = Path(__file__).parent.parent / "models" / "all-MiniLM-L6-v2"
_CE_MODEL_PATH    = Path(__file__).parent.parent / "models" / "cross-encoder-ms-marco"
_CE_MODEL_HF_ID   = "cross-encoder/ms-marco-MiniLM-L-6-v2"
_INDEX_NAMES      = ["security", "style", "bug_pattern"]

# Bi-encoder retrieves this many candidates; cross-encoder re-ranks to top_k
_BIENCODER_CANDIDATES = 20


def _search_index(index: faiss.Index, meta: list[dict], vec: np.ndarray, top_k: int) -> list[dict]:
    scores, ids = index.search(vec, top_k)
    results = []
    for score, idx in zip(scores[0], ids[0]):
        if idx == -1:
            continue
        hit = meta[idx].copy()
        hit["score"] = float(score)
        results.append(hit)
    return results


def _rerank(cross_encoder: CrossEncoder, query: str, candidates: list[dict], top_k: int) -> list[dict]:
    """Score (query, text_preview) pairs with the cross-encoder and return top_k."""
    texts = [c.get("text_preview") or c.get("title") or "" for c in candidates]
    pairs = [[query, t] for t in texts]
    ce_scores = cross_encoder.predict(pairs)

    for chunk, ce_score in zip(candidates, ce_scores):
        chunk["ce_score"] = float(ce_score)

    reranked = sorted(candidates, key=lambda c: c["ce_score"], reverse=True)
    return reranked[:top_k]


class Retriever:
    def __init__(self):
        self._model = SentenceTransformer(str(_MODEL_PATH))

        # Load cross-encoder from local path if downloaded, else from HF Hub
        ce_source = str(_CE_MODEL_PATH) if (_CE_MODEL_PATH / "config.json").exists() else _CE_MODEL_HF_ID
        self._cross_encoder = CrossEncoder(ce_source)

        self._indexes = {
            name: load_index(name) for name in _INDEX_NAMES
        }

    def query(self, code: str, layer1_findings: list[dict], top_k: int = 5) -> dict:
        bandit_context = " ".join(
            f["message"] for f in layer1_findings if f["tool"] == "bandit"
        )
        pylint_context = " ".join(
            f["message"] for f in layer1_findings if f["tool"] == "pylint"
        )

        sec_query   = (code + "\n" + bandit_context).strip() if bandit_context else code
        style_query = (code + "\n" + pylint_context).strip() if pylint_context else code
        bug_query   = code

        vecs = self._model.encode(
            [sec_query, style_query, bug_query],
            normalize_embeddings=True,
        ).astype(np.float32)

        tasks = {
            "security":    (self._indexes["security"],    vecs[0:1], sec_query),
            "style":       (self._indexes["style"],       vecs[1:2], style_query),
            "bug_pattern": (self._indexes["bug_pattern"], vecs[2:3], bug_query),
        }

        # Stage 1: retrieve top-20 per index in parallel
        candidates = {}
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {
                pool.submit(_search_index, index, meta, vec, _BIENCODER_CANDIDATES): name
                for name, ((index, meta), vec, _query) in tasks.items()
            }
            for future in as_completed(futures):
                candidates[futures[future]] = future.result()

        # Stage 2: cross-encoder re-rank to top_k per index
        results = {
            name: _rerank(self._cross_encoder, tasks[name][2], candidates[name], top_k)
            for name in _INDEX_NAMES
        }

        return results
