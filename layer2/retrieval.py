"""
Layer 2: Parallel RAG retrieval across three FAISS indexes.

Usage:
    from layer1.static_analysis import run_static_analysis
    from layer2.retrieval import Retriever

    findings  = run_static_analysis(code)
    retriever = Retriever()                       # load once; reuse across calls
    results   = retriever.query(code, findings)   # top-5 per index

Return value:
    {
        "security":    [ { ...chunk fields..., "score": float }, ... ],
        "style":       [ ... ],
        "bug_pattern": [ ... ],
    }
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

from faiss_index.search import load_index

_MODEL_PATH = Path(__file__).parent.parent / "models" / "all-MiniLM-L6-v2"
_INDEX_NAMES = ["security", "style", "bug_pattern"]


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


class Retriever:
    def __init__(self):
        self._model = SentenceTransformer(str(_MODEL_PATH))
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
            "security":    (self._indexes["security"],    vecs[0:1]),
            "style":       (self._indexes["style"],       vecs[1:2]),
            "bug_pattern": (self._indexes["bug_pattern"], vecs[2:3]),
        }

        results = {}
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {
                pool.submit(_search_index, idx, meta, vec, top_k): name
                for name, (idx, meta), vec in (
                    (name, tasks[name][0], tasks[name][1]) for name in tasks
                )
            }
            for future in as_completed(futures):
                results[futures[future]] = future.result()

        return results
