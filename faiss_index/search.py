"""
Query utility for the three FAISS indexes.

Usage:
  python3 faiss_index/search.py "sql injection in flask" --index security --top 5
  python3 faiss_index/search.py "docstring format"       --index style    --top 3
  python3 faiss_index/search.py "binary operator bug"    --index bug_pattern --top 5
"""

import argparse
import json
from pathlib import Path

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

INDEX_DIR  = Path(__file__).parent / "indexes"
MODEL_PATH = Path(__file__).parent.parent / "models" / "all-MiniLM-L6-v2"

VALID_INDEXES = ["security", "style", "bug_pattern"]


def load_index(name: str):
    faiss_path = INDEX_DIR / f"{name}.faiss"
    meta_path  = INDEX_DIR / f"{name}_meta.jsonl"
    if not faiss_path.exists():
        raise FileNotFoundError(f"Index not found: {faiss_path}  — run build_indexes.py first")
    index = faiss.read_index(str(faiss_path))
    meta  = [json.loads(l) for l in open(meta_path, encoding="utf-8")]
    return index, meta


def search(query: str, index_name: str, top_k: int = 5):
    model = SentenceTransformer(str(MODEL_PATH))
    vec   = model.encode([query], normalize_embeddings=True).astype(np.float32)

    index, meta = load_index(index_name)
    scores, ids = index.search(vec, top_k)

    results = []
    for score, idx in zip(scores[0], ids[0]):
        if idx == -1:
            continue
        hit = meta[idx].copy()
        hit["score"] = float(score)
        results.append(hit)
    return results


def print_results(results: list[dict]):
    for i, r in enumerate(results, 1):
        print(f"\n{'─'*60}")
        print(f"  #{i}  score={r['score']:.4f}")
        print(f"  chunk_id : {r['chunk_id']}")
        print(f"  source   : {r['source']}")
        print(f"  title    : {r['title']}")
        print(f"  severity : {r.get('severity')}")
        print(f"  cwe_ids  : {r.get('cwe_ids')}")
        print(f"  citation : {r.get('citation')}")
        preview = r.get("text_preview", "")
        if preview:
            print(f"  preview  : {preview[:180]}")


def main():
    parser = argparse.ArgumentParser(description="Search PythonGuard FAISS indexes")
    parser.add_argument("query",   help="Natural language query")
    parser.add_argument("--index", choices=VALID_INDEXES, default="security",
                        help="Which index to search (default: security)")
    parser.add_argument("--top",   type=int, default=5, help="Number of results (default: 5)")
    args = parser.parse_args()

    print(f"Query  : {args.query!r}")
    print(f"Index  : {args.index}")
    print(f"Top-k  : {args.top}")

    results = search(args.query, args.index, args.top)
    print_results(results)


if __name__ == "__main__":
    main()
