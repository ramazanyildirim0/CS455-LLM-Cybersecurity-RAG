"""
Build three FAISS indexes from normalized JSONL chunks.

Indexes (saved to faiss_index/indexes/):
  security   ← security_semgrep + security_cwe + security_owasp
  style      ← style_peps
  bug_pattern← bug_patterns

Each index is stored as:
  {name}.faiss        — FAISS IndexFlatIP (cosine via L2-normalized vectors)
  {name}_meta.jsonl   — one JSON line per vector (same order as FAISS IDs)

Embedding model: all-MiniLM-L6-v2 (384-dim)
Similarity:      cosine (vectors are L2-normalized before indexing)
"""

import json
import time
from pathlib import Path

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

# ── Paths ────────────────────────────────────────────────────────────────────
PROJECT   = Path(__file__).parent.parent
DATASET   = PROJECT / "dataset"
INDEX_DIR = Path(__file__).parent / "indexes"
INDEX_DIR.mkdir(exist_ok=True)

# ── Model ────────────────────────────────────────────────────────────────────
MODEL_PATH = PROJECT / "models" / "all-MiniLM-L6-v2"
BATCH_SIZE = 64

# ── Which JSONL files feed which index ───────────────────────────────────────
INDEX_SOURCES = {
    "security":    ["security_semgrep.jsonl", "security_cwe.jsonl", "security_owasp.jsonl"],
    "style":       ["style_peps.jsonl"],
    "bug_pattern": ["bug_patterns.jsonl"],
}


def load_chunks(jsonl_files: list[str]) -> list[dict]:
    chunks = []
    for fname in jsonl_files:
        path = DATASET / fname
        if not path.exists():
            print(f"  WARNING: {fname} not found — skipping")
            continue
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    chunks.append(json.loads(line))
    return chunks


def embed(texts: list[str], model: SentenceTransformer) -> np.ndarray:
    """Return L2-normalized float32 embeddings."""
    vecs = model.encode(
        texts,
        batch_size=BATCH_SIZE,
        show_progress_bar=True,
        convert_to_numpy=True,
        normalize_embeddings=True,   # L2 normalization → cosine via IndexFlatIP
    )
    return vecs.astype(np.float32)


def build_index(name: str, chunks: list[dict], model: SentenceTransformer):
    print(f"\n{'='*55}")
    print(f"  Building index: {name}  ({len(chunks):,} chunks)")
    print(f"{'='*55}")

    texts = [c["text"] for c in chunks]

    t0 = time.time()
    vecs = embed(texts, model)
    embed_secs = round(time.time() - t0, 1)
    print(f"  Embedded in {embed_secs}s  shape={vecs.shape}")

    dim   = vecs.shape[1]
    index = faiss.IndexFlatIP(dim)   # inner product on L2-normed vecs = cosine
    index.add(vecs)
    print(f"  FAISS index: {index.ntotal} vectors, dim={dim}")

    # Save index
    faiss_path = INDEX_DIR / f"{name}.faiss"
    faiss.write_index(index, str(faiss_path))
    faiss_mb = round(faiss_path.stat().st_size / 1024 / 1024, 2)
    print(f"  Saved: {faiss_path.name}  ({faiss_mb} MB)")

    # Save parallel metadata (one JSON line per vector, order matches FAISS IDs)
    meta_path = INDEX_DIR / f"{name}_meta.jsonl"
    with open(meta_path, "w", encoding="utf-8") as f:
        for chunk in chunks:
            # Store everything except the full text to keep meta file small
            meta = {k: v for k, v in chunk.items() if k != "text"}
            meta["text_preview"] = chunk["text"][:200]
            f.write(json.dumps(meta, ensure_ascii=False) + "\n")
    meta_mb = round(meta_path.stat().st_size / 1024 / 1024, 2)
    print(f"  Saved: {meta_path.name}")

    # Count source breakdown
    source_counts = {}
    for c in chunks:
        source_counts.setdefault(c["source"], 0)
        source_counts[c["source"]] += 1

    return {
        "index":        name,
        "vectors":      index.ntotal,
        "dim":          dim,
        "embed_secs":   embed_secs,
        "faiss_mb":     faiss_mb,
        "meta_mb":      meta_mb,
        "sources":      source_counts,
        "jsonl_inputs": INDEX_SOURCES[name],
    }


def write_stats_md(stats_list: list[dict], model_path: Path, built_at: str):
    """Write index build statistics to a markdown file for the project report."""
    out = PROJECT / "faiss_index" / "index_stats.md"

    total_vectors = sum(s["vectors"] for s in stats_list)
    total_faiss   = sum(s["faiss_mb"] for s in stats_list)
    total_meta    = sum(s["meta_mb"] for s in stats_list)
    total_secs    = sum(s["embed_secs"] for s in stats_list)

    lines = [
        "# FAISS Index Build Statistics",
        "",
        f"**Built:** {built_at}  ",
        f"**Embedding model:** `all-MiniLM-L6-v2` (384-dim, loaded from `{model_path.relative_to(PROJECT)}`)  ",
        f"**Index type:** `IndexFlatIP` with L2-normalized vectors (cosine similarity)  ",
        f"**Hardware:** CPU only  ",
        "",
        "---",
        "",
        "## Per-Index Summary",
        "",
        "| Index | Vectors | Embedding dim | Build time (s) | `.faiss` size | `_meta.jsonl` size |",
        "|---|---|---|---|---|---|",
    ]

    for s in stats_list:
        lines.append(
            f"| `{s['index']}` | {s['vectors']:,} | {s['dim']} "
            f"| {s['embed_secs']} | {s['faiss_mb']} MB | {s['meta_mb']} MB |"
        )

    lines += [
        f"| **TOTAL** | **{total_vectors:,}** | — "
        f"| **{total_secs:.1f}** | **{total_faiss:.2f} MB** | **{total_meta:.2f} MB** |",
        "",
        "---",
        "",
        "## Source Breakdown per Index",
        "",
    ]

    for s in stats_list:
        lines.append(f"### `{s['index']}` index")
        lines.append("")
        lines.append(f"Input files: {', '.join(f'`{f}`' for f in s['jsonl_inputs'])}")
        lines.append("")
        lines.append("| Source | Chunks |")
        lines.append("|---|---|")
        for src, n in sorted(s["sources"].items(), key=lambda x: -x[1]):
            lines.append(f"| `{src}` | {n:,} |")
        lines.append("")

    lines += [
        "---",
        "",
        "## Notes",
        "",
        "- Vectors are L2-normalized before insertion so inner product equals cosine similarity.",
        "- `IndexFlatIP` performs exact (brute-force) search — no approximation. "
          "Suitable for this scale (~12K vectors); upgrade to `IndexIVFFlat` if corpus grows beyond ~100K.",
        "- `_meta.jsonl` stores one JSON record per vector in the same order as FAISS IDs, "
          "enabling O(1) metadata lookup by FAISS result ID.",
        "- The full `text` field is excluded from `_meta.jsonl` to keep it small; "
          "only a 200-char `text_preview` is stored.",
    ]

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n  Stats written → {out.relative_to(PROJECT)}")


def main():
    import datetime
    built_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    print(f"Loading model from: {MODEL_PATH}")
    model = SentenceTransformer(str(MODEL_PATH))
    print(f"  Embedding dim: {model.get_sentence_embedding_dimension()}")

    stats_list = []
    for index_name, sources in INDEX_SOURCES.items():
        chunks = load_chunks(sources)
        if not chunks:
            print(f"\nSkipping {index_name}: no chunks loaded")
            continue
        stats = build_index(index_name, chunks, model)
        stats_list.append(stats)

    print(f"\n{'='*55}")
    print("  SUMMARY")
    print(f"{'='*55}")
    for s in stats_list:
        print(f"  {s['index']:<15} {s['vectors']:>6} vectors   {s['faiss_mb']} MB")

    write_stats_md(stats_list, MODEL_PATH, built_at)


if __name__ == "__main__":
    main()
