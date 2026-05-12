# FAISS Index Build Statistics

**Built:** 2026-05-12 18:10  
**Embedding model:** `all-MiniLM-L6-v2` (384-dim, loaded from `models/all-MiniLM-L6-v2`)  
**Index type:** `IndexFlatIP` with L2-normalized vectors (cosine similarity)  
**Hardware:** CPU only  

---

## Per-Index Summary

| Index | Vectors | Embedding dim | Build time (s) | `.faiss` size | `_meta.jsonl` size |
|---|---|---|---|---|---|
| `security` | 1,555 | 384 | 2.2 | 2.28 MB | 1.21 MB |
| `style` | 87 | 384 | 0.4 | 0.13 MB | 0.06 MB |
| `bug_pattern` | 10,462 | 384 | 48.5 | 15.33 MB | 5.89 MB |
| **TOTAL** | **12,104** | — | **51.1** | **17.74 MB** | **7.16 MB** |

---

## Source Breakdown per Index

### `security` index

Input files: `security_semgrep.jsonl`, `security_cwe.jsonl`, `security_owasp.jsonl`

| Source | Chunks |
|---|---|
| `owasp` | 856 |
| `semgrep_official` | 373 |
| `cwe` | 302 |
| `semgrep_trailofbits` | 24 |

### `style` index

Input files: `style_peps.jsonl`

| Source | Chunks |
|---|---|
| `pep484_type_hints` | 50 |
| `pep8_style_guide` | 29 |
| `pep257_docstring_conventions` | 8 |

### `bug_pattern` index

Input files: `bug_patterns.jsonl`

| Source | Chunks |
|---|---|
| `dahoas` | 9,462 |
| `muennighoff` | 1,000 |

---

## Notes

- Vectors are L2-normalized before insertion so inner product equals cosine similarity.
- `IndexFlatIP` performs exact (brute-force) search — no approximation. Suitable for this scale (~12K vectors); upgrade to `IndexIVFFlat` if corpus grows beyond ~100K.
- `_meta.jsonl` stores one JSON record per vector in the same order as FAISS IDs, enabling O(1) metadata lookup by FAISS result ID.
- The full `text` field is excluded from `_meta.jsonl` to keep it small; only a 200-char `text_preview` is stored.
