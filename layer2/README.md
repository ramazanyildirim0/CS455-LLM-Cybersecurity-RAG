# Layer 2 — Parallel RAG Retrieval

## Overview

Layer 2 is the semantic retrieval stage of the PythonGuard pipeline. Given an input Python code snippet and the Layer 1 static analysis findings, it queries all three FAISS indexes in parallel and returns the top-5 most relevant chunks per index. Retrieval is **two-stage**: a bi-encoder retrieves 20 candidates per index, then a cross-encoder re-ranks them to the final top-5.

## Usage

```python
from layer1.static_analysis import run_static_analysis
from layer2.retrieval import Retriever

code = open("my_script.py").read()

findings  = run_static_analysis(code)   # Layer 1
retriever = Retriever()                 # load once; reuse across calls
results   = retriever.query(code, findings, top_k=5)
```

## Output Format

Returns a dict with one key per index, each holding a list of up to `top_k` result dicts:

```python
{
    "security":    [ { ...chunk fields..., "score": float, "ce_score": float }, ... ],
    "style":       [ { ...chunk fields..., "score": float, "ce_score": float }, ... ],
    "bug_pattern": [ { ...chunk fields..., "score": float, "ce_score": float }, ... ],
}
```

Each result dict contains the chunk's metadata fields plus two scores:

```json
{
  "chunk_id":     "semgrep_official::python.lang.security.audit.dangerous-system-call",
  "source":       "semgrep_official",
  "index_type":   "security",
  "title":        "dangerous-system-call",
  "severity":     "WARNING",
  "cwe_ids":      ["CWE-78"],
  "citation":     "semgrep:python.lang.security.audit.dangerous-system-call",
  "text_preview": "Detected a dynamic value used in a system call...",
  "score":        0.6666,
  "ce_score":    -1.5019
}
```

| Field | Description |
|-------|-------------|
| `score` | Bi-encoder cosine similarity (0–1, higher = more similar) |
| `ce_score` | Cross-encoder relevance logit (unbounded; higher = more relevant) |

## Method

### Query Construction (Layer 1–augmented)

Layer 2 builds a targeted query string for each index by augmenting the raw code with relevant Layer 1 findings:

| Index | Query |
|-------|-------|
| **security** | `code + "\n" + bandit finding messages` |
| **style** | `code + "\n" + pylint finding messages` |
| **bug_pattern** | raw `code` only |

If no findings exist for a given tool the query falls back to the raw code. This augmentation steers the embedding toward the vulnerability class already detected by the static analysis tool.

### Stage 1 — Bi-Encoder (all-MiniLM-L6-v2)

All three query strings are encoded in a single `model.encode()` batch call using the locally-stored `all-MiniLM-L6-v2` sentence transformer (384-dim, L2-normalized). The model is loaded once in `Retriever.__init__()` and reused across all calls.

The three FAISS index searches (`IndexFlatIP`, brute-force cosine similarity) are dispatched concurrently via `ThreadPoolExecutor` with 3 workers. Each index returns **top-20 candidates**.

### Stage 2 — Cross-Encoder Re-ranking (ms-marco-MiniLM-L-6-v2)

The 20 candidates from each index are re-ranked by scoring `(query, text_preview)` pairs with `cross-encoder/ms-marco-MiniLM-L-6-v2`. The cross-encoder reads both texts jointly (not as separate embeddings), giving it fine-grained relevance judgment. The top-5 by CE score are returned.

```
Bi-encoder → top-20 candidates → Cross-encoder → top-5 final results
```

### Index Sources

| Index | Chunks | Source datasets |
|-------|--------|-----------------|
| **security** | 1,555 | Semgrep official rules, Trail of Bits rules, CWE XML (Python-relevant), OWASP Cheat Sheets |
| **style** | 87 | PEP 8, PEP 257, PEP 484 |
| **bug_pattern** | 10,462 | Dahoas/code-review-instruct-critique-revision-python, Muennighoff/python-bugs |
| **Total** | 12,104 | — |

---

## Sample Run — OS Command Injection

Input code:

```python
import os
def run(cmd):
    os.system(cmd)
```

Layer 1: B605 (CWE-78, CRITICAL)

### Bi-encoder only (top-5 by cosine score)

| Rank | Bi score | Title |
|------|----------|-------|
| 1 | 0.6972 | subprocess-injection |
| 2 | 0.6972 | subprocess-injection |
| 3 | 0.6666 | os-system-injection |
| 4 | 0.6574 | dangerous-subprocess-use |
| 5 | 0.6570 | command-injection-os-system |

### Bi-encoder + Cross-encoder (top-5 by CE score after retrieving top-20)

| Rank | Bi score | CE score | Title |
|------|----------|----------|-------|
| 1 | 0.6570 | -1.0594 | **command-injection-os-system** |
| 2 | 0.6666 | -1.5019 | **os-system-injection** |
| 3 | 0.6972 | -5.0665 | subprocess-injection |
| 4 | 0.6972 | -5.0665 | subprocess-injection |
| 5 | 0.6574 | -6.3131 | dangerous-subprocess-use |

**Key observation:** The bi-encoder ranked `subprocess-injection` #1 because it is lexically similar to shell injection in general. The cross-encoder correctly promoted `command-injection-os-system` to #1 — the rule specifically addresses `os.system()`, which is exactly the function used in the input code.

---

## Bi-Encoder vs. Bi-Encoder + Cross-Encoder: Security Index Top-1 Comparison

| Snippet | Bi-encoder top-1 | CE-reranked top-1 | Changed? |
|---------|-----------------|-------------------|----------|
| SQL injection (`" + user_id`) | access-foreign-keys (0.485) | access-foreign-keys (-1.43) | No — both agree |
| OS injection (`os.system(cmd)`) | **subprocess-injection** (0.697) | **command-injection-os-system** (-1.06) | Yes — more specific rule promoted |
| Shell injection (`shell=True`) | **subprocess-injection** (0.561) | **subprocess-shell-true** (-0.51) | Yes — `shell=True`-specific rule promoted |

The cross-encoder makes the biggest difference when the vulnerability has multiple closely related rules in the index. It correctly demotes the generic rule (`subprocess-injection`) in favour of the more precise one (`command-injection-os-system`, `subprocess-shell-true`).

Full detailed results for all three test cases across all three indexes are in [`retrieval_biencoder_crossencoder.md`](retrieval_biencoder_crossencoder.md).

---

## Role in the Pipeline

```
Input Code
    │
    ├──► Layer 1 (Bandit + pylint)
    │        │
    │        └── findings list
    │                │
    ▼                ▼
┌────────────────────────────────────────────┐
│                 Retriever                  │
│                                            │
│  sec_query   = code + bandit messages      │
│  style_query = code + pylint messages      │──► ThreadPoolExecutor (3 threads)
│  bug_query   = code                        │    FAISS top-20 per index
│                                            │
│  Cross-encoder re-ranks 20 → top-5         │
└────────────────────────────────────────────┘
         │              │              │
    security          style       bug_pattern
    top-5 (CE)       top-5 (CE)   top-5 (CE)
         │              │              │
         └──────────────────────────────►  Layer 3 (LLM Prompt Builder)
```

## Dependencies

```
faiss-cpu>=1.7
sentence-transformers>=2.2
numpy
```

Models required:
- `models/all-MiniLM-L6-v2/` — bi-encoder (pre-downloaded during dataset setup)
- `models/cross-encoder-ms-marco/` — cross-encoder (~80 MB, downloaded via `download_llm_models.py`)
