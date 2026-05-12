# Layer 2 — Parallel RAG Retrieval

## Overview

Layer 2 is the semantic retrieval stage of the PythonGuard pipeline. Given an input Python code snippet and the Layer 1 static analysis findings, it queries all three FAISS indexes in parallel and returns the top-5 most semantically relevant chunks per index. This output is passed to Layer 3 (the LLM prompt builder) as grounding context for citation-backed findings.

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
    "security":    [ { ...chunk fields..., "score": float }, ... ],
    "style":       [ { ...chunk fields..., "score": float }, ... ],
    "bug_pattern": [ { ...chunk fields..., "score": float }, ... ],
}
```

Each result dict contains the chunk's metadata fields plus a `"score"` (cosine similarity, 0–1):

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
  "score":        0.7193
}
```

## Method

### Query Construction (Layer 1–augmented)

Rather than using a single embedding for all three indexes, Layer 2 builds a targeted query string for each index by augmenting the raw code with relevant Layer 1 findings:

| Index | Query |
|-------|-------|
| **security** | `code + "\n" + bandit finding messages` |
| **style** | `code + "\n" + pylint finding messages` |
| **bug_pattern** | raw `code` only |

If no findings exist for a given tool (e.g. Bandit finds nothing), the query falls back to the raw code. This augmentation steers the embedding toward the vulnerability class already detected by the static analysis tool, improving retrieval precision.

### Embedding

All three query strings are encoded in a single `model.encode()` batch call using the locally-stored `all-MiniLM-L6-v2` sentence transformer (384-dimensional embeddings, L2-normalized for cosine similarity). The model is loaded once in `Retriever.__init__()` and reused across all calls.

### Parallel Search

The three FAISS index searches (`IndexFlatIP`, brute-force cosine similarity) are dispatched concurrently via `concurrent.futures.ThreadPoolExecutor` with 3 workers — one per index. FAISS operations are C++-backed, so threads run with minimal GIL contention. Results are collected as futures complete.

### Index Sources

| Index | Chunks | Source datasets |
|-------|--------|-----------------|
| **security** | 1,555 | Semgrep official rules, Trail of Bits rules, CWE XML (Python-relevant), OWASP Cheat Sheets |
| **style** | 87 | PEP 8, PEP 257, PEP 484 |
| **bug_pattern** | 10,462 | Dahoas/code-review-instruct-critique-revision-python, Muennighoff/python-bugs |
| **Total** | 12,104 | — |

## Sample Run

Input code (OS command injection vulnerability):

```python
import os
def run(cmd):
    os.system(cmd)
```

Layer 1 findings (from Bandit):
- `B605` — `os.system` injection, CRITICAL, CWE-78

Layer 2 security index results (top 5):

| Rank | Score | Title | CWE |
|------|-------|-------|-----|
| 1 | 0.7193 | dangerous-system-call-tainted-env-args | CWE-78 |
| 2 | 0.7105 | dangerous-system-call | CWE-78 |
| 3 | 0.6930 | dangerous-system-call | CWE-78 |
| 4 | 0.6815 | dangerous-os-exec-tainted-env-args | CWE-78 |
| 5 | 0.6710 | os-system-injection | CWE-78 |

All top 5 security results correctly surface CWE-78 (OS Command Injection) Semgrep rules — the precise vulnerability class present in the input. This confirms that the Layer 1–augmented query strategy successfully steers retrieval toward the relevant rule set.

## Role in the Pipeline

```
Input Code
    │
    ├──► Layer 1 (Bandit + pylint)
    │        │
    │        └── findings list
    │                │
    ▼                ▼
┌────────────────────────────────┐
│           Retriever            │
│                                │
│  sec_query  = code + bandit    │
│  style_query = code + pylint   │──► parallel FAISS search (3 threads)
│  bug_query  = code             │
└────────────────────────────────┘
         │           │           │
    security       style    bug_pattern
    top-5          top-5      top-5
         │           │           │
         └─────────────────────────►  Layer 3 (LLM Prompt Builder)
```

## Dependencies

```
faiss-cpu>=1.7
sentence-transformers>=2.2
numpy
```

The `all-MiniLM-L6-v2` model must be present at `models/all-MiniLM-L6-v2/` (pre-downloaded during dataset setup).
