# Layer 1 — Static Analysis (Bandit + pylint)

## Overview

Layer 1 is the deterministic static analysis stage of the PythonGuard pipeline. It runs two tools on the input Python code and returns a unified list of findings as structured JSON. This output is forwarded to Layer 2 (FAISS retrieval) and Layer 3 (LLM prompt builder) as grounding context.

## Usage

```python
from layer1.static_analysis import run_static_analysis

code = open("my_script.py").read()
findings = run_static_analysis(code)
```

## Output Format

Returns a list of dicts, sorted by line number:

```json
[
  {
    "tool":       "bandit",
    "line":       8,
    "severity":   "WARNING",
    "code":       "B608",
    "message":    "Possible SQL injection vector through string-based query construction.",
    "cwe_ids":    ["CWE-89"],
    "confidence": "LOW"
  },
  {
    "tool":       "pylint",
    "line":       3,
    "severity":   "WARNING",
    "code":       "W0611",
    "message":    "Unused import hashlib",
    "cwe_ids":    [],
    "confidence": null
  }
]
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `tool` | str | Source tool: `"bandit"` or `"pylint"` |
| `line` | int | Line number in the input code where the issue was found |
| `severity` | str | Normalized severity: `CRITICAL`, `WARNING`, or `INFO` |
| `code` | str | Tool-specific rule ID (e.g. `B608`, `W0611`) |
| `message` | str | Human-readable description of the issue |
| `cwe_ids` | list[str] | CWE references from Bandit (e.g. `["CWE-89"]`); always `[]` for pylint |
| `confidence` | str\|null | Bandit confidence level (`HIGH`, `MEDIUM`, `LOW`); `null` for pylint |

### Severity Mapping

**Bandit** (`issue_severity` → `severity`):

| Bandit | Unified |
|--------|---------|
| `HIGH` | `CRITICAL` |
| `MEDIUM` | `WARNING` |
| `LOW` | `INFO` |

**pylint** (`type` → `severity`):

| pylint | Unified |
|--------|---------|
| `fatal`, `error` | `CRITICAL` |
| `warning` | `WARNING` |
| `convention`, `refactor` | `INFO` |

## Sample Run

Input code (intentionally vulnerable):

```python
import os
import hashlib

password = "hardcoded_secret_123"

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return query

def run_cmd(cmd):
    os.system(cmd)
```

Output (8 findings, truncated):

```json
[
  { "tool": "pylint", "line": 1,  "severity": "INFO",     "code": "C0114", "message": "Missing module docstring", ... },
  { "tool": "pylint", "line": 3,  "severity": "WARNING",  "code": "W0611", "message": "Unused import hashlib", ... },
  { "tool": "bandit", "line": 5,  "severity": "INFO",     "code": "B105",  "message": "Possible hardcoded password: 'hardcoded_secret_123'", "cwe_ids": ["CWE-259"], "confidence": "MEDIUM" },
  { "tool": "pylint", "line": 5,  "severity": "INFO",     "code": "C0103", "message": "Constant name \"password\" doesn't conform to UPPER_CASE naming style", ... },
  { "tool": "pylint", "line": 7,  "severity": "INFO",     "code": "C0116", "message": "Missing function or method docstring", ... },
  { "tool": "bandit", "line": 8,  "severity": "WARNING",  "code": "B608",  "message": "Possible SQL injection vector through string-based query construction.", "cwe_ids": ["CWE-89"], "confidence": "LOW" },
  { "tool": "pylint", "line": 11, "severity": "INFO",     "code": "C0116", "message": "Missing function or method docstring", ... },
  { "tool": "bandit", "line": 12, "severity": "CRITICAL", "code": "B605",  "message": "Starting a process with a shell, possible injection detected, security issue.", "cwe_ids": ["CWE-78"], "confidence": "HIGH" }
]
```

### Findings Breakdown

| Tool | Count | Notes |
|------|-------|-------|
| Bandit | 3 | 1 CRITICAL (`os.system`), 1 WARNING (SQL inject), 1 INFO (hardcoded password) |
| pylint | 5 | 1 WARNING (unused import), 4 INFO (style/docstring) |
| **Total** | **8** | Sorted by line number |

## Role in the Pipeline

```
Input Code
    │
    ▼
┌─────────────┐     ┌─────────────┐
│   Bandit    │     │   pylint    │
│  (security) │     │(style/logic)│
└──────┬──────┘     └──────┬──────┘
       │                   │
       └────────┬──────────┘
                ▼
     Unified findings list
     (sorted by line, merged)
                │
                ▼
     Layer 2: FAISS Retrieval
     (cwe_ids + code used as query context)
                │
                ▼
     Layer 3: LLM Prompt Builder
```

- **Bandit findings** feed the security FAISS index via their `cwe_ids` (e.g. `CWE-89` → retrieves SQL injection rules from Semgrep/CWE chunks).
- **pylint findings** feed the style FAISS index via their `code` and `message`.
- Findings with no retrievable citation are labeled `"heuristic"` by the LLM in Layer 3.

## Dependencies

```
bandit>=1.7
pylint>=3.0
```

Install with:

```bash
pip install bandit pylint
```

## Baseline (B2)

In the evaluation plan, **Baseline B2** is defined as Bandit + pylint alone without the LLM layer. The raw output of this module is what B2 produces. The full PythonGuard system (all 3 layers) is compared against B2 on recall, false positive rate, and citation faithfulness.
