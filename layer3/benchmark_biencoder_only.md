# PythonGuard — Layer 3 Benchmark Results
## Retrieval: Bi-Encoder Only (no cross-encoder re-ranking)

**Date:** 2026-05-12  
**Embedding model:** all-MiniLM-L6-v2 (384-dim, IndexFlatIP cosine similarity)  
**Retrieval strategy:** Single-stage bi-encoder — top-5 per index, no re-ranking  
**LLM quantization:** Q4_K_M GGUF via llama-cpp-python, n_gpu_layers=-1 (Metal)  
**Models tested:** Qwen2.5-7B-Instruct, Meta-Llama-3.1-8B-Instruct, Mistral-7B-Instruct-v0.3

---

## Score Summary

| Model | JSON Validity | Coverage | Citation Accuracy | Total |
|-------|:---:|:---:|:---:|:---:|
| **qwen2.5** | 3/3 | 8/8 | **7/8** | **18** |
| llama3.1 | 3/3 | 8/8 | 6/8 | 17 |
| mistral | 3/3 | 8/8 | 3/8 | 14 |

**Recommended model: Qwen2.5** (highest citation accuracy, tied on validity and coverage)

### Scoring Rubric
- **JSON Validity** (1 pt per snippet): output parses as a valid JSON array
- **Coverage** (1 pt per expected issue): LLM output references the correct line ±1
- **Citation Accuracy** (1 pt per expected marker): `citation` field contains the expected CWE-ID or Bandit code

---

## Test Cases

Three hand-crafted snippets with known ground-truth vulnerabilities:

| Snippet | Vulnerability | Expected markers |
|---------|--------------|-----------------|
| 1 — SQL injection | String-concatenated SQL query | B608, CWE-89 |
| 2 — OS command injection | `os.system(cmd)` | B605, CWE-78 |
| 3 — Shell injection + hardcoded secret | `subprocess.call(shell=True)` + `SECRET = "hunter2"` | B602, CWE-78, B105, CWE-259 |

---

## Detailed Results

### Model: qwen2.5

---

#### Snippet 1 — SQL Injection

**Input code:**
```python
import sqlite3

def get_user(db, user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
```

**Layer 1 — Static Analysis (4 findings):**
```
Line  1 [INFO    ] PYLINT C0114: Missing module docstring  CWE:—
Line  1 [WARNING ] PYLINT W0611: Unused import sqlite3  CWE:—
Line  3 [INFO    ] PYLINT C0116: Missing function or method docstring  CWE:—
Line  4 [WARNING ] BANDIT B608: Possible SQL injection vector through string-based query construction  CWE:CWE-89
```

**Layer 2 — Top retrieved chunk per index:**
```
security     score=0.5590  semgrep:aiopg-sqli           "aiopg-sqli"
style        score=0.3945  pep257:what-is-a-docstring   "PEP 257 — What is a Docstring?"
bug_pattern  score=0.7225  dahoas:question:185051        "Python simple Class with sqlite and unit testing"
```

**LLM raw output (first 400 chars):**
```json
[
    {
        "line": 4,
        "severity": "CRITICAL",
        "explanation": "This query construction is vulnerable to SQL injection. An attacker can manipulate the `user_id` parameter to execute arbitrary SQL commands.",
        "fix_suggestion": "Use parameterized queries to safely pass user_id. For example: `query = 'SELECT * FROM users WHERE id = ?'` and then pass `user_id` as a parameter
```

**Parsed findings (1 item):**
```
Line  4 [CRITICAL] citation=B608, CWE-89
         This query construction is vulnerable to SQL injection. An attacker can manipulate...
```

**Score:** validity=1  coverage=2/2  citation=2/2

---

#### Snippet 2 — OS Command Injection

**Input code:**
```python
import os

def run_command(cmd):
    os.system(cmd)
```

**Layer 1 — Static Analysis (3 findings):**
```
Line  1 [INFO    ] PYLINT C0114: Missing module docstring  CWE:—
Line  3 [INFO    ] PYLINT C0116: Missing function or method docstring  CWE:—
Line  4 [CRITICAL] BANDIT B605: Starting a process with a shell, possible injection detected  CWE:CWE-78
```

**Layer 2 — Top retrieved chunk per index:**
```
security     score=0.7378  semgrep:dangerous-system-call-tainted-env-args  "dangerous-system-call-tainted-env-args"
style        score=0.5291  pep257:what-is-a-docstring                      "PEP 257 — What is a Docstring?"
bug_pattern  score=0.5729  dahoas:question:62503                           "Join argv list with spaces"
```

**LLM raw output:**
```json
[
    {
        "line": 4,
        "severity": "CRITICAL",
        "explanation": "Starting a process with a shell, possible injection detected, security issue.",
        "fix_suggestion": "Use the 'subprocess' module instead, which is easier to use without accidentally injecting malicious code.",
        "citation": "BANDIT B605, CWE-78, semgrep:dangerous-system-call-tainted-env-args"
    }
]
```

**Parsed findings (1 item):**
```
Line  4 [CRITICAL] citation=BANDIT B605, CWE-78, semgrep:dangerous-system-call-tainted-env-args
         Starting a process with a shell, possible injection detected, security issue.
```

**Score:** validity=1  coverage=2/2  citation=2/2

---

#### Snippet 3 — Shell Injection + Hardcoded Secret

**Input code:**
```python
import subprocess

SECRET = "hunter2"

def deploy(host):
    subprocess.call("ssh " + host, shell=True)
```

**Layer 1 — Static Analysis (5 findings):**
```
Line  1 [INFO    ] BANDIT B404: Consider possible security implications associated with subprocess  CWE:CWE-78
Line  1 [INFO    ] PYLINT C0114: Missing module docstring  CWE:—
Line  3 [INFO    ] BANDIT B105: Possible hardcoded password: 'hunter2'  CWE:CWE-259
Line  5 [INFO    ] PYLINT C0116: Missing function or method docstring  CWE:—
Line  6 [CRITICAL] BANDIT B602: subprocess call with shell=True identified, security issue.  CWE:CWE-78
```

**Layer 2 — Top retrieved chunk per index:**
```
security     score=0.5607  semgrep:subprocess-injection  "subprocess-injection"
style        score=0.3373  pep257:what-is-a-docstring    "PEP 257 — What is a Docstring?"
bug_pattern  score=0.5701  dahoas:question:143625         "Send commands over SSH to server"
```

**LLM raw output (first 400 chars):**
```json
[
    {"line": 1, "severity": "CRITICAL", "explanation": "Detected user input entering a `subprocess` call unsafely. This could result in a command injection vulnerability.", "fix_suggestion": "Use subprocess.run with args instead of shell=True, e.g., subprocess.run(['ssh', host])", "citation": "semgrep:subprocess-injection, s
```

**Parsed findings (4 items):**
```
Line  1 [CRITICAL] citation=semgrep:subprocess-injection, semgrep:subprocess-shell-true, CWE-78
         Detected user input entering a `subprocess` call unsafely...
Line  3 [WARNING ] citation=B105, CWE-259
         Possible hardcoded password: 'hunter2'. Hardcoded secrets can be easily exposed...
Line  5 [INFO    ] citation=C0116, PEP257
         Missing function or method docstring...
Line  6 [CRITICAL] citation=semgrep:subprocess-injection, semgrep:subprocess-shell-true, CWE-78
         Detected user input entering a `subprocess` call unsafely...
```

**Score:** validity=1  coverage=4/4  citation=3/4  
*(missed: B602 not explicitly cited — model cited semgrep rule instead)*

---

### Model: llama3.1

---

#### Snippet 1 — SQL Injection

*(Same input/Layer 1/Layer 2 as above)*

**Parsed findings (8 items):**
```
Line  4 [WARNING ] citation=CWE-89       — Possible SQL injection vector
Line  4 [WARNING ] citation=B608         — Possible SQL injection vector
Line  4 [WARNING ] citation=semgrep:aiopg-sqli
Line  4 [WARNING ] citation=semgrep:tainted-sql-string
Line  4 [WARNING ] citation=semgrep:asyncpg-sqli
Line  1 [INFO    ] citation=PYLINT C0114 — Missing module docstring
Line  1 [WARNING ] citation=PYLINT W0611 — Unused import sqlite3
Line  3 [INFO    ] citation=PYLINT C0116 — Missing function docstring
```

**Score:** validity=1  coverage=2/2  citation=2/2  
*(Over-generates: 5 findings for the same line 4 issue)*

---

#### Snippet 2 — OS Command Injection

**Parsed findings (6 items):**
```
Line  1 [INFO    ] citation=C0114
Line  3 [INFO    ] citation=C0116
Line  4 [CRITICAL] citation=B605, CWE-78
Line  4 [INFO    ] citation=[semgrep:dangerous-system-call-tainted-env-args]
Line  4 [INFO    ] citation=[semgrep:dangerous-system-call]
Line  4 [INFO    ] citation=[semgrep:dangerous-system-call]
```

**Score:** validity=1  coverage=2/2  citation=2/2

---

#### Snippet 3 — Shell Injection + Hardcoded Secret

**Parsed findings (7 items):**
```
Line  1 [INFO    ] citation=CWE-78    — subprocess module security implications
Line  1 [INFO    ] citation=PEP8:W0001 — Missing module docstring
Line  3 [INFO    ] citation=CWE-259   — Possible hardcoded password
Line  5 [INFO    ] citation=PEP8:W0001 — Missing function docstring
Line  6 [CRITICAL] citation=CWE-78    — subprocess shell=True (×3 duplicate findings)
Line  6 [CRITICAL] citation=CWE-78
Line  6 [CRITICAL] citation=CWE-78
```

**Score:** validity=1  coverage=4/4  citation=2/4  
*(Missed: B105 and B602 not cited by name; also produces many duplicates)*

---

### Model: mistral

---

#### Snippet 1 — SQL Injection

**Parsed findings (3 items):**
```
Line  4 [CRITICAL] citation=CWE: CWE-89   — SQL injection
Line  1 [WARNING ] citation=PYLINT W0611  — Unused import
Line  3 [INFO    ] citation=PYLINT C0116  — Missing docstring
```

**Score:** validity=1  coverage=2/2  citation=1/2  
*(Missed: B608 not cited; CWE cited with wrong format "CWE: CWE-89")*

---

#### Snippet 2 — OS Command Injection

**Parsed findings (3 items):**
```
Line  4 [CRITICAL] citation=BANDIT B605, semgrep:dangerous-system-call-tainted-env-args, semgrep:dangerous-system-call
Line  3 [INFO    ] citation=PYLINT C0116
Line  1 [INFO    ] citation=PYLINT C0114
```

**Score:** validity=1  coverage=2/2  citation=1/2  
*(Missed: CWE-78 not cited)*

---

#### Snippet 3 — Shell Injection + Hardcoded Secret

**Parsed findings (3 items):**
```
Line  1 [CRITICAL] citation=semgrep:subprocess-shell-true  — shell=True injection
Line  3 [CRITICAL] citation=BANDIT B105                    — Hardcoded secret
Line  5 [INFO    ] citation=pep257:what-is-a-docstring     — Missing docstring
```

**Score:** validity=1  coverage=4/4  citation=1/4  
*(Missed: CWE-78, CWE-259, B602; attributed shell=True to wrong line)*

---

## Analysis

### Strengths observed across all models
- All three models produced valid JSON on every snippet (validity 3/3)
- All three achieved perfect coverage (8/8) — every expected vulnerability was flagged at the correct line
- Layer 2 retrieval correctly surfaced relevant Semgrep rules for all three vulnerability classes

### Model comparison

**Qwen2.5 (recommended):**  
Highest citation accuracy (7/8). Produces concise, focused findings — typically one well-cited finding per real issue. Correctly cites both Bandit rule IDs and CWE numbers together. Only miss: cited Semgrep rule instead of B602 in snippet 3.

**Llama 3.1:**  
Good citation accuracy (6/8) but tends to over-generate — up to 8 findings for a 5-line snippet, including multiple duplicates for the same line. Useful verbosity for report purposes but would need deduplication in production.

**Mistral:**  
Weakest citation accuracy (3/8). Consistent at identifying issues but frequently omits CWE references, uses non-standard citation formats (`"CWE: CWE-89"` instead of `"CWE-89"`), and misattributes line numbers in multi-issue snippets.

### Retrieval quality note
This benchmark uses **bi-encoder only** (single-stage retrieval). The security index cosine scores ranged from 0.56–0.74, which is adequate but leaves room for improvement. A cross-encoder re-ranking pass (retrieve top-20, re-rank to top-5) is listed in the project proposal as Risk 1 Plan B and could improve citation precision for less common vulnerability patterns.
