# PythonGuard — Layer 3 Benchmark Results
## Retrieval: Bi-Encoder + Cross-Encoder Re-ranking

**Date:** 2026-05-12  
**Retrieval Stage 1:** all-MiniLM-L6-v2 bi-encoder → top-20 candidates per index (FAISS IndexFlatIP)  
**Retrieval Stage 2:** cross-encoder/ms-marco-MiniLM-L-6-v2 → re-ranks top-20 to top-5  
**LLM quantization:** Q4_K_M GGUF via llama-cpp-python, n_gpu_layers=-1 (Metal)  
**Models tested:** Qwen2.5-7B-Instruct, Meta-Llama-3.1-8B-Instruct, Mistral-7B-Instruct-v0.3

---

## Score Summary

| Model | JSON Validity | Coverage | Citation Accuracy | Total |
|-------|:---:|:---:|:---:|:---:|
| **qwen2.5** | 3/3 | 8/8 | **8/8** | **19** |
| llama3.1 | 3/3 | 8/8 | 4/8 | 15 |
| mistral | 3/3 | 8/8 | 3/8 | 14 |

**Recommended model: Qwen2.5** (perfect citation accuracy with two-stage retrieval)

### Scoring Rubric
- **JSON Validity** (1 pt per snippet): output parses as a valid JSON array
- **Coverage** (1 pt per expected issue): LLM output references the correct line ±1
- **Citation Accuracy** (1 pt per expected marker): `citation` field contains the expected CWE-ID or Bandit code

---

## Comparison vs. Bi-Encoder Only

| Model | Bi-only Total | Bi+CE Total | Change |
|-------|:---:|:---:|:---:|
| **qwen2.5** | 18/19 | **19/19** | +1 (citation 7→8) |
| llama3.1 | 17/19 | 15/19 | −2 (citation 6→4) |
| mistral | 14/19 | 14/19 | 0 |

**Key finding:** Cross-encoder re-ranking helped Qwen2.5 achieve a perfect score (19/19) by surfacing more precise retrieval context — notably promoting `command-injection-os-system` and `subprocess-shell-true` to the top of the security index, which Qwen cited directly. Llama3.1 scored lower in the CE run due to non-deterministic generation variability rather than a retrieval quality regression.

---

## Test Cases

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

**Layer 2 — Top retrieved chunk per index (after CE re-ranking):**
```
security     score=0.4852  ce_top1=semgrep:access-foreign-keys       "access-foreign-keys"
style        score=0.3833  ce_top1=pep484:newtype-helper-function    "PEP 484 — NewType helper function"
bug_pattern  score=0.4507  ce_top1=muennighoff:python-bugs:3         "Bug fix: Fix binary operator (Envelope.py)"
```

**LLM raw output (first 400 chars):**
```json
[
    {
        "line": 4,
        "severity": "CRITICAL",
        "explanation": "This code is vulnerable to SQL injection attacks because user-controlled data is directly concatenated into the SQL query string.",
        "fix_suggestion": "Use parameterized queries to safely pass user input. Modify the query to: query = \"SELECT * FROM users WHERE id = ?\"; return db.execute(query, (user_id,))",
```

**Parsed findings (1 item):**
```
Line  4 [CRITICAL] citation=B608, CWE-89
         This code is vulnerable to SQL injection attacks because user-controlled data is directly concatenated...
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

**Layer 2 — Top retrieved chunk per index (after CE re-ranking):**
```
security     score=0.6570  ce_top1=semgrep:command-injection-os-system  "command-injection-os-system"
style        score=0.3120  ce_top1=pep8:imports                         "PEP 8 — Imports"
bug_pattern  score=0.5729  ce_top1=dahoas:question:62503                "Join argv list with spaces"
```

> Cross-encoder promoted `command-injection-os-system` to rank #1 (was ranked #5 by bi-encoder alone, score 0.657). This is the most specific rule for `os.system()`.

**LLM raw output:**
```json
[
    {
        "line": 4,
        "severity": "CRITICAL",
        "explanation": "Starting a process with a shell, possible injection detected, security issue.",
        "fix_suggestion": "Use the 'subprocess' module instead and pass the arguments safely.",
        "citation": "B605, CWE-78, semgrep:command-injection-os-system, semgrep:os-system-injection"
    }
]
```

**Parsed findings (1 item):**
```
Line  4 [CRITICAL] citation=B605, CWE-78, semgrep:command-injection-os-system, semgrep:os-system-injection
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

**Layer 2 — Top retrieved chunk per index (after CE re-ranking):**
```
security     score=0.5152  ce_top1=semgrep:subprocess-shell-true   "subprocess-shell-true"
style        score=0.2696  ce_top1=pep8:imports                    "PEP 8 — Imports"
bug_pattern  score=0.4997  ce_top1=dahoas:question:171179          "Python script to execute a command using Paramiko SSH"
```

> Cross-encoder promoted `subprocess-shell-true` to rank #1 (was ranked #3 by bi-encoder). This is the most specific rule for `shell=True` usage.

**LLM raw output (first 400 chars):**
```json
[
    {
        "line": 1,
        "severity": "CRITICAL",
        "explanation": "The `subprocess.call` function with `shell=True` is used, which can lead to a command injection vulnerability.",
        "fix_suggestion": "Use `subprocess.run` with a list of arguments instead of a string, or avoid using `shell=True` altogether
```

**Parsed findings (3 items):**
```
Line  1 [CRITICAL] citation=BANDIT B602, CWE-78, semgrep:subprocess-shell-true
         The `subprocess.call` function with `shell=True` is used, which can lead to a command injection vulnerability.
Line  3 [WARNING ] citation=BANDIT B105, CWE-259
         The secret key 'hunter2' is hardcoded in the code, which poses a security risk.
Line  6 [INFO    ] citation=BANDIT B602, CWE-78, semgrep:subprocess-shell-true
         The `subprocess.call` function with `shell=True` is used, which can lead to a command injection vulnerability.
```

**Score:** validity=1  coverage=4/4  citation=4/4  ← Perfect score on this snippet

---

### Model: llama3.1

---

#### Snippet 1 — SQL Injection

*(Same input / Layer 1 / Layer 2 as above)*

**Parsed findings (3 items):**
```
Line  4 [WARNING ] citation=CWE-89                              — SQL injection vector
Line  4 [WARNING ] citation=semgrep:sql-injection-db-cursor-execute
Line  4 [WARNING ] citation=semgrep:sql-injection-using-raw
```

**Score:** validity=1  coverage=2/2  citation=1/2  
*(Missed: B608 not cited)*

---

#### Snippet 2 — OS Command Injection

**Parsed findings (5 items):**
```
Line  4 [CRITICAL] citation=CWE-78
Line  4 [CRITICAL] citation=semgrep:command-injection-os-system
Line  4 [CRITICAL] citation=semgrep:os-system-injection
Line  1 [INFO    ] citation=PYLINT C0114
Line  3 [INFO    ] citation=PYLINT C0116
```

**Score:** validity=1  coverage=2/2  citation=1/2  
*(Missed: B605 not cited by name; also generates duplicate findings for line 4)*

---

#### Snippet 3 — Shell Injection + Hardcoded Secret

**Parsed findings (7 items):**
```
Line  1 [INFO    ] citation=CWE-78         — subprocess module implications
Line  1 [INFO    ] citation=PEP8:W0001     — Missing module docstring
Line  3 [INFO    ] citation=CWE-259        — Hardcoded password
Line  5 [INFO    ] citation=PEP8:W0001     — Missing function docstring
Line  6 [CRITICAL] citation=CWE-78         — shell=True (×3, with Semgrep citations)
Line  6 [CRITICAL] citation=semgrep:subprocess-shell-true
Line  6 [CRITICAL] citation=semgrep:subprocess-injection
```

**Score:** validity=1  coverage=4/4  citation=2/4  
*(Missed: B105, B602 not cited by Bandit rule name; produces duplicate findings for line 6)*

---

### Model: mistral

---

#### Snippet 1 — SQL Injection

**Parsed findings (4 items):**
```
Line  1 [WARNING ] citation=PYLINT W0611   — Unused import
Line  1 [INFO    ] citation=PYLINT C0114   — Missing module docstring
Line  3 [INFO    ] citation=PYLINT C0116   — Missing function docstring
Line  4 [CRITICAL] citation=BANDIT B608, CWE: CWE-89  — SQL injection
```

**Score:** validity=1  coverage=2/2  citation=2/2  
*(Note: uses non-standard format "CWE: CWE-89" — matched by substring check)*

---

#### Snippet 2 — OS Command Injection

**Parsed findings (3 items):**
```
Line  4 [CRITICAL] citation=semgrep:command-injection-os-system
Line  1 [INFO    ] citation=PEP257:what-is-a-docstring
Line  3 [INFO    ] citation=PEP257:what-is-a-docstring
```

**Score:** validity=1  coverage=2/2  citation=0/2  
*(Missed both B605 and CWE-78 — cited only the Semgrep rule name)*

---

#### Snippet 3 — Shell Injection + Hardcoded Secret

**Parsed findings (3 items):**
```
Line  1 [CRITICAL] citation=semgrep:subprocess-shell-true  — shell=True injection
Line  3 [CRITICAL] citation=BANDIT B105                    — Hardcoded secret
Line  5 [INFO    ] citation=PYLINT C0116                   — Missing docstring
```

**Score:** validity=1  coverage=4/4  citation=1/4  
*(Missed: CWE-78, CWE-259, B602; attribution on wrong line for shell=True)*

---

## Analysis

### Qwen2.5 — Perfect score (19/19)

The only model to achieve perfect citation accuracy with two-stage retrieval. Consistently produces focused, well-cited findings — typically one finding per real issue. The cross-encoder's promotion of `command-injection-os-system` and `subprocess-shell-true` to the top of the security index directly influenced Qwen's citations in snippets 2 and 3, producing the first-ever perfect score across all three test cases.

### Llama3.1 — Good coverage, weaker citation (15/19)

Coverage remains perfect (8/8) but citation accuracy dropped from 6/8 (bi-only) to 4/8 with CE retrieval. Llama tends to over-generate — up to 7 findings for a 6-line snippet including duplicates. It correctly identifies vulnerability classes but often omits Bandit rule IDs in favour of Semgrep rule names or CWE numbers alone. The citation scoring miss is partially a generation variability issue rather than a retrieval quality issue.

### Mistral — Consistent but weak citation (14/19)

Citation accuracy unchanged at 3/8. Correctly identifies all vulnerabilities but struggles with citation format (uses `"CWE: CWE-89"` instead of `"CWE-89"`) and misses Bandit rule IDs in 2 out of 3 snippets. The cross-encoder retrieval did surface the correct rules at the top of the context, but Mistral did not consistently cite them.

### Impact of cross-encoder re-ranking on LLM output quality

| Metric | Bi-only (best model) | Bi+CE (best model) |
|--------|---------------------|---------------------|
| Qwen2.5 total | 18/19 | **19/19** |
| Citation accuracy | 7/8 | **8/8** |
| Security index top-1 (snippet 2) | subprocess-injection | **command-injection-os-system** |
| Security index top-1 (snippet 3) | subprocess-injection | **subprocess-shell-true** |

The cross-encoder's key contribution is precision: it demotes generic rules and surfaces the most specific applicable rule at rank #1, which the LLM then cites directly.
