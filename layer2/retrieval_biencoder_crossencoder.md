# PythonGuard — Layer 2 Retrieval Results
## Two-Stage: Bi-Encoder → Cross-Encoder Re-ranking

**Date:** 2026-05-12  
**Stage 1 (Bi-encoder):** all-MiniLM-L6-v2 → retrieves top-20 per index (FAISS IndexFlatIP, cosine similarity)  
**Stage 2 (Cross-encoder):** cross-encoder/ms-marco-MiniLM-L-6-v2 → re-ranks top-20 to top-5  
**Query augmentation:** security index uses code + Bandit messages; style index uses code + pylint messages; bug_pattern uses raw code

---

## Test Cases

Same three snippets used in the Layer 3 benchmark:

| # | Snippet | Vulnerability | Expected retrieval target |
|---|---------|--------------|--------------------------|
| 1 | SQL string concat | SQL Injection | CWE-89, B608 rules |
| 2 | `os.system(cmd)` | OS Command Injection | CWE-78, B605 rules |
| 3 | `subprocess.call(shell=True)` + hardcoded secret | Shell Injection + Hardcoded Credential | CWE-78, CWE-259, B602, B105 rules |

---

## Detailed Results

### Snippet 1 — SQL Injection

```python
import sqlite3

def get_user(db, user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
```

**Layer 1 findings:** B608 (CWE-89), W0611, C0114, C0116

#### Security Index (top-5 after CE re-ranking)

| Rank | Bi score | CE score | Citation | Title |
|------|----------|----------|----------|-------|
| 1 | 0.4852 | -1.4329 | semgrep:access-foreign-keys | access-foreign-keys |
| 2 | 0.4766 | -2.7635 | semgrep:sql-injection-db-cursor-execute | sql-injection-db-cursor-execute |
| 3 | 0.4439 | -3.5153 | semgrep:sql-injection-using-raw | sql-injection-using-raw |
| 4 | 0.4290 | -3.6270 | semgrep:sql-injection-using-rawsql | sql-injection-using-rawsql |
| 5 | 0.4544 | -3.9680 | semgrep:user-exec-format-string | user-exec-format-string |

> **Note:** Bi-encoder and CE agree on positions 1–2. CE demotes `user-exec-format-string` (bi rank #3 at 0.4544) to rank #5, correctly preferring the direct SQL injection rules.

#### Style Index (top-5 after CE re-ranking)

| Rank | Bi score | CE score | Citation | Title |
|------|----------|----------|----------|-------|
| 1 | 0.3833 | -0.9842 | pep484:newtype-helper-function | PEP 484 — NewType helper function |
| 2 | 0.2077 | -3.1069 | pep484:callable | PEP 484 — Callable |
| 3 | 0.2346 | -3.8681 | pep484:user-defined-generic-types | PEP 484 — User-defined generic types |
| 4 | 0.2988 | -4.4165 | pep257:one-line-docstrings | PEP 257 — One-line Docstrings |
| 5 | 0.2253 | -5.8390 | pep257:rationale | PEP 257 — Rationale |

#### Bug Pattern Index (top-5 after CE re-ranking)

| Rank | Bi score | CE score | Citation | Title |
|------|----------|----------|----------|-------|
| 1 | 0.4507 | +0.8496 | muennighoff:python-bugs:3 | Bug fix: Fix binary operator (Envelope.py) |
| 2 | 0.4572 | +0.4246 | muennighoff:python-bugs:9 | Bug fix: Fix binary operator (basesqlutil.py) |
| 3 | 0.5347 | -0.2828 | muennighoff:python-bugs:5 | Bug fix: Fix binary operator (create_tables_test.py) |
| 4 | 0.7099 | -1.5038 | dahoas:question:241333 | Is it good practice to give a value to a variable... |
| 5 | 0.5588 | -2.2227 | dahoas:question:138667 | SQLite database for a micro/tumble blog application |

> **Note:** The bi-encoder ranked `dahoas:question:241333` as #1 (bi=0.71). The cross-encoder demoted it to #4 and elevated binary-operator bug fixes to the top, which are more structurally similar to the SQL concatenation pattern.

---

### Snippet 2 — OS Command Injection

```python
import os

def run_command(cmd):
    os.system(cmd)
```

**Layer 1 findings:** B605 (CWE-78), C0114, C0116

#### Security Index (top-5 after CE re-ranking)

| Rank | Bi score | CE score | Citation | Title |
|------|----------|----------|----------|-------|
| 1 | 0.6570 | -1.0594 | semgrep:command-injection-os-system | command-injection-os-system |
| 2 | 0.6666 | -1.5019 | semgrep:os-system-injection | os-system-injection |
| 3 | 0.6972 | -5.0665 | semgrep:subprocess-injection | subprocess-injection |
| 4 | 0.6972 | -5.0665 | semgrep:subprocess-injection | subprocess-injection |
| 5 | 0.6574 | -6.3131 | semgrep:dangerous-subprocess-use | dangerous-subprocess-use |

> **Key re-ranking effect:** The bi-encoder ranked `subprocess-injection` #1 (bi=0.697) because it is lexically similar to shell injection. The cross-encoder correctly promoted `command-injection-os-system` (bi=0.657) to rank #1 — it is specifically about `os.system()`, which is exactly the vulnerability present.

#### Style Index (top-5 after CE re-ranking)

| Rank | Bi score | CE score | Citation | Title |
|------|----------|----------|----------|-------|
| 1 | 0.3120 | -4.0966 | pep8:imports | PEP 8 — Imports |
| 2 | 0.5291 | -4.6381 | pep257:what-is-a-docstring | PEP 257 — What is a Docstring? |
| 3 | 0.5261 | -4.8529 | pep257:specification | PEP 257 — Specification |
| 4 | 0.3989 | -6.9837 | pep8:documentation-strings | PEP 8 — Documentation Strings |
| 5 | 0.3852 | -7.2015 | pep257:multi-line-docstrings | PEP 257 — Multi-line Docstrings |

#### Bug Pattern Index (top-5 after CE re-ranking)

| Rank | Bi score | CE score | Citation | Title |
|------|----------|----------|----------|-------|
| 1 | 0.5729 | +5.1254 | dahoas:question:62503 | Join argv list with spaces |
| 2 | 0.4555 | +2.5548 | muennighoff:python-bugs:4 | Bug fix: Fix binary operator (_vertica.py) |
| 3 | 0.4723 | +1.3419 | muennighoff:python-bugs:5 | Bug fix: Fix binary operator (status.py) |
| 4 | 0.4618 | -1.3152 | muennighoff:python-bugs:1 | Bug fix: Fix binary operator (test_imageop.py) |
| 5 | 0.5154 | -2.1069 | muennighoff:python-bugs:7 | Bug fix: Fix binary operator (subcommand.py) |

> **Strong cross-encoder signal:** `dahoas:question:62503` ("Join argv list with spaces") received a very high CE score (+5.13). Its content explicitly discusses replacing `os.system` with `subprocess`, making it highly relevant. The bi-encoder had already ranked it #1 (bi=0.573); CE strongly confirmed this.

---

### Snippet 3 — Shell Injection + Hardcoded Secret

```python
import subprocess

SECRET = "hunter2"

def deploy(host):
    subprocess.call("ssh " + host, shell=True)
```

**Layer 1 findings:** B602 (CWE-78), B404 (CWE-78), B105 (CWE-259), C0114, C0116

#### Security Index (top-5 after CE re-ranking)

| Rank | Bi score | CE score | Citation | Title |
|------|----------|----------|----------|-------|
| 1 | 0.5152 | -0.5064 | semgrep:subprocess-shell-true | subprocess-shell-true |
| 2 | 0.5607 | -0.6592 | semgrep:subprocess-injection | subprocess-injection |
| 3 | 0.5607 | -0.6592 | semgrep:subprocess-injection | subprocess-injection |
| 4 | 0.4591 | -1.2152 | semgrep:subprocess-list-passed-as-string | subprocess-list-passed-as-string |
| 5 | 0.4570 | -2.2286 | semgrep:dangerous-subprocess-use | dangerous-subprocess-use |

> **Re-ranking effect:** `subprocess-shell-true` (bi=0.515) was ranked #3 by the bi-encoder but promoted to #1 by the cross-encoder — it is the most precise rule for `shell=True` usage.

#### Style Index (top-5 after CE re-ranking)

| Rank | Bi score | CE score | Citation | Title |
|------|----------|----------|----------|-------|
| 1 | 0.2696 | -3.4831 | pep8:imports | PEP 8 — Imports |
| 2 | 0.2121 | -5.7531 | pep484:callable | PEP 484 — Callable |
| 3 | 0.2919 | -9.4102 | pep257:one-line-docstrings | PEP 257 — One-line Docstrings |
| 4 | 0.2164 | -9.7232 | pep484:version-and-platform-checking | PEP 484 — Version and platform checking |
| 5 | 0.2292 | -10.6630 | pep257:acknowledgements | PEP 257 — Acknowledgements |

> **Note:** All CE scores are strongly negative for this snippet's style results, indicating the style index has low relevance to this particular code pattern. This is expected — the code has no notable style violations beyond missing docstrings.

#### Bug Pattern Index (top-5 after CE re-ranking)

| Rank | Bi score | CE score | Citation | Title |
|------|----------|----------|----------|-------|
| 1 | 0.4997 | -7.3916 | dahoas:question:171179 | Python script to execute a command using Paramiko SSH |
| 2 | 0.3951 | -7.8623 | muennighoff:python-bugs:7 | Bug fix: Fix binary operator (subcommand.py) |
| 3 | 0.3922 | -7.8914 | muennighoff:python-bugs:7 | Bug fix: Fix binary operator (node.py) |
| 4 | 0.4781 | -8.1387 | muennighoff:python-bugs:6 | Bug fix: Fix incorrect variable name (local_state.py) |
| 5 | 0.3970 | -8.3146 | muennighoff:python-bugs:5 | Bug fix: Fix incorrect variable name (manifest_xml.py) |

> **Note:** All CE scores are strongly negative here too. The Paramiko SSH entry (rank #1) is semantically closest to the SSH deployment context in the snippet, but no bug pattern chunk has a strong match for `shell=True` + hardcoded secret combination.

---

## Comparison: Bi-Encoder Only vs. Bi-Encoder + Cross-Encoder

The most impactful re-ranking occurs in the **security index** where the cross-encoder consistently corrects the bi-encoder's top-1 pick:

| Snippet | Bi-encoder top-1 | CE-reranked top-1 | Change |
|---------|-----------------|-------------------|--------|
| SQL injection | access-foreign-keys (0.485) | access-foreign-keys (-1.43) | No change — both agree |
| OS command injection | **subprocess-injection** (0.697) | **command-injection-os-system** (-1.06) | Promoted more specific rule |
| Shell injection | **subprocess-injection** (0.561) | **subprocess-shell-true** (-0.51) | Promoted `shell=True`-specific rule |

In snippets 2 and 3, the bi-encoder retrieved the correct vulnerability class but ranked a more generic rule first. The cross-encoder correctly promoted the more specific rule in both cases.

**CE score interpretation:**  
ms-marco scores are logit-scale (unbounded). Higher = more relevant. Scores above 0 indicate strong relevance; scores below -5 indicate weak relevance. The security index consistently produces scores in the -1 to -7 range, while the bug_pattern index shows wider variation (+5 to -10 depending on snippet).
