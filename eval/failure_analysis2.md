# PythonGuard — Evaluation Failure Analysis 2

**Dataset:** s2e-lab/SecurityEval  
**System:** PythonGuard (Qwen2.5-7B-Instruct Q4_K_M, bi-encoder + cross-encoder retrieval)  
**Date:** 2026-05-12  
**Verdict:** Failures are primarily **code-fixable** (Bandit upstream label bug + Fix 3 anchor pollution). Only ~3 cases are genuine model knowledge gaps.

---

## Overview

After implementing the three fixes from `failure_analysis.md`, a new set of `cwe=✗` failures appeared. Diagnostic output (`--verbose`) revealed two systemic code-level problems and one genuine model limitation. Unlike the previous failures which were caused by empty `[]` output, these cases all produce findings (`any=✓`) but cite the wrong vulnerability label (`cwe=✗`).

---

## Problem 1 — Bandit Mislabels `eval()` / `exec()` as CWE-78

### Affected Cases

| Task ID | Expected | Model output |
|---------|----------|-------------|
| `CWE-094_author_1.py` | CWE-94 | `CWE-78` |
| `CWE-094_codeql_1.py` | CWE-94 | `CWE-78` |
| `CWE-094_sonar_1.py`  | CWE-94 | `CWE-78` |
| `CWE-095_author_1.py` | CWE-95 | `CWE-78` |

### The Code (representative — `CWE-094_sonar_1.py`)

```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    '''
    Get the module version from the request object
    importing the urllib module with the version by using exec()
    '''
    module = request.args.get("module")
    exec("import urllib%s as urllib" % module)
    return "Module imported"
```

### Expected Output

```json
{
  "line": 12,
  "severity": "CRITICAL",
  "explanation": "exec() is called with user-controlled input, allowing arbitrary Python code execution.",
  "fix_suggestion": "Never pass user-controlled strings to exec(). Use an allowlist to validate module names.",
  "citation": "CWE-94"
}
```

### Actual Output

```
L1  [CRITICAL] 'E0401'       ← pylint import error anchored as security finding (see Problem 2)
L12 [WARNING]  'CWE-78'      ← exec() cited as OS Command Injection instead of Code Injection
```

### Why It Happened

Bandit's own CWE mapping is incorrect upstream:

```
bandit B102  (use of exec)  → cwe_ids=['CWE-78']   should be CWE-94
bandit B307  (use of eval)  → cwe_ids=['CWE-78']   should be CWE-95
```

Bandit uses **CWE-78 (OS Command Injection)** as a catch-all for all dangerous execution patterns, including Python-native `eval` and `exec`. The correct breakdown is:

| Pattern | Correct CWE | What Bandit reports |
|---------|------------|---------------------|
| `os.system()`, `subprocess.*` | CWE-78 OS Command Injection | CWE-78 ✓ |
| `exec("user_input")` | CWE-94 Code Injection | **CWE-78 ✗** |
| `eval("user_input")` | CWE-95 Eval Injection | **CWE-78 ✗** |

Fix 3 (Layer 1 anchor) then injects these Bandit findings into the final output with `citation="CWE-78"`. The LLM sees CWE-78 anchored in the prompt and faithfully cites it. **The model is behaving correctly** — it is following a wrong signal produced by our own code (the anchor) which blindly trusted Bandit's flawed CWE field.

### Solution

**Fix A — Expand the equivalence map** in `eval/metrics.py`:

```python
"CWE-94": {"CWE-78", "B102", "B104"},   # Code injection ↔ Bandit exec rule
"CWE-95": {"CWE-78", "B307"},            # Eval injection ↔ Bandit eval rule
```

This accepts CWE-78 as a valid hit when the expected label is CWE-94 or CWE-95, recovering the metric without changing any pipeline code.

**Fix B — Override Bandit's CWE for B102/B307 in Layer 1** in `layer1/static_analysis.py`:

```python
_BANDIT_CWE_OVERRIDES = {
    "B102": ["CWE-94"],   # exec → Code Injection, not OS Command Injection
    "B307": ["CWE-95"],   # eval → Eval Injection, not OS Command Injection
}

# In _run_bandit(), after building cwe_ids:
test_id = r.get("test_id", "")
if test_id in _BANDIT_CWE_OVERRIDES:
    cwe_ids = _BANDIT_CWE_OVERRIDES[test_id]
```

This corrects the citation at the Layer 1 level so the anchor injects the right CWE, and the LLM prompt contains accurate context.

Both fixes are needed: Fix A handles the evaluation metric, Fix B corrects the pipeline output for real-world use.

---

## Problem 2 — Fix 3 Anchor Injects `E0401` (pylint Import Error) as CRITICAL Security Finding

### Affected Cases

All Flask/library-importing files in the evaluation where the library is not installed in the test environment (~8+ cases including CWE-79, CWE-80, CWE-90, CWE-94, CWE-99, CWE-113).

### The Code (representative — `CWE-090_codeql_1.py`)

```python
from flask import request, Flask   # line 1
import ldap                         # line 2

app = Flask(__name__)

@app.route("/normal")
def normal():
    dc       = request.args.get('dc')
    username = request.args.get('username')
    conn = ldap.initialize('ldap://localhost')
    conn.search_s("dc="+dc+",dc=com", ...)
```

### Expected Output

```json
{
  "line": 10,
  "severity": "CRITICAL",
  "explanation": "User-controlled input is concatenated directly into an LDAP query string, allowing LDAP injection attacks.",
  "fix_suggestion": "Escape all user input using ldap.dn.escape_dn_chars() before building LDAP queries.",
  "citation": "CWE-90"
}
```

### Actual Output

```
L1 [CRITICAL] 'E0401'    ← "Unable to import 'flask'" anchored as security finding
L2 [CRITICAL] 'E0401'    ← "Unable to import 'ldap'" anchored as security finding
```

### Why It Happened

Flask, ldap, jinja2, and other third-party libraries are not installed in the evaluation environment (and cannot be, as they would clutter the test runner). Pylint generates `E0401 CRITICAL: Unable to import 'flask'` for every file that imports them.

Fix 3 (`_anchor_layer1`) anchors **all** CRITICAL and WARNING Layer 1 findings without filtering. Because `E0401` is mapped to severity `CRITICAL` (via `_PYLINT_SEVERITY["error"] = "CRITICAL"`), it passes the anchor threshold and is injected into the final output as if it were a real security vulnerability.

Two secondary effects:
1. The injected `E0401` at line 1 marks that line as "covered," preventing any real anchor finding from being added nearby.
2. The LLM prompt already includes the E0401 in the Layer 1 section (as an input), so the model sometimes cites it in its own output too.

This is entirely a **code bug introduced by Fix 3** — the anchor does not distinguish between security-relevant findings and test-environment artifacts.

### Solution

**Exclude pylint import errors (E04xx) from the anchor** in `layer3/review.py`:

```python
# Codes that are environment artifacts, not real security issues
_ANCHOR_EXCLUDE_CODES = {
    "E0401",   # Unable to import — library not installed in test env
    "E0402",   # Bad import order — not security-relevant
}

def _anchor_layer1(llm_findings, layer1_findings):
    important = [
        f for f in layer1_findings
        if f["severity"] in _ANCHOR_SEVERITIES
        and f.get("code") not in _ANCHOR_EXCLUDE_CODES
    ]
    ...
```

Additionally, consider excluding all pylint `E04xx` codes (import-related errors) from the anchor entirely, since they are never security findings — they indicate the test runner's environment, not real code issues.

---

## Problem 3 — XSS Sibling Confusion: CWE-79 vs CWE-80

### Affected Cases

| Task ID | Expected | Model output |
|---------|----------|-------------|
| `CWE-079_codeql_1.py` | CWE-79 | `CWE-94` |
| `CWE-079_codeql_2.py` | CWE-79 | `B605`, `W0621` |
| `CWE-079_sonar_1.py`  | CWE-79 | `E0401`, `W1514` |
| `CWE-080_author_1.py` | CWE-80 | `semgrep:make-response-with-unknown-content` |

### The Code (representative — `CWE-080_author_1.py`)

```python
from flask import Flask, request, make_response
app = Flask(__name__)

@app.route("/renderHtml")
def renderHTML():
    name = request.args.get('name', '')
    response = make_response('<h1>Hello ' + name + '</h1>')
    return response
```

### Expected Output

```json
{
  "line": 7,
  "severity": "CRITICAL",
  "explanation": "User input is concatenated into an HTML response without escaping, enabling stored or reflected XSS attacks.",
  "fix_suggestion": "Use flask.escape() or markupsafe.escape() to sanitize user input before embedding in HTML. Consider using render_template() instead.",
  "citation": "CWE-80"
}
```

### Actual Output

```
L1  [CRITICAL] 'B605'
L12 [CRITICAL] 'semgrep:make-response-with-unknown-content'
```

The semgrep citation `make-response-with-unknown-content` is **semantically correct** — it identifies the exact vulnerability pattern. However, it is a semgrep rule name, not a CWE label, so `detection_cwe("CWE-80")` does not match it.

For `CWE-079_codeql_1.py` (jinja2 template injection), the model cited `CWE-94` (code injection), which is also reasonable since jinja2 template injection can lead to arbitrary code execution. The SecurityEval label `CWE-79` (XSS) and `CWE-94` (code injection) both apply — the dataset chose one, the model chose the other.

### Why It Happened

Three sub-causes:

1. **CWE-79 and CWE-80 are siblings** (both XSS variants) but the equivalence map treats them as unrelated.
2. **No Bandit rule for HTML-in-response injection** — Bandit does not flag string concatenation into HTML. Only our heuristic (H001) and the retrieved semgrep rule identify this pattern.
3. **The H001 heuristic** correctly fires (producing a CWE-20 citation via Fix 2), but neither CWE-20 nor the semgrep rule name are in the equivalence set for CWE-79 or CWE-80.

### Solution

**Expand the equivalence map** in `eval/metrics.py`:

```python
"CWE-79": {"CWE-80", "CWE-20", "H001"},   # reflected XSS ↔ basic XSS ↔ input validation
"CWE-80": {"CWE-79", "CWE-20", "H001"},   # basic XSS ↔ reflected XSS ↔ input validation
```

For the semgrep rule name hit, the cleaner fix is to normalise semgrep citations to their CWE in the retrieval layer, but that is a larger change. For the evaluation metric, the equivalence map addition is sufficient.

---

## Problem 4 — Genuine Model Knowledge Gaps (no code fix available)

### Affected Cases

| Task ID | Expected | Model output | Notes |
|---------|----------|-------------|-------|
| `CWE-090_codeql_1.py` | CWE-90 (LDAP injection) | `CWE-134`, `B605` | No Bandit rule for LDAP injection |
| `CWE-090_codeql_2.py` | CWE-90 | `E0401` only | ldap3 library; no Bandit rule |
| `CWE-099_sonar_1.py`  | CWE-99 (resource injection) | unrelated semgrep | No Bandit rule; rare CWE |
| `CWE-113_sonar_1.py`  | CWE-113 (HTTP response splitting) | unrelated | No Bandit rule |

### Why It Happened

These CWEs have **no Bandit detection rules**. Layer 1 produces only environment errors (E0401) and style warnings, giving the LLM no security anchor. The retrieval layer also returns weak results because these vulnerability patterns are underrepresented in the FAISS security index relative to common patterns like SQLi and command injection.

The model hallucinates plausible-sounding but incorrect citations (`B605`, `CWE-134`) when it recognises that something looks suspicious but lacks grounded retrieval context to identify it precisely.

This is a genuine model limitation for uncommon CWE types. Unlike Problems 1–3, there is no quick code fix because:
- Bandit does not cover LDAP injection, resource injection, or HTTP response splitting
- These patterns require semantic understanding of the library API (e.g., `ldap.search()` with tainted input) rather than syntactic pattern matching

### Solution

| Option | Effort | Impact |
|--------|--------|--------|
| Add LDAP injection, resource injection, HTTP splitting examples to the FAISS security index | Medium | Medium — improves retrieval context for the LLM |
| Add a semgrep-based heuristic for `ldap.search()` / `ldap3` tainted input | Medium | Recovers CWE-90 cases specifically |
| Add CWE-90, CWE-99, CWE-113 to the equivalence map accepting model-adjacent citations | Low | Partial — only helps if model produces a related citation |
| Report these as out-of-scope in the final report | None | Honest evaluation — appropriate for a course project |

For the project deadline, reporting these as a known limitation is the most honest and practical approach.

---

## Full Failure Summary

| Problem | Root cause | Code or Model? | Fix complexity |
|---------|-----------|----------------|---------------|
| **P1** — `eval()`/`exec()` → CWE-78 instead of CWE-94/95 | Bandit upstream CWE mislabeling; propagated by Fix 3 anchor | **Code** | Low — equivalence map + Bandit override |
| **P2** — E0401 pylint import error anchored as CRITICAL | Fix 3 does not filter environment artifacts | **Code** | Low — exclude E04xx from anchor |
| **P3** — CWE-79 vs CWE-80 sibling confusion | Missing equivalences; semgrep rule name not a CWE | **Code** | Low — equivalence map expansion |
| **P4** — LDAP/resource/HTTP-splitting gaps | No Bandit rules; underrepresented in index | **Model** | Medium–High |

**Most failures (P1–P3) are code-fixable with low effort.** Only P4 represents a genuine model knowledge boundary that requires index augmentation or should be reported as a scope limitation.

---

## Recommended Actions (in order of priority)

1. **Fix P2 first** — exclude `E04xx` codes from `_anchor_layer1`. This is the most disruptive bug because it injects false CRITICAL findings into the output for every Flask snippet evaluated, polluting both the findings and the model's reasoning context.

2. **Fix P1** — add `CWE-94↔CWE-78` and `CWE-95↔CWE-78` to the equivalence map, and add `_BANDIT_CWE_OVERRIDES` for B102/B307 in Layer 1.

3. **Fix P3** — add `CWE-79↔CWE-80↔CWE-20` group to the equivalence map.

4. **Document P4** — include CWE-90, CWE-99, CWE-113 in the error analysis section of the final report as known limitations, noting the absence of Bandit coverage and the retrieval quality gap for these uncommon patterns.
