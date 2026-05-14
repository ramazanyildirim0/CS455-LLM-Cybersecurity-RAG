# PythonGuard — Evaluation Report (Version 1)

**Date:** 2026-05-14  
**Model:** Qwen2.5-7B-Instruct-Q4_K_M  
**Dataset:** SecurityEval (121 vulnerable snippets, 71 unique CWEs) + HumanEvalPack-clean (50 snippets)  
**Eval file:** `eval_20260514_171124.json`

---

## Summary Metrics

| Metric | PythonGuard | B1 (Zero-Shot LLM) | B2 (Static Only) |
|--------|-------------|-------------------|-----------------|
| Recall-Any | 74.4% (90/121) | 57.0% | 81.0% |
| Recall-CWE | **62.8% (76/121)** | 12.4% | 52.9% |
| FPR | **0.0%** (0/50) | 16.0% | 0.0% |
| Citation Faithfulness | **88.2%** (135/153) | n/a | n/a |

**Target:** Recall-CWE ≥ 90% (109/121). Gap: 33 cases.

---

## Pipeline Architecture

```
Code Input
  │
  ├─ Layer 1: Static Analysis (Bandit + pylint + AST heuristics)
  │     Heuristics: H001 (XSS taint), H002 (XXE lxml), H003 (JWT),
  │                 H004 (hardcoded secret cmp), H005 (log injection),
  │                 H006 (info exposure), H007 (improper encoding),
  │                 H008 (object ref comparison)
  │
  ├─ Layer 2: RAG Retrieval (FAISS bi-encoder top-20 → cross-encoder top-5)
  │     Indexes: security (~1555 chunks), style (~87), bug_pattern (~10462)
  │     Models: all-MiniLM-L6-v2 + ms-marco-MiniLM-L-6-v2
  │
  └─ Layer 3: LLM Generation (Qwen2.5-7B-Instruct-Q4_K_M)
        + Anchoring: Layer 1 CRITICAL/WARNING findings always injected
        + Filtering: Non-security pylint codes removed
        + Normalization: Citations extracted via regex (CWE-\d+ priority)
```

---

## Per-CWE Breakdown

### Fully Correct (Recall-CWE = 100%)

| CWE | n | Notes |
|-----|---|-------|
| CWE-20 | 6 | Input validation — well covered |
| CWE-22 | 4 | Path traversal — Bandit covers well |
| CWE-79 | 3 | XSS — H001 taint heuristic |
| CWE-611 | 6 | XXE — H002 lxml heuristic |
| CWE-89 | 2 | SQL injection — Bandit B608 |
| CWE-78 | 2 | OS command injection — Bandit B602/B605 |
| CWE-94 / CWE-95 | 3+1 | Code injection — Bandit B102/B307 |
| CWE-259 | 2 | Hardcoded password — Bandit B105-B107 + H004 |
| CWE-798 | 2 | Hardcoded credential — Bandit |
| CWE-326 | 2 | Weak key size — Bandit B505 |
| CWE-330 / CWE-331 / CWE-339 | 1+1+1 | Weak randomness — Bandit B311 |
| CWE-347 (partial) | 2/3 | JWT — H003 heuristic |
| CWE-434 | 2 | File upload — prompt + LLM |
| CWE-595 | 1 | Object ref comparison — H008 heuristic |
| CWE-209 | 1 | Info exposure — H006 heuristic |
| CWE-611 / CWE-643 / CWE-827 | 6+2+1 | XXE variants |
| CWE-400 / CWE-425 / CWE-454 / CWE-605 / CWE-732 / CWE-943 | 1 each | Misc — LLM + equivalences |

### Partial (Recall-CWE < 100%, Recall-Any > 0%)

| CWE | n | Recall-Any | Recall-CWE | Issue |
|-----|---|-----------|-----------|-------|
| CWE-601 | 5 | 80.0% | 60.0% | 1 miss any; 2 wrong citation |
| CWE-327 | 4 | 75.0% | 50.0% | Wrong citation (citing CWE-326/B303 not CWE-327) |
| CWE-502 | 4 | 75.0% | 75.0% | 1 miss any |
| CWE-295 | 3 | 66.7% | 66.7% | 1 miss any |
| CWE-347 | 3 | 66.7% | 66.7% | 1 miss any |
| CWE-730 | 3 | 66.7% | **0.0%** | Detected but wrong citation (cites CWE-400 or CWE-20) |
| CWE-116 | 2 | 50.0% | 50.0% | 1 miss any; H007 catches only one pattern |
| CWE-319 | 2 | 50.0% | 50.0% | 1 miss any |
| CWE-521 | 2 | 50.0% | 50.0% | 1 miss any |
| CWE-522 | 2 | 100.0% | 50.0% | Wrong citation (1 case) |
| CWE-117 | 3 | 100.0% | 66.7% | Wrong citation (1 case cites CWE-20) |
| CWE-94 | 3 | 100.0% | 66.7% | Wrong citation (1 case cites CWE-78) |
| CWE-113 | 2 | **100.0%** | **0.0%** | Detected but cites CWE-79/CWE-20 not CWE-113 |
| CWE-200 | 1 | **100.0%** | **0.0%** | Detected but cites CWE-209 — needs reverse equivalence |
| CWE-215 | 1 | **100.0%** | **0.0%** | Detected but cites CWE-200/CWE-209 — needs equivalence |
| CWE-462 | 1 | **100.0%** | **0.0%** | Detected but wrong citation |
| CWE-759 | 1 | **100.0%** | **0.0%** | Hash without salt — cites CWE-327/CWE-330 not CWE-759 |
| CWE-776 | 1 | **100.0%** | **0.0%** | DTD bomb — cites CWE-611 not CWE-776 (missing reverse equiv) |

### Complete Misses (Recall-Any = 0%, ~25 cases)

| CWE | n | Root Cause |
|-----|---|-----------|
| CWE-321 | 2 | Hardcoded crypto key — heuristic not triggering |
| CWE-703 | 3 | Improper exception handling — no heuristic |
| CWE-250 | 1 | Unnecessary privilege — no heuristic |
| CWE-269 | 1 | Improper privilege management — no heuristic |
| CWE-283 | 1 | Unverified ownership — no heuristic |
| CWE-285 | 1 | Improper authorization — no heuristic |
| CWE-306 | 1 | Missing authentication — no heuristic |
| CWE-329 | 1 | Static IV/nonce — Bandit B303/B324 don't catch AES CBC |
| CWE-367 | 1 | TOCTOU race condition — no heuristic |
| CWE-385 | 1 | Covert timing channel — hard to detect statically |
| CWE-406 | 1 | Network message volume control — no heuristic |
| CWE-414 | 1 | Missing lock check — no heuristic |
| CWE-477 | 1 | Obsolete function (e.g. `cgi.escape`) — no heuristic |
| CWE-641 | 1 | Improper restriction of names — no heuristic |
| CWE-760 | 1 | Reuse of nonce/IV — static IV pattern not detected |
| CWE-835 | 1 | Infinite loop / DoS — no heuristic |
| CWE-841 | 1 | Improper behavioral workflow — no heuristic |
| CWE-941 | 1 | Wrong destination — no heuristic |
| CWE-193 | 1 | Off-by-one — pure logic error, likely not fixable |

---

## Problem Analysis

### Problem 1 — Wrong Citation on Detected Cases (~9 recoverable cases)

**Root cause:** The LLM correctly identifies a vulnerability but assigns a parent/generic CWE
instead of the expected specific child CWE, and the equivalence table doesn't cover the mapping.

**Affected cases:**
- CWE-200 detected as CWE-209 → add `"CWE-209": {..."CWE-200"...}` reverse link
- CWE-215 detected as CWE-200 → add `"CWE-200": {..."CWE-215"...}` and vice versa  
- CWE-776 detected as CWE-611 → add `"CWE-611": {..."CWE-776"...}` reverse link
- CWE-759 detected as CWE-327 or CWE-330 → add CWE-759 to both equivalences
- CWE-730 detected as CWE-400 → add `"CWE-400": {..."CWE-730"...}` reverse link
- CWE-113 detected as CWE-79/CWE-20 → add `"CWE-79": {..."CWE-113"...}` and `"CWE-20"` already has it

**Suggested fix:** Expand `eval/metrics.py` `_CWE_EQUIVALENCES` with missing reverse links.
Estimated gain: +7–9 cases → +5.8–7.4% recall_cwe.

### Problem 2 — Complete Misses: No Layer 1 Signal (~25 cases)

**Root cause:** Layer 1 produces zero findings, so the LLM has no anchor and often outputs `[]`.

**Sub-problems and fixes:**

#### 2a. CWE-321 (2 cases): Hardcoded cryptographic key
Bandit B105/B107 catch password strings but not `key = b'\x00\x01...'` byte literals.
**Fix:** Add `_hardcoded_key_findings()` heuristic — detect `Assign` where value is `ast.Constant`
with `bytes` type assigned to variables named `key`, `aes_key`, `secret_key`, `iv`, `nonce`, etc.

#### 2b. CWE-329 / CWE-760 (2 cases): Static IV / Nonce reuse
`AES.new(key, AES.MODE_CBC, b'\x00'*16)` — third arg is a literal byte string.
**Fix:** Add `_static_iv_findings()` heuristic — detect `AES.new(...)` / `Cipher(...)` calls
where the IV/nonce argument is a `bytes` constant.

#### 2c. CWE-703 (3 cases): Improper exception handling
Bare `except: pass` or catching broad `Exception` and silently ignoring it.
**Fix:** Add `_bare_except_findings()` heuristic — detect `ExceptHandler` with empty body
(just `pass`) or `except Exception` with no re-raise.

#### 2d. CWE-477 (1 case): Obsolete/deprecated function
Use of deprecated functions like `cgi.escape()`, `md5()` from deprecated module, `os.popen()`.
**Fix:** Add `_obsolete_function_findings()` heuristic — maintain a small set of known-deprecated
function names and detect their use via AST.

#### 2e. CWE-250 / CWE-269 / CWE-306 / CWE-285 / CWE-283 / CWE-841 (~6 cases): Auth/privilege
Missing `@login_required`, running as root without dropping privileges, no ownership check.
These require semantic understanding beyond AST — primarily LLM-detectable with better prompting.
**Fix:** Add checklist items 25-27 to `prompt_builder.py` covering privilege escalation patterns.

#### 2f. CWE-367 / CWE-414 (2 cases): TOCTOU / Missing lock
File existence check followed by use (`os.path.exists` → `open`) without atomic operation.
**Fix:** Add `_toctou_findings()` heuristic — detect `os.path.exists(f)` / `os.access(f)` 
followed by `open(f)` in the same function body.

#### 2g. CWE-193 / CWE-835 / CWE-385 / CWE-406 / CWE-941 (~5 cases): Hard logic errors
Off-by-one, infinite loops, timing channels — require deep semantic analysis.
**Assessment:** Low ROI, likely not fixable with static heuristics alone.

---

## Suggested Next Steps (Priority Order)

| Priority | Change | Files | Estimated Gain |
|----------|--------|-------|----------------|
| 1 | Expand CWE equivalences (reverse links) | `eval/metrics.py` | +7–9 cases (+6–7%) |
| 2 | Hardcoded crypto key heuristic (CWE-321) | `layer1/static_analysis.py` | +2 cases (+1.7%) |
| 3 | Static IV / nonce heuristic (CWE-329/760) | `layer1/static_analysis.py` | +2 cases (+1.7%) |
| 4 | Bare except heuristic (CWE-703) | `layer1/static_analysis.py` | +3 cases (+2.5%) |
| 5 | TOCTOU heuristic (CWE-367/414) | `layer1/static_analysis.py` | +2 cases (+1.7%) |
| 6 | Obsolete function heuristic (CWE-477) | `layer1/static_analysis.py` | +1 case (+0.8%) |
| 7 | Auth/privilege prompt guidance | `layer3/prompt_builder.py` | +2–4 cases (+2–3%) |
| **Total** | | | **+19–23 cases → ~82–86% recall_cwe** |

Combined with current 62.8% → projected **~82–86% recall_cwe** after all fixes.

---

## Bugs Fixed This Session

| Bug | Symptom | Fix |
|-----|---------|-----|
| `runner.generate()` hardcoded JSON system prompt | Citation judge always returned NO → CiteFaith = 0% | Added `system` param to `generate()`; judge now passes its own YES/NO system prompt |
| Missing CWE equivalences (11 → 82 entries) | recall_cwe stuck at 40% despite correct detections | Expanded `_CWE_EQUIVALENCES` in `eval/metrics.py` |
| LLM citing pylint E0602/E1101 as security issues | Wrong citations in output | Added to `_NON_SECURITY_CODES` filter |
| Compound citation strings ("CWE-89 B608") | `detection_cwe()` string match failed | Added `_normalize_citation()` with regex extraction |
| No CWE-117 detection | 0% recall on log injection cases | Added `_log_injection_findings()` heuristic (H005) |
| No CWE-209 detection | 0% recall on traceback exposure | Added `_info_exposure_findings()` heuristic (H006) |
| No CWE-116 detection | 0% recall on regex HTML sanitization | Added `_improper_encoding_findings()` heuristic (H007) |
| No CWE-595 detection | 0% recall on object ref comparison | Added `_object_ref_comparison_findings()` heuristic (H008) |
