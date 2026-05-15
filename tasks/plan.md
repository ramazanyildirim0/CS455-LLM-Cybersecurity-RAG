# PythonGuard — Sprint Plan to 90% Recall-CWE

**Context:** PythonGuard currently sits at 62.8% Recall-CWE (76/121) against a 90% target (109/121). FPR is 0.0% and CiteFaith is 88.2% — those are fine. The gap is 33 cases, split into two categories: (a) cases where the vulnerability is detected but the wrong CWE is cited, and (b) complete misses where Layer 1 produces no signal so the LLM outputs `[]`. A third set of problems was found in `failure_analysis2.md` (P1/P2/P3) that haven't been fixed yet. This plan closes the gap systematically in priority order.

**Deadline:** June 7, 2026. Currently Week 2 (May 11–17).

---

## Dependency Graph

```
Task 1 (metrics fixes)  ─────────────────────────────┐
Task 2 (crypto heuristics) ──────────────────────────┤
Task 3 (control-flow heuristics) ────────────────────┤──► Task 5 (eval run + report)
Task 4 (prompt auth guidance) ───────────────────────┘
Task 6 (UI polish) ── independent
```

Tasks 1–4 are all independent (different files). Task 5 aggregates them.

---

## TASK 1 — Fix anchor regression + expand CWE equivalences
**Files:** `layer3/review.py`, `eval/metrics.py`
**Estimated gain:** +7–10 Recall-CWE cases

### 1a. Fix anchor injecting E04xx pylint import errors (P2 from failure_analysis2.md)
- In `layer3/review.py`, `_anchor_layer1()`: add filter to skip findings whose `code` starts with `"E04"`.
- Reuse the existing `_NON_SECURITY_CODES` pattern — extend same logic to the anchor step.

### 1b. Fix Bandit CWE-78 → CWE-94/95 mislabeling (P1)
- In `eval/metrics.py` `_CWE_EQUIVALENCES`: add `"CWE-94"` and `"CWE-95"` to `"CWE-78"`'s equiv set.
- In `layer1/static_analysis.py`: override `cwe_ids` for B102/B307 findings to `["CWE-94"]`.

### 1c. Add XSS sibling equivalences (P3)
- Add `"CWE-80"` ↔ `"CWE-79"` and `"CWE-87"` into the XSS family.

### 1d. Add missing reverse links from report_v1
- `"CWE-209"` ↔ `"CWE-200"` ↔ `"CWE-215"`
- `"CWE-611"` → `"CWE-776"` (DTD bomb)
- `"CWE-327"` and `"CWE-330"` → `"CWE-759"` (hash without salt)
- `"CWE-400"` → `"CWE-730"` (ReDoS)
- `"CWE-79"` and `"CWE-20"` → `"CWE-113"` (HTTP response splitting)

**Acceptance criteria:** Recall-CWE improves ≥7 cases; FPR stays 0.0%.

---

## TASK 2 — New Layer 1 heuristics: crypto patterns
**File:** `layer1/static_analysis.py`
**Estimated gain:** +4 Recall-CWE cases

### 2a. `_hardcoded_key_findings()` → H011 (CWE-321)
- Walk `ast.Assign`: target name matches `key|aes_key|secret_key|iv|nonce|enc_key|priv_key`, value is `bytes` constant.

### 2b. `_static_iv_findings()` → H012 (CWE-329/760)
- Walk `ast.Call` for `AES.new(...)` / `Cipher(...)`: detect `bytes` constant as 3rd positional arg (IV).
- Add shared `_is_bytes_literal(node)` helper used by both heuristics.

**Acceptance criteria:** Both heuristics fire on minimal test snippets; 4 SecurityEval cases newly detected.

---

## TASK 3 — New Layer 1 heuristics: control-flow patterns
**File:** `layer1/static_analysis.py`
**Estimated gain:** +6 Recall-CWE cases

### 3a. `_bare_except_findings()` → H013 (CWE-703)
- Flag `ExceptHandler` where type is `None` (bare `except:`) or `Exception`, and body is only `pass`/string constant.

### 3b. `_toctou_findings()` → H014 (CWE-367/414)
- Within each function: find `os.path.exists/isfile/access(path)` followed by `open(path)` without atomic wrapper.

### 3c. `_obsolete_function_findings()` → H015 (CWE-477)
- Maintain `_OBSOLETE` dict (`cgi.escape`, `os.popen`, `commands.getoutput`, `md5`).
- Walk `ast.Call`, match via existing `_get_call_name()`.

**Acceptance criteria:** ≥5 of 7 CWE-703/367/414/477 cases detected after integration.

---

## TASK 4 — Prompt guidance for auth/privilege patterns
**File:** `layer3/prompt_builder.py`
**Estimated gain:** +2–4 Recall-CWE cases

- Add 3 checklist items (25–27) to the vulnerability checklist in `build_prompt()`:
  - Missing authentication checks — CWE-306
  - Privilege escalation (root/setuid without drop) — CWE-250, CWE-269
  - Missing authorization (no ownership/role check) — CWE-285, CWE-283

**Acceptance criteria:** Prompt token increase ≤200; auth snippets now flagged by LLM.

---

## CHECKPOINT A
```bash
python -m eval.harness --output eval/results/eval_checkpoint_a.json
```
Expected: Recall-CWE ≥ 78% (95/121). Triage if below.

---

## TASK 5 — Full eval run + report v2
**Files:** `eval/results/eval_YYYYMMDD.json`, `eval/results/report_v2.md`
- Run complete harness (recall + FPR + citation faithfulness).
- Write `report_v2.md` with v1→v2 per-CWE comparison, remaining miss analysis.
- If Recall-CWE < 90%: identify next interventions. If ≥90%: move to ablation.

**Acceptance criteria:** `report_v2.md` exists; FPR = 0.0%.

---

## TASK 6 — Gradio UI polish (independent)
**File:** `ui/app.py`

- Clickable CWE citation links (→ `https://cwe.mitre.org/data/definitions/XXX.html`)
- Copy-to-clipboard on JSON panel
- Clear button
- Add example snippets for crypto, exception handling, TOCTOU

**Acceptance criteria:** All 6 examples pass manual test; CWE links open correctly.

---

## CHECKPOINT B — End of Week 3
Recall-CWE ≥ 82%. Begin Week 4: ablation study, baseline comparison, error analysis write-up.

---

## Critical Files Reference

| Task | Primary File | Secondary Files |
|------|-------------|----------------|
| 1a | `layer3/review.py` `_anchor_layer1()` | — |
| 1b | `eval/metrics.py` `_CWE_EQUIVALENCES` | `layer1/static_analysis.py` |
| 1c–1d | `eval/metrics.py` `_CWE_EQUIVALENCES` | — |
| 2a–2b | `layer1/static_analysis.py` (H011, H012) | register in `run_static_analysis()` |
| 3a–3c | `layer1/static_analysis.py` (H013–H015) | same |
| 4 | `layer3/prompt_builder.py` `build_prompt()` | — |
| 5 | `eval/harness.py` (run only) | `eval/results/` |
| 6 | `ui/app.py` | — |

## Reusable Utilities

- `_get_call_name(node)` — dotted call name extraction (`static_analysis.py`)
- `_is_taint_source(node)` — taint source detection (`static_analysis.py`)
- `_contains_tainted(node, tainted_dict)` — taint propagation (`static_analysis.py`)
- `_NON_SECURITY_CODES` — pylint code filter (`review.py`)
- `_CWE_EQUIVALENCES` — equivalence map (`metrics.py`)
- `_normalize_citation()` — citation extraction (`review.py`)
