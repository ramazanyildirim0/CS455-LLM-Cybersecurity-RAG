# PythonGuard — Task List

> Current: 62.8% Recall-CWE → Target: 90% (109/121). See `tasks/plan.md` for full details.

## TASK 1 — Fix anchor + expand CWE equivalences ✓ DONE
**Files:** `layer3/review.py`, `eval/metrics.py`, `layer1/static_analysis.py`

- [x] 1a. Filter E04xx codes from `_anchor_layer1()` in `layer3/review.py`
- [x] 1b. Add CWE-94/CWE-95 to `"CWE-78"` equiv set in `eval/metrics.py`
- [x] 1b. B102/B307 CWE override already in `layer1/static_analysis.py`
- [x] 1c. Add CWE-83/CWE-87 ↔ CWE-79/80 XSS family in `eval/metrics.py`
- [x] 1d. Reverse links already present from previous session

## TASK 2 — New crypto heuristics (CWE-321, CWE-329, CWE-760) ✓ DONE
**File:** `layer1/static_analysis.py`

- [x] Add `_is_bytes_literal(node)` helper
- [x] 2a. Add `_hardcoded_key_findings()` → H011 (CWE-321)
- [x] 2b. Add `_static_iv_findings()` → H012 (CWE-329/760)
- [x] Register H011, H012 in `run_static_analysis()`
- [x] Smoke-tested — all pass including false-positive checks

## TASK 3 — New control-flow heuristics (CWE-703, CWE-367, CWE-414, CWE-477) ✓ DONE
**File:** `layer1/static_analysis.py`

- [x] 3a. Add `_bare_except_findings()` → H013 (CWE-703)
- [x] 3b. Add `_toctou_findings()` → H014 (CWE-367/414)
- [x] 3c. Add `_obsolete_function_findings()` → H015 (CWE-477)
- [x] Register H013, H014, H015 in `run_static_analysis()`
- [x] Smoke-tested — all pass including false-positive checks

## TASK 4 — Prompt auth/privilege + new-pattern guidance ✓ DONE
**File:** `layer3/prompt_builder.py`

- [x] Add checklist item 25: CWE-703 bare except
- [x] Add checklist item 26: CWE-367/414 TOCTOU
- [x] Add checklist item 27: CWE-477 obsolete functions
- [x] Add checklist item 28: CWE-285/283 missing authorization

## CHECKPOINT A
- [ ] Run: `python -m eval.harness --output eval/results/eval_checkpoint_a.json`
- [ ] Verify Recall-CWE ≥ 78% (95/121); FPR = 0.0%

## TASK 5 — Full eval run + report v2
**Files:** `eval/results/`, `eval/results/report_v2.md`

- [ ] Run full harness (recall + FPR + citation faithfulness)
- [ ] Write `report_v2.md` with v1→v2 per-CWE comparison
- [ ] Document remaining misses and classify fixable/hard
- [ ] Update memory with new metrics

## TASK 6 — Gradio UI polish (independent)
**File:** `ui/app.py`

- [ ] Add clickable CWE links → `https://cwe.mitre.org/data/definitions/XXX.html`
- [ ] Add copy-to-clipboard on JSON panel
- [ ] Add Clear button
- [ ] Add example snippets: crypto key, bare except, TOCTOU
- [ ] Manual test all examples; verify CWE links open

## CHECKPOINT B
- [ ] Recall-CWE ≥ 82% confirmed
- [ ] Begin Week 4: ablation study (with/without Layer 1 anchor), baseline finalization
