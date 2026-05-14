"""
PythonGuard Evaluation Harness.

Measures three metrics against two baselines on pre-saved evaluation datasets:

  Metric                  Dataset
  ─────────────────────── ──────────────────────────────────────────
  Detection Recall        SecurityEval (121 known-vulnerable snippets)
  False Positive Rate     HumanEvalPack canonical_solutions (50 clean)
  Citation Faithfulness   LLM judge on findings from the Recall run

  Baselines:
    B1        — Zero-shot LLM (no retrieval, no static analysis)
    B2        — Layer 1 static analysis only (Bandit + pylint, no LLM)
    No-Bandit — RAG-only ablation: code → bi-encoder → cross-encoder → Qwen (no Bandit)

Usage:
    python3 -m eval.harness [options]

Options:
    --model NAME        LLM model name (default: qwen2.5)
    --n-security N      SecurityEval cases to run (default: all 121)
    --n-clean N         Clean-code cases for FPR (default: all 50)
    --skip-b1           Skip B1 baseline
    --skip-b2           Skip B2 baseline
    --ablation          Also run the No-Bandit ablation pipeline
    --skip-judge        Skip LLM citation faithfulness judge
    --resume FILE       Resume from a progress JSONL file
    --out DIR           Output directory (default: eval/results)
"""

import argparse
import json
import time
from datetime import datetime
from pathlib import Path

from tqdm import tqdm

from eval.baselines import run_b1, run_b2, run_no_bandit
from eval.citation_judge import judge_findings
from eval.datasets import load_humanevalpack_clean, load_security_eval
from eval.metrics import (
    aggregate_faithfulness,
    aggregate_fpr,
    aggregate_recall,
    detection_any,
    detection_cwe,
    false_positive,
    per_cwe_breakdown,
)
from layer3.llm_runner import LLMRunner
from layer3.review import review


# ─────────────────────────────────────────────────────────────────────────────
# Progress persistence (for resumability)
# ─────────────────────────────────────────────────────────────────────────────

def _load_progress(path: Path) -> dict[str, dict]:
    """Load already-processed records keyed by task_id."""
    done: dict[str, dict] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip():
                rec = json.loads(line)
                done[rec["task_id"]] = rec
    return done


def _append_progress(path: Path, record: dict):
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# Per-record runners
# ─────────────────────────────────────────────────────────────────────────────

def _run_recall_record(
    record: dict,
    model_name: str,
    runner: LLMRunner,
    run_baseline_b1: bool,
    run_baseline_b2: bool,
    run_ablation: bool,
) -> dict:
    """Run all systems on one SecurityEval vulnerable snippet."""
    code = record["code"]
    cwe = record["cwe"]

    t0 = time.time()
    findings_system = review(code, model_name=model_name, runner=runner)
    t_system = time.time() - t0

    findings_b1        = run_b1(code, runner)   if run_baseline_b1 else []
    findings_b2        = run_b2(code)            if run_baseline_b2 else []
    findings_no_bandit = run_no_bandit(code, runner) if run_ablation else []

    return {
        "task_id": record["task_id"],
        "phase": "recall",
        "cwe": cwe,
        "system": {
            "findings": findings_system,
            "detected_any": detection_any(findings_system),
            "detected_cwe": detection_cwe(findings_system, cwe),
            "elapsed_s": round(t_system, 2),
        },
        "b1": {
            "findings": findings_b1,
            "detected_any": detection_any(findings_b1),
            "detected_cwe": detection_cwe(findings_b1, cwe),
        } if run_baseline_b1 else None,
        "b2": {
            "findings": findings_b2,
            "detected_any": detection_any(findings_b2),
            "detected_cwe": detection_cwe(findings_b2, cwe),
        } if run_baseline_b2 else None,
        "no_bandit": {
            "findings": findings_no_bandit,
            "detected_any": detection_any(findings_no_bandit),
            "detected_cwe": detection_cwe(findings_no_bandit, cwe),
        } if run_ablation else None,
    }


def _run_fpr_record(
    record: dict,
    model_name: str,
    runner: LLMRunner,
    run_baseline_b1: bool,
    run_baseline_b2: bool,
    run_ablation: bool,
) -> dict:
    """Run all systems on one clean HumanEvalPack snippet."""
    code = record["code"]

    findings_system    = review(code, model_name=model_name, runner=runner)
    findings_b1        = run_b1(code, runner)        if run_baseline_b1 else []
    findings_b2        = run_b2(code)                if run_baseline_b2 else []
    findings_no_bandit = run_no_bandit(code, runner) if run_ablation    else []

    return {
        "task_id": record["task_id"],
        "phase": "fpr",
        "system": {
            "findings": findings_system,
            "false_positive": false_positive(findings_system),
        },
        "b1": {
            "findings": findings_b1,
            "false_positive": false_positive(findings_b1),
        } if run_baseline_b1 else None,
        "b2": {
            "findings": findings_b2,
            "false_positive": false_positive(findings_b2),
        } if run_baseline_b2 else None,
        "no_bandit": {
            "findings": findings_no_bandit,
            "false_positive": false_positive(findings_no_bandit),
        } if run_ablation else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main evaluation loop
# ─────────────────────────────────────────────────────────────────────────────

def run_evaluation(
    model_name: str = "qwen2.5",
    n_security: int | None = None,
    n_clean: int | None = None,
    run_baseline_b1: bool = True,
    run_baseline_b2: bool = True,
    run_ablation: bool = False,
    run_judge: bool = True,
    resume_path: Path | None = None,
    out_dir: Path = Path("eval/results"),
    verbose: bool = False,
) -> dict:
    # model_name is kept as a local variable and passed explicitly everywhere
    # (LLMRunner has no .model_name attribute)
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    progress_path = resume_path or (out_dir / f"progress_{timestamp}.jsonl")

    done = _load_progress(progress_path) if resume_path else {}
    if done:
        print(f"Resuming from {resume_path} — {len(done)} records already processed.")

    runner = LLMRunner(model_name)

    # ── Load datasets ────────────────────────────────────────────────────────
    security_records = load_security_eval(n=n_security)
    clean_records = load_humanevalpack_clean()
    if n_clean and n_clean < len(clean_records):
        clean_records = clean_records[:n_clean]

    print(f"\nEvaluation config:")
    print(f"  Model        : {model_name}")
    print(f"  Security eval: {len(security_records)} records")
    print(f"  Clean code   : {len(clean_records)} records")
    print(f"  Baselines    : {'B1 ' if run_baseline_b1 else ''}{'B2' if run_baseline_b2 else ''}")
    print(f"  Judge        : {'yes' if run_judge else 'no'}")
    print(f"  Progress file: {progress_path}\n")

    recall_results: list[dict] = []
    fpr_results: list[dict] = []

    # ── Recall loop ──────────────────────────────────────────────────────────
    detected_any_count = 0
    detected_cwe_count = 0
    with tqdm(security_records, desc="Phase 1/3 Recall", unit="snippet", dynamic_ncols=True) as pbar:
        for record in pbar:
            tid = record["task_id"]
            if tid in done:
                recall_results.append(done[tid])
                tqdm.write(f"  {tid} (cached)")
                continue

            result = _run_recall_record(record, model_name, runner, run_baseline_b1, run_baseline_b2, run_ablation)
            recall_results.append(result)
            _append_progress(progress_path, result)

            sys_det = result["system"]["detected_any"]
            cwe_det = result["system"]["detected_cwe"]
            detected_any_count += sys_det
            detected_cwe_count += cwe_det
            elapsed = result["system"]["elapsed_s"]

            tqdm.write(
                f"  {tid}  CWE={record['cwe']}"
                f"  any={'✓' if sys_det else '✗'}"
                f"  cwe={'✓' if cwe_det else '✗'}"
                f"  ({elapsed:.1f}s)"
            )

            if not sys_det or not cwe_det:
                findings = result["system"]["findings"]
                if not findings:
                    tqdm.write("    → model output: [] (no findings produced)")
                else:
                    summary = "  |  ".join(
                        f"L{f.get('line','?')} [{f.get('severity','?')}] {f.get('citation','?')!r}"
                        for f in findings if isinstance(f, dict)
                    )
                    tqdm.write(f"    → model findings: {summary}")
                    if not cwe_det:
                        tqdm.write(f"    → expected citation {record['cwe']!r} not found in above")
                if verbose:
                    code_lines = [
                        f"      {i+1:>2} | {ln}"
                        for i, ln in enumerate(record["code"].splitlines()[:12])
                    ]
                    tqdm.write("    → input code:\n" + "\n".join(code_lines))

            pbar.set_postfix(
                recall_any=f"{detected_any_count}/{len(recall_results)}",
                recall_cwe=f"{detected_cwe_count}/{len(recall_results)}",
            )

    # ── FPR loop ─────────────────────────────────────────────────────────────
    fp_count = 0
    with tqdm(clean_records, desc="Phase 2/3 FPR   ", unit="snippet", dynamic_ncols=True) as pbar:
        for record in pbar:
            tid = record["task_id"]
            if tid in done:
                fpr_results.append(done[tid])
                tqdm.write(f"  {tid} (cached)")
                continue

            result = _run_fpr_record(record, model_name, runner, run_baseline_b1, run_baseline_b2, run_ablation)
            fpr_results.append(result)
            _append_progress(progress_path, result)

            fp = result["system"]["false_positive"]
            fp_count += fp
            tqdm.write(f"  {tid}  fp={'✗ (FP!)' if fp else '✓ clean'}")
            pbar.set_postfix(fp=f"{fp_count}/{len(fpr_results)}")

    # ── Citation faithfulness judge ───────────────────────────────────────────
    all_judge_results: list[bool] = []
    if run_judge:
        # Build a code lookup for the judge
        code_lookup = {r["task_id"]: r["code"] for r in security_records}
        judge_records = [
            r for r in recall_results if r["system"].get("findings")
        ]
        yes_count = 0
        total_findings = 0
        with tqdm(judge_records, desc="Phase 3/3 Judge  ", unit="snippet", dynamic_ncols=True) as pbar:
            for rec_result in pbar:
                task_id = rec_result["task_id"]
                code = code_lookup.get(task_id, "")
                findings = rec_result["system"].get("findings", [])
                verdicts = judge_findings(code, findings, runner)
                all_judge_results.extend(verdicts)
                yes = sum(verdicts)
                yes_count += yes
                total_findings += len(verdicts)
                tqdm.write(f"  {task_id}  {yes}/{len(verdicts)} YES")
                pbar.set_postfix(faithfulness=f"{yes_count}/{total_findings}")

    # ── Aggregate metrics ────────────────────────────────────────────────────
    def _extract_phase(results, phase):
        return [r for r in results if r.get("phase") == phase]

    recall_recs = _extract_phase(recall_results, "recall")
    fpr_recs = _extract_phase(fpr_results, "fpr")

    def _recall_metrics(key):
        if key == "b1" and not run_baseline_b1:
            return None
        if key == "b2" and not run_baseline_b2:
            return None
        if key == "no_bandit" and not run_ablation:
            return None
        subset = [r[key] for r in recall_recs if r.get(key)]
        return aggregate_recall(subset)

    def _fpr_metrics(key):
        if key == "b1" and not run_baseline_b1:
            return None
        if key == "b2" and not run_baseline_b2:
            return None
        if key == "no_bandit" and not run_ablation:
            return None
        subset = [r[key] for r in fpr_recs if r.get(key)]
        return aggregate_fpr(subset)

    results = {
        "config": {
            "model": model_name,
            "n_security": len(security_records),
            "n_clean": len(clean_records),
            "date": timestamp,
            "baselines": {
                "b1": run_baseline_b1,
                "b2": run_baseline_b2,
                "no_bandit": run_ablation,
            },
            "judge": run_judge,
        },
        "recall": {
            "system":    aggregate_recall([r["system"] for r in recall_recs]),
            "b1":        _recall_metrics("b1"),
            "b2":        _recall_metrics("b2"),
            "no_bandit": _recall_metrics("no_bandit"),
        },
        "fpr": {
            "system":    aggregate_fpr([r["system"] for r in fpr_recs]),
            "b1":        _fpr_metrics("b1"),
            "b2":        _fpr_metrics("b2"),
            "no_bandit": _fpr_metrics("no_bandit"),
        },
        "citation_faithfulness": {
            "system": aggregate_faithfulness(all_judge_results),
        },
        "per_cwe": per_cwe_breakdown([
            {**r["system"], "cwe": r["cwe"]} for r in recall_recs
        ]),
        "raw_recall": recall_results,
        "raw_fpr": fpr_results,
    }

    # ── Save results ─────────────────────────────────────────────────────────
    out_path = out_dir / f"eval_{timestamp}.json"
    out_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"\nFull results saved → {out_path}")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

def print_report(results: dict):
    cfg = results["config"]
    recall = results["recall"]
    fpr = results["fpr"]
    faith = results["citation_faithfulness"]

    print()
    print("╔" + "═" * 68 + "╗")
    print(f"║  PythonGuard Evaluation Results — {cfg['date']:<32}║")
    print(f"║  Model: {cfg['model']:<59}║")
    print("╠" + "═" * 68 + "╣")
    print(f"║  {'System':<14} │ {'Recall-Any':>10} │ {'Recall-CWE':>10} │ {'FPR':>8} │ {'CiteFaith':>9} ║")
    print("╠" + "═" * 68 + "╣")

    def _fmt(val):
        return f"{val:.1%}" if val is not None else "  n/a  "

    def _row(label, r_key, f_key, faith_val=None):
        r = recall.get(r_key)
        f = fpr.get(f_key)
        r_any = _fmt(r["recall_any"]) if r else "  n/a  "
        r_cwe = _fmt(r["recall_cwe"]) if r else "  n/a  "
        fpr_v = _fmt(f["fpr"]) if f else "  n/a  "
        faith_s = _fmt(faith_val) if faith_val is not None else "  n/a  "
        print(f"║  {label:<14} │ {r_any:>10} │ {r_cwe:>10} │ {fpr_v:>8} │ {faith_s:>9} ║")

    system_faith = faith.get("system", {}).get("faithfulness")
    _row("PythonGuard", "system", "system", system_faith)
    if recall.get("b1"):
        _row("B1 (zero-shot)", "b1", "b1")
    if recall.get("b2"):
        _row("B2 (static)", "b2", "b2")
    if recall.get("no_bandit"):
        _row("No-Bandit", "no_bandit", "no_bandit")

    print("╠" + "═" * 68 + "╣")
    n_sec = cfg["n_security"]
    n_cln = cfg["n_clean"]
    n_f = faith.get("system", {}).get("n_findings", 0)
    print(f"║  Recall n={n_sec}, FPR n={n_cln}, CiteFaith n_findings={n_f:<26}║")
    print("╚" + "═" * 68 + "╝")

    # Per-CWE breakdown (top 10 most common)
    per_cwe = results.get("per_cwe", {})
    if per_cwe:
        print()
        print("  Per-CWE Recall (system):")
        print(f"  {'CWE':<12} │ {'Recall-Any':>10} │ {'Recall-CWE':>10} │ {'n':>4}")
        print("  " + "─" * 46)
        for cwe, m in sorted(per_cwe.items(), key=lambda x: -x[1]["recall_any"]):
            print(f"  {cwe:<12} │ {m['recall_any']:>10.1%} │ {m['recall_cwe']:>10.1%} │ {m['n']:>4}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PythonGuard evaluation harness")
    parser.add_argument("--model", default="qwen2.5", help="LLM model name (default: qwen2.5)")
    parser.add_argument("--n-security", type=int, default=None,
                        help="Number of SecurityEval cases (default: all 121)")
    parser.add_argument("--n-clean", type=int, default=None,
                        help="Number of clean HumanEvalPack cases (default: all 50)")
    parser.add_argument("--skip-b1", action="store_true", help="Skip B1 baseline")
    parser.add_argument("--skip-b2", action="store_true", help="Skip B2 baseline")
    parser.add_argument("--ablation", action="store_true",
                        help="Also run No-Bandit ablation (RAG-only, no Layer 1)")
    parser.add_argument("--skip-judge", action="store_true", help="Skip citation faithfulness judge")
    parser.add_argument("--resume", type=Path, default=None,
                        help="Resume from a progress JSONL file")
    parser.add_argument("--out", type=Path, default=Path("eval/results"),
                        help="Output directory (default: eval/results)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="On failed detections also print the input code (first 12 lines)")
    args = parser.parse_args()

    results = run_evaluation(
        model_name=args.model,
        n_security=args.n_security,
        n_clean=args.n_clean,
        run_baseline_b1=not args.skip_b1,
        run_baseline_b2=not args.skip_b2,
        run_ablation=args.ablation,
        run_judge=not args.skip_judge,
        resume_path=args.resume,
        out_dir=args.out,
        verbose=args.verbose,
    )
    print_report(results)


if __name__ == "__main__":
    main()
