"""
Layer 3 — Model Benchmark.

Runs Qwen2.5, Llama 3.1, and Mistral on three vulnerable Python snippets,
scores each on JSON validity, issue coverage, and citation accuracy,
then prints a summary table and saves results to layer3/benchmark_results.json.

Usage:
    python3 -m layer3.benchmark
"""

import json
from pathlib import Path

from layer1.static_analysis import run_static_analysis
from layer2.retrieval import Retriever
from layer3.llm_runner import MODELS, LLMRunner
from layer3.prompt_builder import build_prompt

# ---------------------------------------------------------------------------
# Test cases — (snippet, list of expected {line, cwe_or_code} dicts)
# ---------------------------------------------------------------------------

TEST_CASES = [
    (
        # Snippet 1: SQL injection
        """\
import sqlite3

def get_user(db, user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
""",
        [{"line": 4, "marker": "CWE-89"}, {"line": 4, "marker": "B608"}],
    ),
    (
        # Snippet 2: OS command injection
        """\
import os

def run_command(cmd):
    os.system(cmd)
""",
        [{"line": 4, "marker": "CWE-78"}, {"line": 4, "marker": "B605"}],
    ),
    (
        # Snippet 3: shell=True subprocess + hardcoded password
        """\
import subprocess

SECRET = "hunter2"

def deploy(host):
    subprocess.call("ssh " + host, shell=True)
""",
        [
            {"line": 3, "marker": "CWE-259"},
            {"line": 3, "marker": "B105"},
            {"line": 6, "marker": "CWE-78"},
            {"line": 6, "marker": "B602"},
        ],
    ),
]


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _score_validity(findings: list[dict]) -> int:
    return 1 if isinstance(findings, list) else 0


def _score_coverage(findings: list[dict], expected: list[dict]) -> int:
    """1 pt per expected issue whose line (±1) appears anywhere in findings."""
    score = 0
    found_lines = {f.get("line") for f in findings if isinstance(f, dict)}
    for exp in expected:
        exp_line = exp["line"]
        if any(abs(fl - exp_line) <= 1 for fl in found_lines if fl is not None):
            score += 1
    return score


def _score_citation(findings: list[dict], expected: list[dict]) -> int:
    """1 pt per expected marker that appears in any finding's citation field."""
    score = 0
    citations = " ".join(
        str(f.get("citation", "")) for f in findings if isinstance(f, dict)
    ).upper()
    for exp in expected:
        if exp["marker"].upper() in citations:
            score += 1
    return score


# ---------------------------------------------------------------------------
# Main benchmark runner
# ---------------------------------------------------------------------------

def run_benchmark(models: list[str] | None = None) -> dict:
    if models is None:
        models = list(MODELS.keys())

    retriever = Retriever()
    results   = {}

    for model_name in models:
        print(f"\n{'='*60}")
        print(f"  Benchmarking: {model_name}")
        print(f"{'='*60}")

        runner = LLMRunner(model_name)
        model_results = []

        for i, (code, expected) in enumerate(TEST_CASES, 1):
            print(f"\n  {'─'*56}")
            print(f"  Snippet {i}/{len(TEST_CASES)}", flush=True)

            # ── Input code ──────────────────────────────────────────
            print(f"\n  [INPUT CODE]")
            for lineno, line in enumerate(code.strip().splitlines(), 1):
                print(f"    {lineno:>2} | {line}")

            l1 = run_static_analysis(code)
            l2 = retriever.query(code, l1)
            prompt = build_prompt(code, l1, l2)

            # ── Layer 1 findings ────────────────────────────────────
            print(f"\n  [LAYER 1 — Static Analysis] ({len(l1)} findings)")
            for f in l1:
                cwe = ", ".join(f.get("cwe_ids") or []) or "—"
                print(f"    Line {f['line']:>2} [{f['severity']:<8}] {f['tool'].upper()} {f['code']}: {f['message'][:60]}  CWE:{cwe}")

            # ── Layer 2 top retrieval ────────────────────────────────
            print(f"\n  [LAYER 2 — Retrieved Chunks] (top 1 per index)")
            for idx_name in ("security", "style", "bug_pattern"):
                hits = l2.get(idx_name, [])
                if hits:
                    top = hits[0]
                    print(f"    {idx_name:<12} score={top['score']:.4f}  {top.get('citation','?')}  \"{top.get('title','')}\"")

            # ── LLM output ──────────────────────────────────────────
            raw      = runner.generate(prompt)
            findings = runner.parse_json(raw)

            print(f"\n  [LLM RAW OUTPUT] (first 400 chars)")
            print(f"    {raw[:400].replace(chr(10), chr(10)+'    ')}")

            print(f"\n  [PARSED FINDINGS] ({len(findings)} items)")
            for f in findings:
                print(f"    Line {f.get('line','?'):>2} [{f.get('severity','?'):<8}] citation={f.get('citation','?')}")
                print(f"           {str(f.get('explanation',''))[:80]}")

            validity = _score_validity(findings)
            coverage = _score_coverage(findings, expected)
            citation = _score_citation(findings, expected)

            print(f"\n  [SCORE]  validity={validity}  coverage={coverage}/{len(expected)}  citation={citation}/{len(expected)}")

            model_results.append({
                "snippet":  i,
                "validity": validity,
                "coverage": coverage,
                "citation": citation,
                "total":    validity + coverage + citation,
                "raw_output": raw[:500],
                "parsed_findings": findings,
            })

        results[model_name] = model_results

    return results


def print_table(results: dict):
    max_coverage = sum(len(exp) for _, exp in TEST_CASES)
    max_citation = max_coverage

    print(f"\n{'─'*70}")
    print(f"  {'Model':<12} | {'Validity':>8} | {'Coverage':>10} | {'Citation':>10} | {'Total':>6}")
    print(f"{'─'*70}")
    totals = {}
    for model, runs in results.items():
        v = sum(r["validity"] for r in runs)
        c = sum(r["coverage"] for r in runs)
        ci = sum(r["citation"] for r in runs)
        t = v + c + ci
        totals[model] = t
        print(f"  {model:<12} | {v:>5}/{len(TEST_CASES)}  | {c:>6}/{max_coverage}     | {ci:>6}/{max_citation}     | {t:>6}")
    print(f"{'─'*70}")
    best = max(totals, key=totals.get)
    print(f"\n  Recommended model: {best}  (score {totals[best]})")


def main():
    results = run_benchmark()

    out_path = Path(__file__).parent / "benchmark_results.json"
    out_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"\n  Full results saved to {out_path}")

    print_table(results)


if __name__ == "__main__":
    main()
