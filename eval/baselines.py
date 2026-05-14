"""
Baseline runners for the evaluation harness.

B1 — Zero-shot LLM: calls the LLM with only the code and a minimal security prompt.
     No Layer 1 static analysis, no Layer 2 RAG retrieval.

B2 — Static analysis only: runs Bandit + pylint (Layer 1) and maps output to
     the standard findings schema. No LLM involved.

No-Bandit (ablation) — RAG-only pipeline: skips Layer 1 entirely.
     code → bi-encoder (raw code only) → cross-encoder → top-5 chunks → Qwen → findings.
     No Bandit augmentation of retrieval query; no Layer 1 anchor in the output.
"""

_ZERO_SHOT_SYSTEM = (
    "You are a Python security code reviewer. "
    "Analyze the code for security vulnerabilities and return ONLY a valid JSON array. "
    "Each object must have exactly these keys: "
    '"line" (int), "severity" ("CRITICAL"/"WARNING"/"INFO"), '
    '"explanation" (str), "fix_suggestion" (str), "citation" (str — e.g. "CWE-89", "B608", or "heuristic"). '
    "If no issues are found, return []."
)

_ZERO_SHOT_TEMPLATE = "{system}\n\n```python\n{code}\n```"


def run_b1(code: str, runner) -> list[dict]:
    """B1: zero-shot LLM with no retrieval or static-analysis context.

    Args:
        code: Python source code to review.
        runner: An LLMRunner instance (from layer3.llm_runner).

    Returns:
        Parsed findings list in the standard schema.
    """
    prompt = _ZERO_SHOT_TEMPLATE.format(system=_ZERO_SHOT_SYSTEM, code=code)
    raw = runner.generate(prompt, max_new_tokens=1024)
    return runner.parse_json(raw)


def run_no_bandit(code: str, runner) -> list[dict]:
    """Ablation — RAG without Bandit: code → bi-encoder (raw code) → cross-encoder → Qwen.

    Differences from the full PythonGuard system:
    - Layer 1 (Bandit + pylint + heuristics) is NOT run.
    - Retrieval query = raw code only (no Bandit message augmentation).
    - LLM prompt has no Layer 1 findings section.
    - Layer 1 anchor is NOT applied to the output.

    This isolates the contribution of Bandit to the pipeline.
    """
    from layer2.retrieval import Retriever
    from layer3.prompt_builder import build_prompt
    from layer3.review import _get_retriever

    retriever: Retriever = _get_retriever()
    # Pass empty layer1_findings → sec_query = style_query = bug_query = raw code
    layer2_results = retriever.query(code, [], top_k=5)
    prompt = build_prompt(code, [], layer2_results)
    raw = runner.generate(prompt, max_new_tokens=1024)
    return runner.parse_json(raw)


def run_b2(code: str) -> list[dict]:
    """B2: Layer 1 static analysis only (Bandit + pylint), no LLM.

    Returns findings in the standard schema so they can be scored identically
    to system and B1 output.
    """
    from layer1.static_analysis import run_static_analysis

    findings = []
    for f in run_static_analysis(code):
        # Prefer first CWE ID as citation; fall back to tool code (e.g. B605)
        cwe_ids = f.get("cwe_ids") or []
        citation = cwe_ids[0] if cwe_ids else f.get("code", "heuristic")
        findings.append(
            {
                "line": f["line"],
                "severity": f["severity"],
                "explanation": f["message"],
                "fix_suggestion": "",
                "citation": citation,
            }
        )
    return findings
