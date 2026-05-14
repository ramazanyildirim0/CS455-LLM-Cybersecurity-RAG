"""
LLM-as-judge for citation faithfulness evaluation.

For each finding produced by PythonGuard, a second LLM call judges whether
the citation field accurately supports the stated explanation.
"""

_JUDGE_SYSTEM = (
    "You are a security knowledge validator. "
    "Answer questions with exactly YES or NO on the first line, "
    "followed by one sentence of justification. "
    "Do NOT output JSON or any other format."
)

_JUDGE_PROMPT = """\
Code under review:
```python
{code}
```

Finding:
  Line      : {line}
  Severity  : {severity}
  Explanation: {explanation}
  Citation  : {citation}

Does the citation "{citation}" accurately identify and support the security issue \
described in the explanation above?
Answer YES or NO on the first line, then one sentence of justification.
"""

_MAX_CODE_CHARS = 1500


def judge_citation(code: str, finding: dict, runner) -> bool:
    """Ask the LLM judge whether the citation supports the finding.

    Args:
        code: The Python source code that was reviewed.
        finding: A single finding dict with line/severity/explanation/citation.
        runner: An LLMRunner instance (from layer3.llm_runner).

    Returns:
        True if the judge answers YES, False otherwise.
    """
    prompt = _JUDGE_PROMPT.format(
        code=code[:_MAX_CODE_CHARS],
        line=finding.get("line", "?"),
        severity=finding.get("severity", "?"),
        explanation=finding.get("explanation", ""),
        citation=finding.get("citation", ""),
    )
    raw = runner.generate(prompt, max_new_tokens=128, system=_JUDGE_SYSTEM)
    first_line = raw.strip().split("\n")[0].strip().upper()
    return first_line.startswith("YES")


def judge_findings(code: str, findings: list[dict], runner) -> list[bool]:
    """Judge all findings for a single code snippet. Returns a bool per finding."""
    return [judge_citation(code, f, runner) for f in findings if isinstance(f, dict)]
