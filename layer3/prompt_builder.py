"""
Layer 3 — Prompt Builder.

Assembles code + Layer 1 static analysis findings + Layer 2 retrieved chunks
into a single structured prompt string for the LLM.
"""

_SYSTEM = """\
You are a Python security code reviewer. Analyse the code provided and return a JSON array of issues.

Rules:
- Return ONLY valid JSON. No markdown, no explanation outside the JSON array.
- Each item must have exactly these fields:
    "line"           : int   — line number in the input code
    "severity"       : str   — one of "CRITICAL", "WARNING", "INFO"
    "explanation"    : str   — what the issue is and why it is dangerous
    "fix_suggestion" : str   — a concrete code fix or recommendation
    "citation"       : str   — e.g. "CWE-78", "B605", "PEP8:W0611", or "heuristic"
- If there are no issues, return an empty array: []
"""


def _fmt_findings(findings: list[dict]) -> str:
    if not findings:
        return "  (none)\n"
    lines = []
    for f in findings:
        cwe = ", ".join(f.get("cwe_ids") or []) or "—"
        lines.append(
            f"  - Line {f['line']} [{f['severity']}] {f['tool'].upper()} {f['code']}: "
            f"{f['message']}  (CWE: {cwe})"
        )
    return "\n".join(lines) + "\n"


def _fmt_chunks(chunks: list[dict], top_n: int = 3) -> str:
    if not chunks:
        return "  (none)\n"
    lines = []
    for c in chunks[:top_n]:
        citation = c.get("citation") or c.get("chunk_id", "?")
        title    = c.get("title", "")
        preview  = (c.get("text_preview") or "")[:200].replace("\n", " ")
        lines.append(f"  - [{citation}] {title}: {preview}")
    return "\n".join(lines) + "\n"


def _number_lines(code: str) -> str:
    return "\n".join(f"{i+1:>4} | {line}" for i, line in enumerate(code.splitlines()))


def build_prompt(
    code: str,
    layer1_findings: list[dict],
    layer2_results: dict,
) -> str:
    """
    Build the full LLM prompt from code + Layer 1 findings + Layer 2 retrieved chunks.

    layer2_results is the dict returned by Retriever.query():
        {"security": [...], "style": [...], "bug_pattern": [...]}
    """
    sec_chunks  = layer2_results.get("security", [])
    style_chunks = layer2_results.get("style", [])
    bug_chunks  = layer2_results.get("bug_pattern", [])

    prompt = (
        f"{_SYSTEM}\n"
        "## Input Code\n"
        "```python\n"
        f"{_number_lines(code)}\n"
        "```\n\n"
        "## Static Analysis Findings (Bandit + pylint)\n"
        f"{_fmt_findings(layer1_findings)}\n"
        "## Retrieved Security Rules (top 3)\n"
        f"{_fmt_chunks(sec_chunks)}\n"
        "## Retrieved Style Rules (top 3)\n"
        f"{_fmt_chunks(style_chunks)}\n"
        "## Retrieved Bug Patterns (top 3)\n"
        f"{_fmt_chunks(bug_chunks)}\n"
        "Return your JSON array now:"
    )
    return prompt
