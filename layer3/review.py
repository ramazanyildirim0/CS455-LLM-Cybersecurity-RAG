"""
Layer 3 — End-to-end review pipeline.

Ties together Layer 1 (static analysis), Layer 2 (RAG retrieval),
and Layer 3 (LLM generation) into a single review() call.

Usage:
    from layer3.review import review
    findings = review(code, model_name="qwen2.5")
"""

import re

from layer1.static_analysis import run_static_analysis
from layer2.retrieval import Retriever
from layer3.llm_runner import LLMRunner
from layer3.prompt_builder import build_prompt

_ANCHOR_SEVERITIES = {"CRITICAL", "WARNING"}

# Pylint codes that are NOT security issues — exclude from anchoring and filter
# from LLM prompt so the model doesn't echo them back as false findings.
_NON_SECURITY_CODES = {
    "E0401",  # Unable to import — library absent in test env, not a vulnerability
    "E0402",  # Bad import order — not security-relevant
    "E0602",  # Undefined variable — runtime error, not a security issue
    "E1101",  # Module has no member
    "E1111",  # Assigning result of a function call that returns None
    "E1121",  # Too many positional arguments
    "C0114",  # Missing module docstring
    "C0115",  # Missing class docstring
    "C0116",  # Missing function docstring
    "C0103",  # Naming convention
    "C0301",  # Line too long
    "C0304",  # Final newline missing
    "C0209",  # Use f-string
    "R1732",  # Consider using 'with'
    "W1514",  # Using open without explicit encoding
    "W0621",  # Redefining name from outer scope
    "W0611",  # Unused import
}

# Generic fix hints keyed by Bandit code or CWE, used when the LLM missed a finding
_FIX_HINTS: dict[str, str] = {
    "B608":  "Use parameterized queries or an ORM instead of string formatting.",
    "B605":  "Avoid shell=True; pass arguments as a list to subprocess.",
    "B602":  "Pass command as a list to subprocess and remove shell=True.",
    "B307":  "Replace eval() with ast.literal_eval() or a safe parser.",
    "B102":  "Remove exec(); use importlib or a safer alternative.",
    "B301":  "Use json, msgpack, or another safe serialization format instead of pickle.",
    "B403":  "Use json, msgpack, or another safe serialization format instead of pickle.",
    "B506":  "Replace yaml.load() with yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader).",
    "B105":  "Store credentials in environment variables or a secrets manager.",
    "B106":  "Store credentials in environment variables or a secrets manager.",
    "B107":  "Store credentials in environment variables or a secrets manager.",
    "B303":  "Use SHA-256 or SHA-3 (hashlib.sha256) instead of MD5/SHA1 for security.",
    "B324":  "Use SHA-256 or SHA-3 (hashlib.sha256) instead of weak hashes.",
    "B311":  "Use secrets.token_bytes() or os.urandom() for cryptographic randomness.",
    "B501":  "Remove verify=False; always verify SSL certificates.",
    "CWE-89":  "Use parameterized queries or an ORM to prevent SQL injection.",
    "CWE-78":  "Avoid shell=True; use subprocess with a list of arguments.",
    "CWE-502": "Replace pickle with json or use hmac-signed data.",
    "CWE-259": "Store secrets in environment variables or a secrets manager.",
    "CWE-22":  "Sanitize file paths with os.path.basename() and validate against an allowed directory.",
    "CWE-327": "Use SHA-256 or SHA-3 for cryptographic hashing.",
    "CWE-330": "Use the secrets module for cryptographically secure random values.",
    "H001":  "Validate and sanitize all request input before passing it to sinks.",
    "H002":  "Use defusedxml or set resolve_entities=False on the lxml parser.",
    "H003":  "Always verify JWT signatures; never use algorithm='none' or verify=False.",
    "H004":  "Store credentials in environment variables or a secrets manager, never in source code.",
    "H005":  "Sanitize user input before logging: strip newlines with input.replace('\\n','').replace('\\r','').",
    "H006":  "Catch exceptions internally and return a generic error message; never expose traceback.format_exc() or str(e) to clients.",
    "H007":  "Replace regex-based HTML filtering with a dedicated library such as bleach or markupsafe.",
    "H008":  "Use `==`/`!=` to compare object values; reserve `is`/`is not` only for None, True, and False.",
    "CWE-611": "Use defusedxml or configure lxml with resolve_entities=False to prevent XXE.",
    "CWE-347": "Always verify JWT signatures with the correct algorithm and never use algorithm='none'.",
}


def _fix_hint(finding: dict) -> str:
    """Return a generic fix suggestion for a Layer 1 finding."""
    code = finding.get("code", "")
    if code in _FIX_HINTS:
        return _FIX_HINTS[code]
    for cwe in finding.get("cwe_ids") or []:
        if cwe in _FIX_HINTS:
            return _FIX_HINTS[cwe]
    return "Review and remediate according to the referenced CWE guidance."


_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_BANDIT_RE = re.compile(r"\bB\d{3}\b")
_HEURISTIC_RE = re.compile(r"\bH\d{3}\b")


def _normalize_citation(citation: str) -> str:
    """Extract the primary citation token from a compound LLM citation string.

    The LLM sometimes emits things like "CWE-89 B608", "B306: CWE-377", or
    "CWE-330/329". This function extracts the most specific first CWE-ID found,
    falling back to Bandit/heuristic codes, then returns the original string.
    All pattern-based — no hardcoded values.
    """
    if not citation:
        return citation
    m = _CWE_RE.search(citation)
    if m:
        return m.group(0).upper()
    m = _BANDIT_RE.search(citation)
    if m:
        return m.group(0).upper()
    m = _HEURISTIC_RE.search(citation)
    if m:
        return m.group(0).upper()
    return citation.strip()


def _filter_for_prompt(layer1_findings: list[dict]) -> list[dict]:
    """Remove non-security pylint codes before building the prompt.

    E0401 and style-only codes confuse the LLM into citing them as security
    findings or using them as wrong citations for real issues.
    """
    return [f for f in layer1_findings if f.get("code") not in _NON_SECURITY_CODES]


def _filter_output(findings: list[dict]) -> list[dict]:
    """Remove non-security findings and normalize citation fields.

    - Drops findings whose citation is a non-security pylint code.
    - Normalizes compound citation strings (e.g. "CWE-89 B608" → "CWE-89").
    """
    out = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        citation = str(f.get("citation", ""))
        if citation in _NON_SECURITY_CODES:
            continue
        f = dict(f)  # don't mutate caller's dict
        f["citation"] = _normalize_citation(citation)
        out.append(f)
    return out


_retriever: Retriever | None = None
_runners: dict[str, LLMRunner] = {}


def _get_retriever() -> Retriever:
    global _retriever
    if _retriever is None:
        _retriever = Retriever()
    return _retriever


def _get_runner(model_name: str) -> LLMRunner:
    if model_name not in _runners:
        _runners[model_name] = LLMRunner(model_name)
    return _runners[model_name]


def _anchor_layer1(llm_findings: list[dict], layer1_findings: list[dict]) -> list[dict]:
    """Ensure every CRITICAL/WARNING Layer 1 security finding appears in the final output.

    If the LLM missed a high-confidence static finding (by ±1 line), inject it
    directly so it is never silently dropped.
    """
    important = [
        f for f in layer1_findings
        if f["severity"] in _ANCHOR_SEVERITIES
        and f.get("code") not in _NON_SECURITY_CODES
    ]
    if not important:
        return llm_findings

    covered = {
        f.get("line")
        for f in llm_findings
        if isinstance(f, dict) and f.get("line") is not None
    }

    anchored = list(llm_findings)
    for f in important:
        if not any(abs(f["line"] - c) <= 1 for c in covered if c is not None):
            cwe_ids = f.get("cwe_ids") or []
            citation = cwe_ids[0] if cwe_ids else f["code"]
            anchored.append({
                "line":           f["line"],
                "severity":       f["severity"],
                "explanation":    f["message"],
                "fix_suggestion": _fix_hint(f),
                "citation":       citation,
            })
            covered.add(f["line"])

    anchored.sort(key=lambda x: x.get("line") or 0)
    return anchored


def review(
    code: str,
    model_name: str = "qwen2.5",
    top_k: int = 5,
    max_new_tokens: int = 1536,
    runner: LLMRunner | None = None,
) -> list[dict]:
    """
    Run the full PythonGuard pipeline on a Python code string.

    Returns a list of finding dicts, each with:
        line, severity, explanation, fix_suggestion, citation

    Pass an already-loaded ``runner`` to avoid reloading the model on every call.
    """
    layer1_findings  = run_static_analysis(code)
    prompt_findings  = _filter_for_prompt(layer1_findings)
    layer2_results   = _get_retriever().query(code, prompt_findings, top_k=top_k)
    prompt           = build_prompt(code, prompt_findings, layer2_results)
    llm              = runner if runner is not None else _get_runner(model_name)
    raw              = llm.generate(prompt, max_new_tokens=max_new_tokens)
    llm_findings     = llm.parse_json(raw)
    filtered         = _filter_output(llm_findings)
    return _anchor_layer1(filtered, layer1_findings)
