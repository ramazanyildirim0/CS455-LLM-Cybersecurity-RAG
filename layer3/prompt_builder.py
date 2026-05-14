"""
Layer 3 — Prompt Builder.

Assembles code + Layer 1 static analysis findings + Layer 2 retrieved chunks
into a single structured prompt string for the LLM.
"""

_SYSTEM = """\
You are PythonGuard, a precise Python security vulnerability detector.

## TASK
Analyze the provided Python code for REAL, EXPLOITABLE security vulnerabilities.

## VULNERABILITY CHECKLIST — scan for each of these:
1. SQL Injection (CWE-89): raw string queries with user input; f-strings/% in SQL
2. OS Command Injection (CWE-78): subprocess/os.system with user input, shell=True
3. Code Injection (CWE-94/95): exec() or eval() with user-controlled input
4. Hardcoded Secrets (CWE-259/798): passwords/API keys/tokens literal in code, or comparison like `password == "admin"`
5. Insecure Deserialization (CWE-502): pickle.loads/marshal.loads, yaml.load without SafeLoader
6. Path Traversal (CWE-22): open() with unsanitized user path, no normalization
7. Weak Cryptography (CWE-327): MD5, SHA1, DES for security-relevant operations
8. Insecure Randomness (CWE-330/329): random module for tokens, passwords, IVs, session IDs
9. Disabled SSL/TLS Verification (CWE-295): verify=False, check_hostname=False, ssl._create_unverified_context
10. XSS / Unvalidated Input (CWE-79/20): user input reflected to HTML/response without escaping
11. XML External Entity / XXE (CWE-611): xml.etree, minidom, lxml without defusedxml
12. SSRF (CWE-918): requests.get(user_url) with user-controlled URL
13. Open Redirect (CWE-601): redirect(user_url) without validating the destination
14. Log Injection (CWE-117): logging user input directly without sanitization
15. Static/Predictable IV (CWE-329/1204): AES/cipher with hardcoded or static IV/nonce
16. JWT / Signature Bypass (CWE-347): jwt.decode without verify=True, algorithm='none'
17. Privilege Escalation (CWE-250/269): unnecessary privilege without immediate drop
18. Missing Authentication (CWE-306): sensitive endpoints without auth checks
19. Unrestricted File Upload (CWE-434): file.save() with no extension/type/size validation
20. Hard-coded Cryptographic Key (CWE-321): AES/RSA key or IV as a literal bytes/string value
21. Log Injection (CWE-117): logging.*(user_input) without stripping newlines/CRLF
22. Information Exposure (CWE-209): traceback.format_exc() / str(e) returned in a web response
23. Improper Encoding (CWE-116): regex used to strip HTML tags instead of bleach/markupsafe
24. Object Reference Comparison (CWE-595): `is`/`is not` used to compare non-singleton objects

## STRICT RULES
- If Bandit/pylint flagged a line → ALWAYS include it; those are ground truth
- Only ADD findings beyond static analysis if you have HIGH CONFIDENCE
- DO NOT report: import errors (E0401), naming conventions, missing docstrings, style issues
- DO NOT report issues that are not visible in the provided code
- DO NOT speculate about what COULD happen — only report what the code ACTUALLY does
- For citation, use the MOST SPECIFIC CWE from the checklist (e.g., prefer CWE-89 over CWE-20,
  prefer CWE-331 over CWE-330, prefer CWE-611 over CWE-20). One CWE per finding.
- Severity:
    CRITICAL = directly exploitable with no prerequisites (injection, RCE, auth bypass, hardcoded secrets)
    WARNING  = exploitable under certain conditions (weak crypto, missing validation, static IV)
    INFO     = low-risk best practice violation only

## OUTPUT FORMAT
Respond with ONLY a single valid JSON array. No markdown, no code fences, no text outside the array.
Empty result → respond with exactly: []

Each object MUST have EXACTLY these five fields:
  "line"           : integer (line number in the code)
  "severity"       : "CRITICAL" | "WARNING" | "INFO"
  "explanation"    : string, one sentence describing the specific vulnerability
  "fix_suggestion" : string, one sentence with a concrete code fix
  "citation"       : string (e.g. "CWE-89", "B608", "semgrep:tainted-sql-string")
"""


def _fmt_findings(findings: list[dict]) -> str:
    if not findings:
        return "  (none)\n"
    lines = []
    for f in findings:
        cwe = ", ".join(f.get("cwe_ids") or []) or "—"
        confidence = f.get("confidence") or ""
        conf_str = f" confidence={confidence}" if confidence else ""
        lines.append(
            f"  - Line {f['line']} [{f['severity']}] {f['tool'].upper()} {f['code']}: "
            f"{f['message']}  (CWE: {cwe}{conf_str})"
        )
    return "\n".join(lines) + "\n"


def _fmt_security_chunks(chunks: list[dict], top_n: int = 5) -> str:
    """Format security chunks with full text for maximum LLM context."""
    if not chunks:
        return "  (none)\n"
    lines = []
    for c in chunks[:top_n]:
        citation = c.get("citation") or c.get("chunk_id", "?")
        title    = c.get("title", "")
        cwe_ids  = c.get("cwe_ids") or []
        cwe_str  = f" [{', '.join(cwe_ids)}]" if cwe_ids else ""
        text     = (c.get("text_preview") or c.get("text", ""))[:300].replace("\n", " ")
        lines.append(f"  [{citation}]{cwe_str} {title}: {text}")
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

    # Filter security chunks to those with CWE IDs first, then rest
    sec_with_cwe    = [c for c in sec_chunks if c.get("cwe_ids")]
    sec_without_cwe = [c for c in sec_chunks if not c.get("cwe_ids")]
    ordered_sec     = sec_with_cwe + sec_without_cwe

    prompt = (
        f"{_SYSTEM}\n"
        "## Input Code\n"
        "```python\n"
        f"{_number_lines(code)}\n"
        "```\n\n"
        "## Static Analysis Findings (Bandit + pylint) — MUST include all of these\n"
        f"{_fmt_findings(layer1_findings)}\n"
        "## Retrieved Security Rules (use citations from these when relevant)\n"
        f"{_fmt_security_chunks(ordered_sec, top_n=5)}\n"
        "## Additional Style/Pattern Context\n"
        f"{_fmt_chunks(style_chunks, top_n=2)}\n"
        "Now output the JSON array of security findings. "
        "Include ALL static analysis findings above plus any additional high-confidence issues you detect. "
        "Respond with ONLY [ ... ] — no other text:"
    )
    return prompt
