"""
Layer 1: Deterministic static analysis via Bandit (security) and pylint (style/logic).

Usage:
    from layer1.static_analysis import run_static_analysis
    findings = run_static_analysis(code_string)

Each finding dict:
    {
        "tool":       "bandit" | "pylint",
        "line":       int,
        "severity":   "CRITICAL" | "WARNING" | "INFO",
        "code":       str,   # e.g. "B608", "W0611"
        "message":    str,
        "cwe_ids":    list[str],   # e.g. ["CWE-89"]  (bandit only; pylint → [])
        "confidence": str | None,  # "HIGH"/"MEDIUM"/"LOW" (bandit) or None (pylint)
    }
"""

import json
import os
import subprocess
import tempfile

# ---------------------------------------------------------------------------
# Severity mappings
# ---------------------------------------------------------------------------

_BANDIT_SEVERITY = {
    "HIGH":   "CRITICAL",
    "MEDIUM": "WARNING",
    "LOW":    "INFO",
}

_PYLINT_SEVERITY = {
    "fatal":      "CRITICAL",
    "error":      "CRITICAL",
    "warning":    "WARNING",
    "convention": "INFO",
    "refactor":   "INFO",
}


# ---------------------------------------------------------------------------
# Tool runners
# ---------------------------------------------------------------------------

def _run_bandit(filepath: str) -> list[dict]:
    try:
        result = subprocess.run(
            ["bandit", "-f", "json", "-q", filepath],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "bandit not found — install it with: pip install bandit"
        )

    raw = result.stdout.strip()
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print(f"[layer1] WARNING: could not parse bandit output: {raw[:200]}")
        return []

    findings = []
    for r in data.get("results", []):
        cwe_raw = r.get("issue_cwe") or {}
        cwe_id  = cwe_raw.get("id")
        cwe_ids = [f"CWE-{cwe_id}"] if cwe_id else []

        findings.append({
            "tool":       "bandit",
            "line":       r.get("line_number", 0),
            "severity":   _BANDIT_SEVERITY.get(r.get("issue_severity", "").upper(), "INFO"),
            "code":       r.get("test_id", ""),
            "message":    r.get("issue_text", ""),
            "cwe_ids":    cwe_ids,
            "confidence": r.get("issue_confidence"),
        })
    return findings


def _run_pylint(filepath: str) -> list[dict]:
    try:
        result = subprocess.run(
            ["pylint", "--output-format=json", "--score=n", filepath],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "pylint not found — install it with: pip install pylint"
        )

    raw = result.stdout.strip()
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print(f"[layer1] WARNING: could not parse pylint output: {raw[:200]}")
        return []

    findings = []
    for r in data:
        findings.append({
            "tool":       "pylint",
            "line":       r.get("line", 0),
            "severity":   _PYLINT_SEVERITY.get(r.get("type", "").lower(), "INFO"),
            "code":       r.get("message-id", ""),
            "message":    r.get("message", ""),
            "cwe_ids":    [],
            "confidence": None,
        })
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_static_analysis(code: str) -> list[dict]:
    """Run Bandit and pylint on *code*, return merged findings sorted by line."""
    tmp = tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False, encoding="utf-8")
    try:
        tmp.write(code)
        tmp.flush()
        tmp.close()

        bandit_findings = _run_bandit(tmp.name)
        pylint_findings = _run_pylint(tmp.name)
    finally:
        os.unlink(tmp.name)

    all_findings = bandit_findings + pylint_findings
    all_findings.sort(key=lambda f: f["line"])
    return all_findings
