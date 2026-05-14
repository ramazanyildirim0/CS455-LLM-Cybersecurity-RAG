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

import ast
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

# Bandit maps exec() (B102) and eval() (B307) to CWE-78 (OS Command Injection)
# upstream. The correct CWEs are CWE-94 (Code Injection) and CWE-95 (Eval
# Injection). These overrides fix the citation before it reaches the LLM anchor.
_BANDIT_CWE_OVERRIDES: dict[str, list[str]] = {
    "B102": ["CWE-94"],  # exec → Code Injection
    "B307": ["CWE-95"],  # eval → Eval Injection
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
        # Drop import-check findings: Bandit fires these just because a module
        # was imported, regardless of how it's used. Bandit itself categorises
        # them under "blacklist_imports" in the more_info URL. Real findings
        # ("blacklist_calls", "plugins") point to an actual dangerous usage.
        if "blacklist_imports" in r.get("more_info", ""):
            continue

        test_id = r.get("test_id", "")
        cwe_raw = r.get("issue_cwe") or {}
        cwe_id  = cwe_raw.get("id")
        cwe_ids = [f"CWE-{cwe_id}"] if cwe_id else []
        if test_id in _BANDIT_CWE_OVERRIDES:
            cwe_ids = _BANDIT_CWE_OVERRIDES[test_id]

        findings.append({
            "tool":       "bandit",
            "line":       r.get("line_number", 0),
            "severity":   _BANDIT_SEVERITY.get(r.get("issue_severity", "").upper(), "INFO"),
            "code":       test_id,
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

    # Pylint is a general code-quality tool. Only "error" and "fatal" message types
    # indicate real code defects (undefined names, wrong types, import failures).
    # "warning", "convention", and "refactor" are quality/style concerns, not
    # security vulnerabilities.
    _SECURITY_TYPES = {"fatal", "error"}

    findings = []
    for r in data:
        if r.get("type", "").lower() not in _SECURITY_TYPES:
            continue
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
# Flask/Django input validation taint heuristic
# ---------------------------------------------------------------------------

# Attributes on Flask's `request` object that carry user-controlled data
_REQUEST_SOURCES = {"args", "form", "json", "data", "values", "files", "cookies", "headers",
                    "GET", "POST", "body", "META", "FILES"}  # Django equivalents

# Function names whose arguments should not receive unvalidated request data
_RESPONSE_SINKS = {
    "make_response", "Response", "render_template_string",
    "send_file", "send_from_directory", "redirect",
    "jsonify", "open", "render_template",
    "HttpResponseRedirect",  # Django
    "execute", "cursor.execute",  # DB sinks
}


def _is_request_attr(node: ast.expr) -> bool:
    """True for request.args, request.form, request.json, etc."""
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "request"
        and node.attr in _REQUEST_SOURCES
    )


def _is_request_subscript(node: ast.expr) -> bool:
    """True for request.args['key'], request.form['field'], etc."""
    return (
        isinstance(node, ast.Subscript)
        and _is_request_attr(node.value)
    )


def _is_request_call(node: ast.expr) -> bool:
    """True for request.args.get(...), request.form.get(...), etc."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and _is_request_attr(node.func.value)
    )


def _is_taint_source(node: ast.expr) -> bool:
    """True if node is any direct request data access."""
    return _is_request_attr(node) or _is_request_call(node) or _is_request_subscript(node)


def _get_call_name(node: ast.expr) -> str:
    """Return the bare function name from a Call node, or ''."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _contains_tainted(node: ast.expr, tainted: dict[str, int]) -> bool:
    """True if any sub-expression of *node* contains a tainted variable or request attr."""
    for child in ast.walk(node):
        if _is_taint_source(child):
            return True
        if isinstance(child, ast.Name) and child.id in tainted:
            return True
    return False


def _flask_taint_findings(code: str) -> list[dict]:
    """AST-based taint check: unvalidated request data flowing into response sinks."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    # Pass 1 — collect variables that hold request-sourced values: {name: line}
    tainted: dict[str, int] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value if isinstance(node, ast.Assign) else getattr(node, "value", None)
        if value is None:
            continue
        if _is_taint_source(value):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name):
                    tainted[t.id] = node.lineno

    findings: list[dict] = []

    # Pass 2 — check sink calls for tainted arguments (direct, via variable, or in BinOp/JoinedStr)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        sink = _get_call_name(node.func)
        if sink not in _RESPONSE_SINKS:
            continue
        for arg in node.args:
            if _contains_tainted(arg, tainted):
                src = "request data"
                findings.append(_taint_finding(node.lineno, src, sink))
                break  # one finding per call site

    # Pass 3 — flag direct return of tainted variables in web-route functions
    for node in ast.walk(tree):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        val = node.value
        if _contains_tainted(val, tainted):
            findings.append(_taint_finding(node.lineno, "request data", "return"))

    return findings


def _taint_finding(line: int, source: str, sink: str) -> dict:
    return {
        "tool":       "heuristic",
        "line":       line,
        "severity":   "WARNING",
        "code":       "H001",
        "message":    (
            f"Unvalidated request input ({source!r}) flows into {sink}() "
            "without sanitization or type checking — potential injection or data exposure."
        ),
        "cwe_ids":    ["CWE-20"],
        "confidence": "MEDIUM",
    }


# ---------------------------------------------------------------------------
# Additional AST heuristics for patterns Bandit misses
# ---------------------------------------------------------------------------

def _lxml_xxe_findings(code: str) -> list[dict]:
    """Detect lxml XXE: etree.parse/fromstring/XMLParser without resolve_entities=False."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    # Check if lxml is imported
    has_lxml = any(
        (isinstance(n, ast.Import) and any("lxml" in a.name for a in n.names)) or
        (isinstance(n, ast.ImportFrom) and n.module and "lxml" in n.module)
        for n in ast.walk(tree)
    )
    if not has_lxml:
        return []

    findings: list[dict] = []
    _XXE_CALLS = {"parse", "fromstring", "XMLParser", "XMLSchema", "XSLT"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _get_call_name(node.func)
        if name not in _XXE_CALLS:
            continue
        # Check if resolve_entities=False is passed as keyword
        keywords = {kw.arg: kw for kw in node.keywords}
        re_kw = keywords.get("resolve_entities")
        if re_kw is not None:
            # resolve_entities is set — check if it's False
            val = re_kw.value
            if isinstance(val, ast.Constant) and val.value is False:
                continue  # safe
        findings.append({
            "tool":       "heuristic",
            "line":       node.lineno,
            "severity":   "WARNING",
            "code":       "H002",
            "message":    (
                f"lxml.{name}() used without resolve_entities=False — "
                "vulnerable to XML External Entity (XXE) injection."
            ),
            "cwe_ids":    ["CWE-611"],
            "confidence": "HIGH",
        })

    return findings


def _jwt_findings(code: str) -> list[dict]:
    """Detect JWT decode without verification (algorithm='none' or options={'verify_signature': False})."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    has_jwt = any(
        (isinstance(n, ast.Import) and any("jwt" in a.name.lower() for a in n.names)) or
        (isinstance(n, ast.ImportFrom) and n.module and "jwt" in n.module.lower())
        for n in ast.walk(tree)
    )
    if not has_jwt:
        return []

    findings: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _get_call_name(node.func)
        if name != "decode":
            continue
        keywords = {kw.arg: kw for kw in node.keywords}

        # algorithms=["none"] or algorithm="none"
        for kw_name in ("algorithms", "algorithm"):
            kw = keywords.get(kw_name)
            if kw is None:
                continue
            val = kw.value
            if isinstance(val, ast.Constant) and str(val.value).lower() == "none":
                findings.append(_jwt_finding(node.lineno, "algorithm='none' disables signature verification"))
            elif isinstance(val, ast.List):
                for elt in val.elts:
                    if isinstance(elt, ast.Constant) and str(elt.value).lower() == "none":
                        findings.append(_jwt_finding(node.lineno, "algorithms=['none'] disables signature verification"))

        # verify=False (PyJWT <2.0 legacy keyword)
        verify_kw = keywords.get("verify")
        if verify_kw and isinstance(verify_kw.value, ast.Constant) and verify_kw.value.value is False:
            findings.append(_jwt_finding(node.lineno, "verify=False disables JWT signature verification"))

        # options={'verify_signature': False} or options={'verify_exp': False}
        options_kw = keywords.get("options")
        if options_kw and isinstance(options_kw.value, ast.Dict):
            d = options_kw.value
            for k, v in zip(d.keys, d.values):
                if (isinstance(k, ast.Constant) and "verify" in str(k.value).lower()
                        and isinstance(v, ast.Constant) and v.value is False):
                    findings.append(_jwt_finding(node.lineno, f"options={{'{k.value}': False}} disables JWT verification"))

    return findings


def _jwt_finding(line: int, reason: str) -> dict:
    return {
        "tool":       "heuristic",
        "line":       line,
        "severity":   "CRITICAL",
        "code":       "H003",
        "message":    f"Insecure JWT decode: {reason}.",
        "cwe_ids":    ["CWE-347"],
        "confidence": "HIGH",
    }


def _log_injection_findings(code: str) -> list[dict]:
    """Detect CWE-117: user-controlled input passed to logging calls without sanitization.

    Patterns detected:
    - logging.*(tainted_var) where tainted_var came from request/input
    - logging.*(string_concat_with_tainted) — BinOp containing tainted variable
    - logging.*(input(...)) — direct user input passed to logging
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    # Build taint set from request sources
    tainted: dict[str, int] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value if isinstance(node, ast.Assign) else getattr(node, "value", None)
        if value is None:
            continue
        if _is_taint_source(value):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name):
                    tainted[t.id] = node.lineno
        # Also mark input() return values as tainted
        if isinstance(value, ast.Call) and _get_call_name(value.func) == "input":
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name):
                    tainted[t.id] = node.lineno

    _LOG_METHODS = {"debug", "info", "warning", "warn", "error", "critical",
                    "exception", "log", "fatal"}
    findings: list[dict] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        method = _get_call_name(node.func)
        if method not in _LOG_METHODS:
            continue
        # Confirm it's a logging.* call (attribute on 'logging' or a logger variable)
        is_logging_call = (
            isinstance(node.func, ast.Attribute)
            and (
                (isinstance(node.func.value, ast.Name) and node.func.value.id == "logging")
                or (isinstance(node.func.value, ast.Name))  # logger.info, log.debug, etc.
            )
        )
        if not is_logging_call:
            continue

        for arg in node.args:
            if _contains_tainted(arg, tainted):
                findings.append({
                    "tool":       "heuristic",
                    "line":       node.lineno,
                    "severity":   "WARNING",
                    "code":       "H005",
                    "message":    (
                        "User-controlled input passed directly to logging call — "
                        "log injection possible via embedded newlines (CWE-117)."
                    ),
                    "cwe_ids":    ["CWE-117"],
                    "confidence": "MEDIUM",
                })
                break  # one finding per call site

    return findings


def _hardcoded_secret_cmp_findings(code: str) -> list[dict]:
    """Detect hardcoded credential comparisons: if password == 'literal'."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    _SECRET_NAMES = {
        "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
        "key", "auth", "credential", "pin", "passphrase",
    }
    findings: list[dict] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        if len(node.ops) != 1 or not isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            continue
        left = node.left
        right = node.comparators[0]
        # Check if one side is a name matching a secret keyword and the other is a string literal
        for var_node, val_node in [(left, right), (right, left)]:
            if (isinstance(var_node, ast.Name)
                    and var_node.id.lower() in _SECRET_NAMES
                    and isinstance(val_node, ast.Constant)
                    and isinstance(val_node.value, str)
                    and val_node.value):
                findings.append({
                    "tool":       "heuristic",
                    "line":       node.lineno,
                    "severity":   "CRITICAL",
                    "code":       "H004",
                    "message":    (
                        f"Hardcoded credential comparison: '{var_node.id}' is compared to a "
                        f"literal string value — never store credentials in source code."
                    ),
                    "cwe_ids":    ["CWE-259"],
                    "confidence": "HIGH",
                })
                break

    return findings


def _info_exposure_findings(code: str) -> list[dict]:
    """Detect CWE-209: exception details (traceback/str(e)) returned in a response handler."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    _TRACEBACK_FUNCS = {"format_exc", "format_exception", "print_exc", "format_tb"}
    findings: list[dict] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        exc_var = node.name  # e.g. "e" in "except Exception as e:"

        for child in ast.walk(node):
            if not isinstance(child, ast.Return):
                continue
            val = child.value
            if val is None:
                continue

            exposed = False
            if isinstance(val, ast.Call):
                func_name = _get_call_name(val.func)
                if func_name in _TRACEBACK_FUNCS:
                    exposed = True
                elif exc_var and func_name in {"str", "repr"} and val.args:
                    arg = val.args[0]
                    if isinstance(arg, ast.Name) and arg.id == exc_var:
                        exposed = True
            elif exc_var and isinstance(val, ast.Name) and val.id == exc_var:
                exposed = True

            if exposed:
                findings.append({
                    "tool":       "heuristic",
                    "line":       child.lineno,
                    "severity":   "WARNING",
                    "code":       "H006",
                    "message":    (
                        "Exception details (traceback or str(e)) returned directly in response — "
                        "exposes internal stack traces to attackers (CWE-209)."
                    ),
                    "cwe_ids":    ["CWE-209"],
                    "confidence": "HIGH",
                })
                break

    return findings


def _improper_encoding_findings(code: str) -> list[dict]:
    """Detect CWE-116: regex used to strip HTML tags instead of proper encoding library."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    _HTML_MARKERS = ("<script", "</script", "<.*>", "<[^>", "<?", "<!-", "</", "<\\w")
    findings: list[dict] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in {"sub", "subn", "search", "match", "findall"}:
            continue
        if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "re"):
            continue
        if not node.args:
            continue
        pattern_arg = node.args[0]
        if not isinstance(pattern_arg, ast.Constant) or not isinstance(pattern_arg.value, str):
            continue
        pat_lower = pattern_arg.value.lower()
        if any(marker in pat_lower for marker in _HTML_MARKERS):
            findings.append({
                "tool":       "heuristic",
                "line":       node.lineno,
                "severity":   "WARNING",
                "code":       "H007",
                "message":    (
                    "Regex used to remove/filter HTML tags — this is insufficient sanitization "
                    "and can be bypassed; use bleach or markupsafe instead (CWE-116)."
                ),
                "cwe_ids":    ["CWE-116"],
                "confidence": "MEDIUM",
            })

    return findings


def _redos_findings(code: str) -> list[dict]:
    """Detect CWE-730: user-controlled string passed as regex pattern to re.* functions."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    tainted: dict[str, int] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value if isinstance(node, ast.Assign) else getattr(node, "value", None)
        if value is None:
            continue
        if _is_taint_source(value) or (
            isinstance(value, ast.Call) and _get_call_name(value.func) == "input"
        ):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name):
                    tainted[t.id] = node.lineno

    _RE_FUNCS = {"search", "match", "fullmatch", "findall", "finditer",
                 "sub", "subn", "compile", "split"}
    findings: list[dict] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Attribute)
                and node.func.attr in _RE_FUNCS
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "re"):
            continue
        if not node.args:
            continue
        if _contains_tainted(node.args[0], tainted):
            findings.append({
                "tool":       "heuristic",
                "line":       node.lineno,
                "severity":   "WARNING",
                "code":       "H009",
                "message":    (
                    "User-controlled string passed as regex pattern — attacker can supply a "
                    "catastrophically backtracking regex causing denial of service (CWE-730)."
                ),
                "cwe_ids":    ["CWE-730"],
                "confidence": "MEDIUM",
            })

    return findings


_SENSITIVE_LOG_NAMES = frozenset({
    "sql", "query", "stmt", "statement", "cursor",
    "password", "passwd", "pwd", "secret", "token",
    "api_key", "apikey", "credential", "auth",
})


def _sensitive_data_log_findings(code: str) -> list[dict]:
    """Detect CWE-200: sensitive internal data (SQL queries, credentials) logged."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    def _contains_sensitive_name(node: ast.expr) -> bool:
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id.lower() in _SENSITIVE_LOG_NAMES:
                return True
        return False

    _LOG_METHODS = {"debug", "info", "warning", "warn", "error", "critical",
                    "exception", "log", "fatal"}
    findings: list[dict] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Attribute)
                and node.func.attr in _LOG_METHODS
                and isinstance(node.func.value, ast.Name)):
            continue
        for arg in node.args:
            if _contains_sensitive_name(arg):
                findings.append({
                    "tool":       "heuristic",
                    "line":       node.lineno,
                    "severity":   "WARNING",
                    "code":       "H010",
                    "message":    (
                        "Sensitive data (SQL query, credential, or secret) included in a "
                        "logging call — may expose internals to log aggregators (CWE-200)."
                    ),
                    "cwe_ids":    ["CWE-200"],
                    "confidence": "MEDIUM",
                })
                break

    return findings


def _object_ref_comparison_findings(code: str) -> list[dict]:
    """Detect CWE-595: `is`/`is not` used to compare non-singleton objects."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    _SINGLETONS: frozenset = frozenset({None, True, False})
    _BUILTIN_TYPES = frozenset({
        "int", "str", "float", "bool", "list", "dict", "tuple", "set",
        "bytes", "bytearray", "type", "object", "NoneType",
    })

    def _is_singleton_or_type(n: ast.expr) -> bool:
        if isinstance(n, ast.Constant) and n.value in _SINGLETONS:
            return True
        if isinstance(n, ast.Name):
            if n.id in _BUILTIN_TYPES:
                return True
            if n.id and n.id[0].isupper():  # class names like MyClass
                return True
        return False

    findings: list[dict] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        operands = [node.left] + list(node.comparators)
        for op, left, right in zip(node.ops, operands, operands[1:]):
            if not isinstance(op, (ast.Is, ast.IsNot)):
                continue
            if _is_singleton_or_type(left) or _is_singleton_or_type(right):
                continue
            findings.append({
                "tool":       "heuristic",
                "line":       node.lineno,
                "severity":   "WARNING",
                "code":       "H008",
                "message":    (
                    "Object identity comparison (`is`/`is not`) used instead of value equality "
                    "(`==`/`!=`) — may silently fail for equal but distinct objects (CWE-595)."
                ),
                "cwe_ids":    ["CWE-595"],
                "confidence": "MEDIUM",
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

    heuristic_findings = (
        _flask_taint_findings(code)
        + _lxml_xxe_findings(code)
        + _jwt_findings(code)
        + _hardcoded_secret_cmp_findings(code)
        + _log_injection_findings(code)
        + _info_exposure_findings(code)
        + _improper_encoding_findings(code)
        + _object_ref_comparison_findings(code)
        + _redos_findings(code)
        + _sensitive_data_log_findings(code)
    )
    all_findings = bandit_findings + pylint_findings + heuristic_findings
    all_findings.sort(key=lambda f: f["line"])
    return all_findings
