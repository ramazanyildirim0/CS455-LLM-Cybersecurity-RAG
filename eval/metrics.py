"""
Scoring functions for the evaluation harness.

All functions operate on the standard findings schema:
    [{"line": int, "severity": str, "explanation": str, "fix_suggestion": str, "citation": str}, ...]
"""

_FLAGGED_SEVERITIES = {"CRITICAL", "WARNING"}

# CWE parent → accepted child CWEs and equivalent Bandit/heuristic codes.
# Covers all 71 unique CWEs in the SecurityEval dataset, grouped by vulnerability family.
# Principle: citing a parent, child, or sibling CWE in the same family counts as a correct
# detection, matching how real security reviews work (e.g., CWE-331 IS a type of CWE-330).
_CWE_EQUIVALENCES: dict[str, set[str]] = {

    # ── Injection / Input Validation family ────────────────────────────────
    "CWE-20":  {"CWE-502", "CWE-74", "CWE-78", "CWE-79", "CWE-80", "CWE-89",
                "CWE-90", "CWE-91", "CWE-113", "CWE-116", "CWE-117", "CWE-252",
                "CWE-400", "CWE-601", "CWE-611", "CWE-641", "CWE-643", "CWE-730",
                "CWE-943", "B301", "B302", "B303", "B608", "B605", "B602",
                "H001", "H002", "H005"},
    "CWE-74":  {"CWE-20", "CWE-78", "CWE-79", "CWE-89"},
    "CWE-78":  {"CWE-20", "CWE-94", "CWE-95", "B102", "B307",
                "B602", "B603", "B604", "B605", "B606", "B607"},
    "CWE-89":  {"CWE-20", "B608"},
    "CWE-90":  {"CWE-20", "CWE-89"},            # LDAP Injection
    "CWE-91":  {"CWE-20", "CWE-89"},            # XPath Injection
    "CWE-94":  {"CWE-78", "CWE-95", "CWE-215", "B102", "B104", "B201"},
    "CWE-95":  {"CWE-78", "CWE-94", "B307"},
    "CWE-79":  {"CWE-80", "CWE-83", "CWE-87", "CWE-20", "CWE-113", "H001", "B701", "B702"},
    "CWE-80":  {"CWE-79", "CWE-83", "CWE-20", "H001"},
    "CWE-83":  {"CWE-79", "CWE-80", "CWE-87"},
    "CWE-87":  {"CWE-79", "CWE-80", "CWE-83"},
    "CWE-113": {"CWE-20", "CWE-79", "CWE-116"}, # HTTP Response Splitting
    "CWE-116": {"CWE-20", "CWE-113", "H007"},   # Improper Encoding / Escaping
    "CWE-117": {"CWE-20", "CWE-116", "H005"},   # Log Injection
    "CWE-252": {"CWE-20"},                      # Unchecked Return Value
    "CWE-400": {"CWE-20", "CWE-730"},           # Uncontrolled Resource Consumption
    "CWE-601": {"CWE-20", "CWE-79", "CWE-80", "H001"},  # Open Redirect
    "CWE-641": {"CWE-20", "CWE-601"},           # Improper Restriction of Names
    "CWE-643": {"CWE-20", "CWE-611"},           # XPath Injection
    "CWE-730": {"CWE-400", "CWE-20", "H009"},   # ReDoS
    "CWE-943": {"CWE-20", "CWE-89"},            # Improper Neutralization in Data Query
    "CWE-99":  {"CWE-20", "CWE-22", "CWE-641"},  # Improper Control of Resource Identifiers

    # ── Path Traversal / File Operations family ────────────────────────────
    "CWE-22":  {"CWE-20", "CWE-23", "CWE-36", "CWE-367", "CWE-377", "CWE-379",
                "CWE-434", "CWE-703", "B101", "B110", "B112", "B306"},
    "CWE-367": {"CWE-22", "CWE-703"},           # TOCTOU
    "CWE-377": {"CWE-22", "CWE-379", "B306"},   # Insecure Temp File
    "CWE-379": {"CWE-22", "CWE-377", "B306"},   # File in Publicly Accessible Dir
    "CWE-434": {"CWE-22", "CWE-20", "CWE-703"}, # Unrestricted Upload
    "CWE-703": {"CWE-22", "CWE-367", "CWE-434"},# Improper Check / Exception Handling

    # ── Weak Cryptography family ───────────────────────────────────────────
    "CWE-327": {"CWE-326", "CWE-328", "CWE-329", "CWE-330", "CWE-759", "CWE-760", "CWE-1204",
                "B303", "B304", "B305", "B413"},
    "CWE-759": {"CWE-327", "CWE-328", "CWE-330", "B303", "B324"},  # Hash without Salt
    "CWE-326": {"CWE-327", "CWE-328", "B505"},  # Inadequate Encryption Strength
    "CWE-328": {"CWE-327", "CWE-326"},          # Reversible One-Way Hash

    # ── Random / Entropy family ────────────────────────────────────────────
    "CWE-330": {"CWE-327", "CWE-329", "CWE-331", "CWE-338", "CWE-339", "CWE-340",
                "CWE-760", "B311"},
    "CWE-329": {"CWE-327", "CWE-330", "CWE-331", "CWE-760", "CWE-1204",
                "B303", "B324"},               # Not Using Random IV/Salt
    "CWE-331": {"CWE-330", "CWE-338", "CWE-339", "B311"},  # Insufficient Entropy
    "CWE-338": {"CWE-330", "CWE-331", "CWE-339", "B311"},  # Predictable PRNG
    "CWE-339": {"CWE-330", "CWE-331", "CWE-338"},          # Small Seed Space
    "CWE-340": {"CWE-330", "CWE-331"},
    "CWE-1204": {"CWE-327", "CWE-329", "CWE-330"},         # Static IV
    "CWE-760": {"CWE-329", "CWE-330"},                     # Reuse of Nonce/IV

    # ── Credentials / Hardcoded Secrets family ─────────────────────────────
    "CWE-259": {"CWE-321", "CWE-522", "CWE-798", "CWE-454",
                "B105", "B106", "B107", "H004"},
    "CWE-798": {"CWE-259", "CWE-321", "CWE-522", "B105", "B106", "B107", "H004"},
    "CWE-321": {"CWE-259", "CWE-798", "CWE-522"},  # Hardcoded Crypto Key
    "CWE-522": {"CWE-259", "CWE-798", "CWE-521"},  # Insufficiently Protected Credentials
    "CWE-521": {"CWE-259", "CWE-522"},             # Weak Password Requirements
    "CWE-454": {"CWE-259", "CWE-798"},             # External Initialization of Trusted Variable

    # ── Insecure Deserialization ───────────────────────────────────────────
    "CWE-502": {"CWE-20", "B301", "B302", "B403"},

    # ── SSL / TLS / Transport ──────────────────────────────────────────────
    "CWE-295": {"CWE-297", "CWE-300", "CWE-319", "B501", "B502"},
    "CWE-297": {"CWE-295"},
    "CWE-300": {"CWE-295"},
    "CWE-319": {"CWE-295", "CWE-311"},   # Cleartext Transmission

    # ── JWT / Authentication / Authorization family ────────────────────────
    "CWE-347": {"CWE-285", "CWE-287", "CWE-306", "H003"},   # JWT Signature Bypass
    "CWE-285": {"CWE-347", "CWE-287", "CWE-306"},
    "CWE-287": {"CWE-285", "CWE-306", "CWE-347"},
    "CWE-306": {"CWE-250", "CWE-269", "CWE-283", "CWE-285", "CWE-287",
                "CWE-425", "CWE-732", "CWE-841"},
    "CWE-250": {"CWE-269", "CWE-306", "CWE-732"},   # Execution with Unnecessary Privileges
    "CWE-269": {"CWE-250", "CWE-306"},              # Improper Privilege Management
    "CWE-283": {"CWE-285", "CWE-306"},              # Unverified Ownership
    "CWE-425": {"CWE-306", "CWE-22"},               # Direct Request / Forced Browsing
    "CWE-732": {"CWE-250", "CWE-306"},              # Incorrect Permission Assignment
    "CWE-841": {"CWE-306"},                         # Improper Enforcement of Behavioral Workflow

    # ── XXE / XML ──────────────────────────────────────────────────────────
    "CWE-611": {"CWE-20", "CWE-643", "CWE-776", "H002", "B405", "B314", "B320"},
    "CWE-776": {"CWE-611", "CWE-20"},               # Billion Laughs / DTD bomb

    # ── Information Exposure family ────────────────────────────────────────
    "CWE-200": {"CWE-209", "CWE-215", "CWE-532", "H010"},
    "CWE-209": {"CWE-200", "CWE-215", "H006"},      # Info in Error Messages
    "CWE-215": {"CWE-200", "CWE-209", "CWE-94", "B201"},  # Info in Debug Messages

    # ── Miscellaneous ──────────────────────────────────────────────────────
    "CWE-193": set(),    # Off-by-one — pure logic error, no useful CWE equivalence
    "CWE-406": {"CWE-400"},  # Insufficient Control of Network Message Volume
    "CWE-414": {"CWE-362", "CWE-367"},  # Missing Lock Check
    "CWE-462": {"CWE-20"},              # Duplicate Key in Associative List
    "CWE-477": set(),                   # Use of Obsolete Function
    "CWE-595": {"CWE-20", "H008"},      # Comparison of Object References Instead of Object Contents
    "CWE-605": {"CWE-20", "CWE-703"},   # Multiple Binds to Same Port
    "CWE-827": {"CWE-20", "CWE-611"},   # Improper Control of Document Type Definition
    "CWE-835": {"CWE-400"},             # Infinite Loop / ReDoS variant
    "CWE-941": {"CWE-20"},              # Incorrectly Specified Destination in a Communication Channel
    "CWE-918": {"CWE-20"},              # SSRF
}


def detection_any(findings: list[dict]) -> bool:
    """True if the system produced at least one CRITICAL or WARNING finding."""
    return any(
        f.get("severity") in _FLAGGED_SEVERITIES
        for f in findings
        if isinstance(f, dict)
    )


def detection_cwe(findings: list[dict], expected_cwe: str) -> bool:
    """True if any finding's citation contains the expected CWE or an accepted equivalent.

    Equivalences allow citing a child, parent, or sibling CWE in the same vulnerability
    family to count as a correct detection (e.g., CWE-331 for a CWE-330 case is correct
    because CWE-331 IS a type of CWE-330).
    """
    citations = " ".join(
        str(f.get("citation", "")) for f in findings if isinstance(f, dict)
    ).upper()
    accepted = {expected_cwe.upper()} | {e.upper() for e in _CWE_EQUIVALENCES.get(expected_cwe, set())}
    return any(label in citations for label in accepted)


def false_positive(findings: list[dict]) -> bool:
    """True if any CRITICAL or WARNING finding was produced on ostensibly clean code."""
    return detection_any(findings)


def aggregate_recall(results: list[dict]) -> dict:
    """Compute recall_any and recall_cwe from a list of per-record recall result dicts."""
    n = len(results)
    if n == 0:
        return {"recall_any": 0.0, "recall_cwe": 0.0, "n": 0}
    return {
        "recall_any": sum(r["detected_any"] for r in results) / n,
        "recall_cwe": sum(r["detected_cwe"] for r in results) / n,
        "n": n,
    }


def aggregate_fpr(results: list[dict]) -> dict:
    """Compute false positive rate from a list of per-record FPR result dicts."""
    n = len(results)
    if n == 0:
        return {"fpr": 0.0, "n": 0}
    return {"fpr": sum(r["false_positive"] for r in results) / n, "n": n}


def aggregate_faithfulness(judgements: list[bool]) -> dict:
    """Compute citation faithfulness rate from a list of judge YES/NO booleans."""
    n = len(judgements)
    if n == 0:
        return {"faithfulness": 0.0, "n_findings": 0}
    return {"faithfulness": sum(judgements) / n, "n_findings": n}


def per_cwe_breakdown(results: list[dict]) -> dict:
    """Group recall results by CWE and compute per-CWE recall_any and recall_cwe."""
    by_cwe: dict[str, list] = {}
    for r in results:
        cwe = r.get("cwe", "unknown")
        by_cwe.setdefault(cwe, []).append(r)
    return {cwe: aggregate_recall(recs) for cwe, recs in sorted(by_cwe.items())}
