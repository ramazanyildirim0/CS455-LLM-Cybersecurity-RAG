"""Normalize Semgrep YAML rules (official + trailofbits) → JSONL chunks."""

import json
import re
from pathlib import Path
import yaml

BASE = Path(__file__).parent.parent / "starting_dataset" / "security"
OUT  = Path(__file__).parent.parent / "dataset" / "security_semgrep.jsonl"

SOURCES = [
    ("semgrep_official",    BASE / "semgrep_official"    / "python"),
    ("semgrep_trailofbits", BASE / "semgrep_trailofbits" / "python"),
]

SEV_MAP = {"ERROR": "CRITICAL", "WARNING": "WARNING", "INFO": "INFO"}


def _to_list(val):
    """Coerce a value that may be str or list to a list."""
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)]


def _extract_cwe_ids(cwe_raw):
    """Return bare IDs like ['CWE-89'] from any CWE field shape."""
    ids = []
    for entry in _to_list(cwe_raw):
        m = re.search(r"CWE-\d+", entry)
        if m:
            ids.append(m.group())
    return ids


def _build_text(rule_id, message, fix, cwe_raw, technology, description):
    parts = [f"{rule_id}: {message.strip()}"]
    cwe_ids = _extract_cwe_ids(cwe_raw)
    if cwe_ids:
        parts.append(f"CWE: {', '.join(cwe_ids)}.")
    if fix:
        parts.append(f"Fix: {fix.strip()}.")
    if technology:
        parts.append(f"Technology: {', '.join(_to_list(technology))}.")
    if description:
        parts.append(description.strip())
    return " ".join(parts)


def normalize_file(yaml_path: Path, source: str):
    try:
        with open(yaml_path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except Exception:
        return []

    if not isinstance(doc, dict) or "rules" not in doc:
        return []

    chunks = []
    for rule in doc.get("rules") or []:
        langs = _to_list(rule.get("languages", []))
        if langs and "python" not in langs and "generic" not in langs:
            continue

        rule_id   = rule.get("id", yaml_path.stem)
        message   = rule.get("message", "")
        fix       = rule.get("fix", "")
        meta      = rule.get("metadata", {}) or {}
        severity  = SEV_MAP.get(str(rule.get("severity", "")).upper(), "WARNING")
        cwe_raw   = meta.get("cwe") or meta.get("cwe-id")
        owasp_raw = meta.get("owasp")
        tech      = meta.get("technology")
        refs      = _to_list(meta.get("references"))
        description = meta.get("description", "")
        category  = meta.get("category", "security")

        tags = []
        for t in _to_list(tech):
            tags.append(t.lower().replace(" ", "-"))
        if category:
            tags.append(category)
        subcat = meta.get("subcategory")
        for s in _to_list(subcat):
            tags.append(s.lower())

        chunk = {
            "chunk_id":   f"{source}::{rule_id}",
            "source":     source,
            "index_type": "security",
            "title":      rule_id,
            "text":       _build_text(rule_id, message, fix, cwe_raw, tech, description),
            "severity":   severity,
            "cwe_ids":    _extract_cwe_ids(cwe_raw),
            "owasp_refs": _to_list(owasp_raw),
            "languages":  langs if langs else ["python"],
            "tags":       list(dict.fromkeys(tags)),
            "citation":   f"semgrep:{rule_id}",
            "references": refs,
            "metadata":   {
                "yaml_file": str(yaml_path.relative_to(BASE.parent.parent)),
                "likelihood": meta.get("likelihood"),
                "impact":     meta.get("impact"),
                "confidence": meta.get("confidence"),
            },
        }
        chunks.append(chunk)
    return chunks


def run():
    all_chunks = []
    for source, root in SOURCES:
        yaml_files = list(root.rglob("*.yaml")) + list(root.rglob("*.yml"))
        for yf in sorted(yaml_files):
            all_chunks.extend(normalize_file(yf, source))

    with open(OUT, "w", encoding="utf-8") as f:
        for chunk in all_chunks:
            f.write(json.dumps(chunk, ensure_ascii=False) + "\n")

    by_source = {}
    for c in all_chunks:
        by_source.setdefault(c["source"], 0)
        by_source[c["source"]] += 1
    print(f"security_semgrep.jsonl: {len(all_chunks)} chunks total")
    for src, n in by_source.items():
        print(f"  {src}: {n}")


if __name__ == "__main__":
    run()
