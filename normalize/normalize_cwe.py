"""Normalize CWE XML → JSONL chunks (Python-relevant weaknesses only)."""

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

BASE = Path(__file__).parent.parent / "dataset" / "security" / "cwe"
OUT  = Path(__file__).parent.parent / "normalized" / "security_cwe.jsonl"

# XML namespace in the CWE catalog
NS = {"cwe": "http://cwe.mitre.org/cwe-7"}

# Keywords that indicate Python relevance (checked on Name + Description)
PYTHON_KEYWORDS = {
    "python", "injection", "sql", "command", "deserialization", "pickle",
    "cryptograph", "secret", "hardcoded", "password", "token", "xss",
    "cross-site", "path traversal", "directory traversal", "open redirect",
    "ssrf", "xxe", "xml", "yaml", "eval", "exec", "subprocess",
    "os.system", "authentication", "authorization", "session", "cookie",
    "insecure", "cleartext", "plaintext", "hash", "weak", "random",
    "entropy", "race condition", "integer overflow", "buffer", "format string",
    "log injection", "ldap", "xpath", "template injection", "jinja",
    "regex", "denial of service", "dos", "symlink", "upload", "file inclusion",
}

LIKELIHOOD_SEV = {
    "High":   "CRITICAL",
    "Medium": "WARNING",
    "Low":    "INFO",
}


def _text(el, tag):
    """Get stripped text of first matching sub-element, handling namespace."""
    child = el.find(tag)
    if child is None:
        return ""
    # Collect all text including tail within xhtml children
    return " ".join((child.itertext())).strip()


def _is_python_relevant(weakness_el, name, desc):
    combined = (name + " " + desc).lower()
    if "python" in combined:
        return True
    # Check applicable platforms for Python
    for plat in weakness_el.iter():
        if plat.get("Name") == "Python":
            return True
        if plat.get("Class") in ("Not Language-Specific",):
            # Language-agnostic weaknesses that relate to our keywords
            for kw in PYTHON_KEYWORDS:
                if kw in combined:
                    return True
            return False
    # Keyword match fallback
    return any(kw in combined for kw in PYTHON_KEYWORDS)


def _get_consequences(weakness_el):
    parts = []
    for cons in weakness_el.iter():
        if not cons.tag.endswith("Consequence"):
            continue
        scope  = " ".join(c.text or "" for c in cons if c.tag.endswith("Scope")).strip()
        impact = " ".join(c.text or "" for c in cons if c.tag.endswith("Impact")).strip()
        if scope or impact:
            parts.append(f"{scope}: {impact}".strip(": "))
    return "; ".join(parts[:4])  # cap at 4 to keep text manageable


def _get_mitigations(weakness_el):
    parts = []
    for mit in weakness_el.iter():
        if not mit.tag.endswith("Mitigation"):
            continue
        for desc_el in mit:
            if desc_el.tag.endswith("Description"):
                text = " ".join(desc_el.itertext()).strip()
                if text:
                    parts.append(re.sub(r"\s+", " ", text)[:300])
                break
    return " | ".join(parts[:3])


def run():
    xml_files = list(BASE.glob("*.xml"))
    if not xml_files:
        print("ERROR: No CWE XML file found in", BASE)
        return

    xml_path = xml_files[0]
    print(f"Parsing {xml_path.name} ...")
    tree = ET.parse(xml_path)
    root = tree.getroot()

    chunks = []
    seen_ids = set()

    for weakness in root.iter():
        if not weakness.tag.endswith("Weakness"):
            continue

        cwe_id   = weakness.get("ID", "")
        name     = weakness.get("Name", "")
        status   = weakness.get("Status", "")

        if status == "Deprecated" or not cwe_id:
            continue
        if cwe_id in seen_ids:
            continue

        # Description
        desc = ""
        for child in weakness:
            if child.tag.endswith("Description"):
                desc = " ".join(child.itertext()).strip()
                break

        ext_desc = ""
        for child in weakness:
            if child.tag.endswith("Extended_Description"):
                ext_desc = re.sub(r"\s+", " ", " ".join(child.itertext())).strip()[:500]
                break

        if not _is_python_relevant(weakness, name, desc):
            continue

        seen_ids.add(cwe_id)

        likelihood_raw = ""
        for child in weakness:
            if child.tag.endswith("Likelihood_Of_Exploit"):
                likelihood_raw = (child.text or "").strip()
                break

        severity = LIKELIHOOD_SEV.get(likelihood_raw, "WARNING")
        consequences = _get_consequences(weakness)
        mitigations  = _get_mitigations(weakness)

        text_parts = [f"CWE-{cwe_id} {name}: {desc}"]
        if ext_desc:
            text_parts.append(ext_desc)
        if consequences:
            text_parts.append(f"Consequences: {consequences}.")
        if mitigations:
            text_parts.append(f"Mitigations: {mitigations}.")
        text = " ".join(text_parts)

        chunk = {
            "chunk_id":   f"cwe::CWE-{cwe_id}",
            "source":     "cwe",
            "index_type": "security",
            "title":      f"CWE-{cwe_id}: {name}",
            "text":       re.sub(r"\s+", " ", text).strip(),
            "severity":   severity,
            "cwe_ids":    [f"CWE-{cwe_id}"],
            "owasp_refs": [],
            "languages":  ["python"],
            "tags":       [w for w in name.lower().split() if len(w) > 3],
            "citation":   f"cwe:CWE-{cwe_id}",
            "references": [f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"],
            "metadata":   {
                "abstraction": weakness.get("Abstraction"),
                "status":      status,
                "likelihood":  likelihood_raw,
            },
        }
        chunks.append(chunk)

    with open(OUT, "w", encoding="utf-8") as f:
        for chunk in chunks:
            f.write(json.dumps(chunk, ensure_ascii=False) + "\n")

    print(f"security_cwe.jsonl: {len(chunks)} Python-relevant CWE chunks")


if __name__ == "__main__":
    run()
