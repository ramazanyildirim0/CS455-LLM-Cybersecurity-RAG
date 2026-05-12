"""Normalize PEP style documents → one JSONL chunk per section.

Reads from pre-scraped *_sections.json files (section-level HTML extraction)
rather than the flat .txt files, which fragmented code examples into tokens.
"""

import json
import re
from pathlib import Path

BASE = Path(__file__).parent.parent / "dataset" / "style"
OUT  = Path(__file__).parent.parent / "normalized" / "style_peps.jsonl"

PEP_META = {
    "pep8_style_guide":            {"pep": "PEP 8",  "topic": "style",    "tags": ["style", "formatting", "indentation", "naming"]},
    "pep257_docstring_conventions":{"pep": "PEP 257","topic": "docstring","tags": ["docstring", "documentation", "style"]},
    "pep484_type_hints":           {"pep": "PEP 484","topic": "typing",   "tags": ["type-hints", "typing", "annotations"]},
}

MIN_CHUNK_CHARS = 80


def run():
    section_files = sorted(BASE.glob("*_sections.json"))
    chunks = []

    for sec_path in section_files:
        stem = sec_path.stem.replace("_sections", "")
        meta = PEP_META.get(stem, {"pep": stem, "topic": "style", "tags": ["style"]})
        pep_name = meta["pep"]
        tags     = meta["tags"]

        sections = json.loads(sec_path.read_text(encoding="utf-8"))

        for sec in sections:
            heading = sec["heading"].strip()
            body    = sec["body"].strip()
            if len(body) < MIN_CHUNK_CHARS:
                continue

            heading_slug = re.sub(r"[^a-z0-9]+", "-", heading.lower()).strip("-")
            chunk_id = f"pep::{stem}::{heading_slug}"
            title    = f"{pep_name} — {heading}"

            chunks.append({
                "chunk_id":   chunk_id,
                "source":     stem,
                "index_type": "style",
                "title":      title,
                "text":       f"{title}\n{body}",
                "severity":   None,
                "cwe_ids":    [],
                "owasp_refs": [],
                "languages":  ["python"],
                "tags":       tags,
                "citation":   f"{pep_name.lower().replace(' ', '')}:{heading_slug}",
                "references": [f"https://peps.python.org/{pep_name.lower().replace(' ', '-')}/"],
                "metadata":   {"pep": pep_name, "section": heading, "topic": meta["topic"]},
            })

    with open(OUT, "w", encoding="utf-8") as f:
        for chunk in chunks:
            f.write(json.dumps(chunk, ensure_ascii=False) + "\n")

    print(f"style_peps.jsonl: {len(chunks)} chunks from {len(section_files)} PEP section files")


if __name__ == "__main__":
    run()
