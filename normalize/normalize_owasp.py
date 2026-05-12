"""Normalize OWASP Cheat Sheets (.md) → one JSONL chunk per H2 section."""

import json
import re
from pathlib import Path

BASE = Path(__file__).parent.parent / "starting_dataset" / "security" / "owasp" / "cheatsheets"
OUT  = Path(__file__).parent.parent / "dataset" / "security_owasp.jsonl"

MIN_SECTION_CHARS = 80  # skip trivially short sections


def _tags_from_stem(stem: str):
    """'SQL_Injection_Cheat_Sheet' → ['sql', 'injection']"""
    words = re.split(r"[_\-\s]+", stem.replace("Cheat_Sheet", "").replace("CheatSheet", ""))
    return [w.lower() for w in words if len(w) > 2 and w.lower() not in ("cheat", "sheet", "the", "and")]


def _split_by_h2(text: str):
    """Split markdown text into (heading, body) tuples on ## headers."""
    pattern = re.compile(r"^##\s+(.+)$", re.MULTILINE)
    positions = [(m.start(), m.group(1).strip()) for m in pattern.finditer(text)]

    if not positions:
        # No H2 — return entire doc as one section
        title_m = re.match(r"^#\s+(.+)$", text, re.MULTILINE)
        heading = title_m.group(1).strip() if title_m else "Introduction"
        return [(heading, text.strip())]

    sections = []
    for i, (pos, heading) in enumerate(positions):
        end = positions[i + 1][0] if i + 1 < len(positions) else len(text)
        body = text[pos:end].strip()
        # Remove the ## heading line itself from body
        body = re.sub(r"^##\s+.+\n?", "", body, count=1).strip()
        sections.append((heading, body))
    return sections


def _is_deprecated(text: str):
    return bool(re.search(r"deprecated|this cheat sheet has been (retired|archived|removed)", text[:500], re.I))


def run():
    md_files = sorted(BASE.glob("*.md"))
    chunks = []
    skipped_files = 0

    for md_path in md_files:
        text = md_path.read_text(encoding="utf-8", errors="ignore")

        if _is_deprecated(text):
            skipped_files += 1
            continue

        stem = md_path.stem
        tags = _tags_from_stem(stem)

        # Top-level title (H1)
        h1_m = re.match(r"^#\s+(.+)$", text, re.MULTILINE)
        doc_title = h1_m.group(1).strip() if h1_m else stem.replace("_", " ")

        sections = _split_by_h2(text)

        for heading, body in sections:
            if len(body) < MIN_SECTION_CHARS:
                continue

            clean_body = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", body)  # strip markdown links
            clean_body = re.sub(r"`([^`]+)`", r"\1", clean_body)          # strip backticks
            clean_body = re.sub(r"\*{1,2}([^*]+)\*{1,2}", r"\1", clean_body)  # strip bold/italic
            clean_body = re.sub(r"\s+", " ", clean_body).strip()

            chunk_id = f"owasp::{stem}::{re.sub(r'[^a-z0-9]+', '-', heading.lower()).strip('-')}"
            title    = f"{doc_title} — {heading}"
            text_out = f"{title}\n{clean_body}"

            chunks.append({
                "chunk_id":   chunk_id,
                "source":     "owasp",
                "index_type": "security",
                "title":      title,
                "text":       text_out,
                "severity":   None,
                "cwe_ids":    [],
                "owasp_refs": [],
                "languages":  ["python"],
                "tags":       tags,
                "citation":   f"owasp:{stem}#{re.sub(r'[^a-z0-9]+', '-', heading.lower()).strip('-')}",
                "references": ["https://cheatsheetseries.owasp.org/cheatsheets/" + md_path.name.replace(".md", ".html")],
                "metadata":   {"cheatsheet": stem, "section": heading},
            })

    with open(OUT, "w", encoding="utf-8") as f:
        for chunk in chunks:
            f.write(json.dumps(chunk, ensure_ascii=False) + "\n")

    print(f"security_owasp.jsonl: {len(chunks)} chunks from {len(md_files) - skipped_files} cheat sheets "
          f"({skipped_files} deprecated skipped)")


if __name__ == "__main__":
    run()
