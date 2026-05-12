"""Normalize Dahoas + Muennighoff bug pattern datasets → JSONL chunks."""

import json
import re
from pathlib import Path

BASE = Path(__file__).parent.parent / "starting_dataset" / "bug_patterns"
OUT  = Path(__file__).parent.parent / "dataset" / "bug_patterns.jsonl"

# Dahoas response block markers
RE_ORIGINAL = re.compile(r"ORIGINAL CODE\s*[:\-]*\s*", re.I)
RE_CRITIQUE = re.compile(r"CRITIQUE\s*[:\-]*\s*", re.I)
RE_REVISED  = re.compile(r"REVISED CODE\s*[:\-]*\s*", re.I)


def _parse_dahoas_response(response: str):
    """Extract (critique, revised_code) from the ORIGINAL/CRITIQUE/REVISED response."""
    # Split on CRITIQUE marker first
    parts_c = RE_CRITIQUE.split(response, maxsplit=1)
    if len(parts_c) < 2:
        return response.strip(), ""

    after_critique = parts_c[1]
    parts_r = RE_REVISED.split(after_critique, maxsplit=1)
    critique     = parts_r[0].strip()
    revised_code = parts_r[1].strip() if len(parts_r) > 1 else ""
    return critique, revised_code


def _normalize_dahoas(path: Path):
    chunks = []
    with open(path, encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f):
            try:
                row = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            # Filter to Python-tagged entries
            tags_raw = (row.get("meta_data") or {}).get("Tags") or []
            tags = [t.lower() for t in tags_raw]
            if "python" not in tags:
                continue

            response = (row.get("response") or "").strip()
            if not response:
                continue

            critique, revised = _parse_dahoas_response(response)
            if not critique:
                continue

            title_raw = (row.get("meta_data") or {}).get("Title") or f"code-review-{line_no}"
            title = re.sub(r"\s+", " ", title_raw).strip()[:120]
            qid   = row.get("question_id", str(line_no))

            text_parts = [f"Code review: {title}"]
            text_parts.append(f"Critique: {critique[:800]}")
            if revised:
                text_parts.append(f"Revised code:\n{revised[:600]}")
            text = "\n".join(text_parts)

            chunks.append({
                "chunk_id":   f"dahoas::{qid}",
                "source":     "dahoas",
                "index_type": "bug_pattern",
                "title":      title,
                "text":       text,
                "severity":   "WARNING",
                "cwe_ids":    [],
                "owasp_refs": [],
                "languages":  ["python"],
                "tags":       [t for t in tags if t != "python"],
                "citation":   f"dahoas:question:{qid}",
                "references": [],
                "metadata":   {"question_id": qid, "score": (row.get("meta_data") or {}).get("Score")},
            })
    return chunks


# Muennighoff field extraction from the `prompt` string
RE_NME = re.compile(r"<NME>\s*(.+?)\s*(?=<|$)", re.S)
RE_BEF = re.compile(r"<BEF>\s*(.+?)\s*(?=<|$)", re.S)
RE_MSG = re.compile(r"<MSG>\s*(.+?)\s*(?=<|$)", re.S)
RE_DFF = re.compile(r"<DFF>\s*(.+?)\s*(?=<|$)", re.S)


def _extract_muennighoff_field(pattern, text):
    m = pattern.search(text)
    return m.group(1).strip() if m else ""


def _normalize_muennighoff(path: Path):
    chunks = []
    with open(path, encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f):
            try:
                row = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            task  = (row.get("task") or "unknown-bug").strip()
            idx   = row.get("index", line_no)
            prompt = row.get("prompt", "")

            nme = _extract_muennighoff_field(RE_NME, prompt)
            bef = _extract_muennighoff_field(RE_BEF, prompt) or (row.get("prompt_code") or "")
            msg = _extract_muennighoff_field(RE_MSG, prompt)
            dff = _extract_muennighoff_field(RE_DFF, prompt)

            if not bef and not dff:
                continue

            title = f"Bug fix: {msg or task}" + (f" ({nme})" if nme else "")
            text_parts = [f"Bug type: {task}."]
            if msg:
                text_parts.append(f"Message: {msg}.")
            if bef:
                text_parts.append(f"Buggy code:\n{bef[:600]}")
            if dff:
                text_parts.append(f"Fix diff:\n{dff[:400]}")

            chunks.append({
                "chunk_id":   f"muennighoff::{idx}",
                "source":     "muennighoff",
                "index_type": "bug_pattern",
                "title":      title[:120],
                "text":       "\n".join(text_parts),
                "severity":   "WARNING",
                "cwe_ids":    [],
                "owasp_refs": [],
                "languages":  ["python"],
                "tags":       [task.lower()],
                "citation":   f"muennighoff:python-bugs:{idx}",
                "references": [],
                "metadata":   {"task": task, "filename": nme, "index": idx},
            })
    return chunks


def run():
    dahoas_path     = BASE / "dahoas_code_review.jsonl"
    muennighoff_path= BASE / "muennighoff_python_bugs.jsonl"

    print("Processing Dahoas ...")
    dahoas_chunks = _normalize_dahoas(dahoas_path)
    print(f"  {len(dahoas_chunks)} Python-tagged chunks")

    print("Processing Muennighoff ...")
    muennighoff_chunks = _normalize_muennighoff(muennighoff_path)
    print(f"  {len(muennighoff_chunks)} chunks")

    all_chunks = dahoas_chunks + muennighoff_chunks

    with open(OUT, "w", encoding="utf-8") as f:
        for chunk in all_chunks:
            f.write(json.dumps(chunk, ensure_ascii=False) + "\n")

    print(f"bug_patterns.jsonl: {len(all_chunks)} total chunks")


if __name__ == "__main__":
    run()
