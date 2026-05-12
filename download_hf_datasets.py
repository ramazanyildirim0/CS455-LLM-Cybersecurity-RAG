"""Download all HuggingFace datasets and PEP style docs for PythonGuard."""

import os
import warnings
warnings.filterwarnings("ignore")

BASE = "/Users/ramazanyildirim/Desktop/Spring 2025/CS455/project/dataset"

# ---------------------------------------------------------------------------
# HuggingFace datasets
# ---------------------------------------------------------------------------
from datasets import load_dataset

print("=== Downloading Dahoas/code-review-instruct-critique-revision-python ===")
ds = load_dataset("Dahoas/code-review-instruct-critique-revision-python", split="train")
ds.to_json(f"{BASE}/bug_patterns/dahoas_code_review.jsonl")
print(f"  Saved {len(ds):,} rows -> bug_patterns/dahoas_code_review.jsonl")

print("=== Downloading Muennighoff/python-bugs ===")
ds = load_dataset("Muennighoff/python-bugs", split="train")
ds.to_json(f"{BASE}/bug_patterns/muennighoff_python_bugs.jsonl")
print(f"  Saved {len(ds):,} rows -> bug_patterns/muennighoff_python_bugs.jsonl")

print("=== Downloading bigcode/humanevalpack (Python split) ===")
ds = load_dataset("bigcode/humanevalpack", "python", split="test", trust_remote_code=True)
ds.to_json(f"{BASE}/eval/humanevalpack_python.jsonl")
print(f"  Saved {len(ds):,} rows -> eval/humanevalpack_python.jsonl")

print("=== Downloading Tomo-Melb/CodeReviewQA ===")
try:
    ds = load_dataset("Tomo-Melb/CodeReviewQA", split="train")
    # Filter to Python subset
    py_ds = ds.filter(lambda x: (x.get("language") or "").lower() == "python")
    py_ds.to_json(f"{BASE}/eval/codereviewqa_python.jsonl")
    print(f"  Saved {len(py_ds):,} Python rows (of {len(ds):,} total) -> eval/codereviewqa_python.jsonl")
except Exception as e:
    print(f"  WARNING: {e}")
    print("  Saving all rows without language filter.")
    ds = load_dataset("Tomo-Melb/CodeReviewQA", split="train")
    ds.to_json(f"{BASE}/eval/codereviewqa_all.jsonl")
    print(f"  Saved {len(ds):,} rows -> eval/codereviewqa_all.jsonl")

# ---------------------------------------------------------------------------
# PEP style docs (scraped from peps.python.org)
# ---------------------------------------------------------------------------
import requests
from bs4 import BeautifulSoup

PEPS = {
    "pep8_style_guide": "https://peps.python.org/pep-0008/",
    "pep257_docstring_conventions": "https://peps.python.org/pep-0257/",
    "pep484_type_hints": "https://peps.python.org/pep-0484/",
}

print("=== Downloading PEP style documents ===")
for name, url in PEPS.items():
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    # Extract main article content
    article = soup.find("article") or soup.find("div", {"class": "section"}) or soup.body
    text = article.get_text(separator="\n", strip=True)
    out = f"{BASE}/style/{name}.txt"
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"  Saved {len(text):,} chars -> style/{name}.txt")

print("\nAll downloads complete.")
