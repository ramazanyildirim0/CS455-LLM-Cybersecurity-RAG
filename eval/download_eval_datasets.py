"""
One-time script to download and save evaluation datasets.

    python3 eval/download_eval_datasets.py

Saves:
    dataset/test/security_eval.jsonl      — s2e-lab/SecurityEval (~130 vulnerable Python snippets)
    dataset/test/humanevalpack_clean.jsonl — 50 canonical_solutions from HumanEvalPack (clean code)
"""

import json
import pathlib
import random

OUT = pathlib.Path("dataset/test")
OUT.mkdir(parents=True, exist_ok=True)

HEP_PATH = pathlib.Path("starting_dataset/eval/humanevalpack_python.jsonl")


def download_security_eval():
    try:
        from datasets import load_dataset
    except ImportError:
        raise SystemExit("Run: pip install datasets")

    print("Downloading s2e-lab/SecurityEval from HuggingFace...")
    ds = load_dataset("s2e-lab/SecurityEval", split="train")

    first = dict(ds[0])
    print(f"Fields: {list(first.keys())}")
    print(f"Sample record: {json.dumps({k: str(v)[:80] for k, v in first.items()}, indent=2)}")

    # Field names: ID (filename like "CWE-020_author_1.py"), Prompt, Insecure_code
    # CWE is extracted from the ID filename via regex
    import re
    records = []
    for r in ds:
        task_id = r.get("ID", "")
        cwe_match = re.search(r"CWE-0*(\d+)", task_id, re.IGNORECASE)
        cwe = f"CWE-{int(cwe_match.group(1))}" if cwe_match else ""
        code = r.get("Insecure_code", "")
        records.append({"task_id": task_id, "code": code, "cwe": cwe})

    out_path = OUT / "security_eval.jsonl"
    out_path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
    print(f"Saved {len(records)} SecurityEval records → {out_path}")
    return records


def extract_humanevalpack_clean(n=50, seed=42):
    if not HEP_PATH.exists():
        print(f"Warning: {HEP_PATH} not found — skipping clean dataset")
        return []

    all_records = [json.loads(l) for l in HEP_PATH.read_text().splitlines() if l.strip()]
    random.seed(seed)
    sample = random.sample(all_records, min(n, len(all_records)))

    # canonical_solution is the function body; prepend prompt (includes signature + docstring)
    clean = [
        {
            "task_id": r["task_id"],
            "code": r["prompt"] + r["canonical_solution"],
        }
        for r in sample
    ]

    out_path = OUT / "humanevalpack_clean.jsonl"
    out_path.write_text("\n".join(json.dumps(r) for r in clean), encoding="utf-8")
    print(f"Saved {len(clean)} clean HumanEvalPack records → {out_path}")
    return clean


if __name__ == "__main__":
    download_security_eval()
    extract_humanevalpack_clean()
    print("\nDone. Both datasets saved under dataset/test/")
