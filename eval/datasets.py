"""
Data loading utilities for the evaluation harness.

Reads from pre-saved JSONL files under dataset/test/ (populated by download_eval_datasets.py).
"""

import json
import random
from pathlib import Path


def load_security_eval(
    path: str | Path = "dataset/test/security_eval.jsonl",
    n: int | None = None,
    seed: int = 42,
) -> list[dict]:
    """Return SecurityEval records: {task_id, code, cwe}.

    Each record is a known-vulnerable Python snippet with its CWE label.
    Used to measure detection recall.
    """
    records = [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
    if n is not None and n < len(records):
        rng = random.Random(seed)
        records = rng.sample(records, n)
    return records


def load_humanevalpack_clean(
    path: str | Path = "dataset/test/humanevalpack_clean.jsonl",
) -> list[dict]:
    """Return clean HumanEvalPack canonical_solution records: {task_id, code}.

    Each record is a correct Python function implementation with no security issues.
    Used to measure false positive rate.
    """
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
