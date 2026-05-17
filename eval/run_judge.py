"""
Standalone citation faithfulness judge.

Loads findings from an existing eval JSON, runs the LLM judge on every
CRITICAL/WARNING finding, and prints + saves the CiteFaith score.

Usage:
    python3 -m eval.run_judge eval/results/eval_20260516_114522.json
"""

import json
import sys
from pathlib import Path

from tqdm import tqdm

from eval.citation_judge import judge_findings
from eval.datasets import load_security_eval
from eval.metrics import aggregate_faithfulness
from layer3.llm_runner import LLMRunner


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("eval/results/eval_20260516_114522.json")
    data = json.loads(path.read_text(encoding="utf-8"))

    # Build code lookup from the SecurityEval dataset
    code_lookup = {r["task_id"]: r["code"] for r in load_security_eval()}

    runner = LLMRunner("qwen2.5")

    recall_results = data.get("raw_recall", [])
    judge_records = [r for r in recall_results if r.get("system", {}).get("findings")]

    all_verdicts: list[bool] = []
    yes_count = 0
    total = 0

    with tqdm(judge_records, desc="Judge", unit="snippet", dynamic_ncols=True) as pbar:
        for rec in pbar:
            task_id = rec["task_id"]
            code = code_lookup.get(task_id, "")
            findings = rec["system"].get("findings", [])
            verdicts = judge_findings(code, findings, runner)
            all_verdicts.extend(verdicts)
            yes = sum(verdicts)
            yes_count += yes
            total += len(verdicts)
            tqdm.write(f"  {task_id}  {yes}/{len(verdicts)} YES")
            pbar.set_postfix(faithfulness=f"{yes_count}/{total}")

    faith = aggregate_faithfulness(all_verdicts)
    print(f"\nCitation Faithfulness: {faith['faithfulness']:.1%}  ({yes_count}/{total} findings judged YES)")

    # Patch the JSON and save
    data["citation_faithfulness"]["system"] = faith
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"Updated {path}")


if __name__ == "__main__":
    main()
