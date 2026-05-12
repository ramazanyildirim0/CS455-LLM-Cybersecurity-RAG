"""
Layer 3 — End-to-end review pipeline.

Ties together Layer 1 (static analysis), Layer 2 (RAG retrieval),
and Layer 3 (LLM generation) into a single review() call.

Usage:
    from layer3.review import review
    findings = review(code, model_name="qwen2.5")
"""

from layer1.static_analysis import run_static_analysis
from layer2.retrieval import Retriever
from layer3.llm_runner import LLMRunner
from layer3.prompt_builder import build_prompt

_retriever: Retriever | None = None


def _get_retriever() -> Retriever:
    global _retriever
    if _retriever is None:
        _retriever = Retriever()
    return _retriever


def review(
    code: str,
    model_name: str = "qwen2.5",
    top_k: int = 5,
    max_new_tokens: int = 1024,
) -> list[dict]:
    """
    Run the full PythonGuard pipeline on a Python code string.

    Returns a list of finding dicts, each with:
        line, severity, explanation, fix_suggestion, citation
    """
    layer1_findings = run_static_analysis(code)
    layer2_results  = _get_retriever().query(code, layer1_findings, top_k=top_k)
    prompt          = build_prompt(code, layer1_findings, layer2_results)
    runner          = LLMRunner(model_name)
    raw             = runner.generate(prompt, max_new_tokens=max_new_tokens)
    return runner.parse_json(raw)
