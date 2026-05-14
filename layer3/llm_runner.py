"""
Layer 3 — LLM Runner.

Loads a quantized GGUF model (Q4_K_M) via llama-cpp-python and generates
structured JSON output from a prompt.

GPU offloading:
  CUDA / MPS → n_gpu_layers=-1  (all layers on GPU)
  CPU        → n_gpu_layers=0

Models must be downloaded first:
    python3 download_llm_models.py
"""

import json
import re
from pathlib import Path

MODELS = {
    "qwen2.5":  "Qwen2.5-7B-Instruct-Q4_K_M.gguf",
    "llama3.1": "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf",
    "mistral":  "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf",
}

# Chat format string passed to llama-cpp-python
_CHAT_FORMAT = {
    "qwen2.5":  "chatml",
    "llama3.1": "llama-3",
    "mistral":  "mistral-instruct",
}

_MODELS_DIR = Path(__file__).parent.parent / "models"


def _extract_json_objects(text: str) -> list[str]:
    """Extract top-level {...} blobs from text using brace-counting (handles nesting)."""
    objects = []
    depth = 0
    start = None
    in_string = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_string:
            if ch == "\\" :
                i += 2        # skip escaped character
                continue
            if ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
            elif ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and start is not None:
                    objects.append(text[start : i + 1])
                    start = None
        i += 1
    return objects


def _gpu_layers() -> int:
    """Return -1 (all layers on GPU) if CUDA or MPS is available, else 0."""
    try:
        import torch
        if torch.cuda.is_available() or torch.backends.mps.is_available():
            return -1
    except ImportError:
        pass
    return 0


def _gguf_path(key: str) -> str:
    path = _MODELS_DIR / key / MODELS[key]
    if not path.exists():
        raise FileNotFoundError(
            f"GGUF file not found: {path}\n"
            f"Run: python3 download_llm_models.py --models {key}"
        )
    return str(path)


class LLMRunner:
    def __init__(self, model_name: str, n_ctx: int = 8192):
        if model_name not in MODELS:
            raise ValueError(f"Unknown model '{model_name}'. Choose from: {list(MODELS)}")

        from llama_cpp import Llama

        gguf_path   = _gguf_path(model_name)
        n_gpu       = _gpu_layers()
        chat_format = _CHAT_FORMAT[model_name]

        print(f"[layer3] Loading {model_name} (Q4_K_M) n_gpu_layers={n_gpu} ...")
        self._llm = Llama(
            model_path=gguf_path,
            n_ctx=n_ctx,
            n_gpu_layers=n_gpu,
            chat_format=chat_format,
            verbose=False,
        )

    _DEFAULT_SYSTEM = (
        "You are PythonGuard, a Python security vulnerability detector. "
        "You MUST respond with ONLY a valid JSON array of findings. "
        "Start your response with [ and end with ]. "
        "No markdown, no code fences, no explanation outside the array. "
        "Empty result = exactly []. "
        "Each finding must have: line (int), severity (CRITICAL/WARNING/INFO), "
        "explanation (string), fix_suggestion (string), citation (string)."
    )

    def generate(self, prompt: str, max_new_tokens: int = 1536, system: str | None = None) -> str:
        response = self._llm.create_chat_completion(
            messages=[
                {"role": "system", "content": system if system is not None else self._DEFAULT_SYSTEM},
                {"role": "user", "content": prompt},
            ],
            max_tokens=max_new_tokens,
            temperature=0.0,
            repeat_penalty=1.1,
        )
        return response["choices"][0]["message"]["content"].strip()

    def parse_json(self, raw: str) -> list[dict]:
        raw = raw.strip()

        # Strip markdown code fences
        fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw)
        if fence:
            raw = fence.group(1).strip()

        # Find outermost array brackets
        start = raw.find("[")
        end   = raw.rfind("]")
        if start == -1 or end == -1:
            return []

        candidate = raw[start : end + 1]

        # Stage 1: direct parse
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

        # Stage 2: fix trailing commas before ] or }
        fixed = re.sub(r",\s*([\]}])", r"\1", candidate)
        try:
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass

        # Stage 3: extract individual objects via balanced-brace counting
        objects = _extract_json_objects(candidate)
        results = []
        for obj_str in objects:
            for attempt in (obj_str, re.sub(r",\s*([\]}])", r"\1", obj_str)):
                try:
                    results.append(json.loads(attempt))
                    break
                except json.JSONDecodeError:
                    continue

        return results
