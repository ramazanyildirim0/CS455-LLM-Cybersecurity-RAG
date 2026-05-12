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
    def __init__(self, model_name: str, n_ctx: int = 4096):
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

    def generate(self, prompt: str, max_new_tokens: int = 1024) -> str:
        response = self._llm.create_chat_completion(
            messages=[
                {"role": "system", "content": "You are a Python security code reviewer."},
                {"role": "user",   "content": prompt},
            ],
            max_tokens=max_new_tokens,
            temperature=0.0,
        )
        return response["choices"][0]["message"]["content"].strip()

    def parse_json(self, raw: str) -> list[dict]:
        raw = raw.strip()

        # Strip markdown code fences if present
        fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw)
        if fence:
            raw = fence.group(1).strip()

        # Find the outermost JSON array
        start = raw.find("[")
        end   = raw.rfind("]")
        if start == -1 or end == -1:
            print("[layer3] WARNING: no JSON array found in output")
            return []

        try:
            return json.loads(raw[start : end + 1])
        except json.JSONDecodeError as e:
            print(f"[layer3] WARNING: JSON parse error — {e}")
            return []
