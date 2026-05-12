"""
Download all models for PythonGuard:
  - LLMs (Layer 3): Q4_K_M GGUF files (~4 GB each) under models/<key>/
  - Cross-encoder (Layer 2): ms-marco-MiniLM-L-6-v2 (~80 MB) under models/cross-encoder-ms-marco/

Skips any model whose files are already present.

Usage:
    python3 download_llm_models.py                          # all LLMs + cross-encoder
    python3 download_llm_models.py --models qwen2.5 mistral # subset of LLMs only
    python3 download_llm_models.py --skip-cross-encoder     # LLMs only
"""

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from huggingface_hub import hf_hub_download, login

MODELS_DIR = Path(__file__).parent / "models"

# Load HF_TOKEN from .env if present
load_dotenv(Path(__file__).parent / ".env")
_token = os.getenv("HF_TOKEN", "").strip()
if _token:
    login(token=_token, add_to_git_credential=False)
    print(f"HuggingFace: authenticated with token from .env")

# (hf_repo, gguf_filename) per model key
MODELS = {
    "qwen2.5": (
        "bartowski/Qwen2.5-7B-Instruct-GGUF",
        "Qwen2.5-7B-Instruct-Q4_K_M.gguf",
    ),
    "llama3.1": (
        "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF",
        "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf",
    ),
    "mistral": (
        "bartowski/Mistral-7B-Instruct-v0.3-GGUF",
        "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf",
    ),
}


def is_downloaded(key: str) -> bool:
    _, filename = MODELS[key]
    return (MODELS_DIR / key / filename).exists()


def download_model(key: str):
    repo_id, filename = MODELS[key]
    dest_dir = MODELS_DIR / key

    if is_downloaded(key):
        print(f"  [{key}] Already present at {dest_dir / filename} — skipping.")
        return

    dest_dir.mkdir(parents=True, exist_ok=True)
    print(f"  [{key}] Downloading {filename} from {repo_id} ...")

    hf_hub_download(
        repo_id=repo_id,
        filename=filename,
        local_dir=str(dest_dir),
    )

    print(f"  [{key}] Saved → {dest_dir / filename}")


def download_cross_encoder():
    from sentence_transformers import CrossEncoder
    dest = MODELS_DIR / "cross-encoder-ms-marco"
    if (dest / "config.json").exists():
        print(f"  [cross-encoder] Already present at {dest} — skipping.")
        return
    print(f"  [cross-encoder] Downloading ms-marco-MiniLM-L-6-v2 (~80 MB) ...")
    dest.mkdir(parents=True, exist_ok=True)
    model = CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")
    model.save(str(dest))
    print(f"  [cross-encoder] Saved → {dest}")


def main():
    parser = argparse.ArgumentParser(description="Download PythonGuard models")
    parser.add_argument(
        "--models",
        nargs="+",
        choices=list(MODELS),
        default=list(MODELS),
        metavar="MODEL",
        help=f"LLMs to download (default: all). Choices: {list(MODELS)}",
    )
    parser.add_argument(
        "--skip-cross-encoder",
        action="store_true",
        help="Skip downloading the cross-encoder re-ranking model",
    )
    args = parser.parse_args()

    MODELS_DIR.mkdir(exist_ok=True)
    print(f"Models directory : {MODELS_DIR}")
    print(f"Quantization     : Q4_K_M GGUF (~4 GB per LLM)\n")

    failed = []

    # Cross-encoder (small, download first)
    if not args.skip_cross_encoder:
        print(f"{'─'*60}")
        try:
            download_cross_encoder()
        except Exception as e:
            print(f"  [cross-encoder] ERROR: {e}", file=sys.stderr)
            failed.append("cross-encoder")

    # LLMs
    for key in args.models:
        print(f"{'─'*60}")
        try:
            download_model(key)
        except Exception as e:
            print(f"  [{key}] ERROR: {e}", file=sys.stderr)
            failed.append(key)

    print(f"\n{'─'*60}")
    succeeded = [k for k in (["cross-encoder"] + args.models) if k not in failed]
    print(f"Downloaded : {succeeded}")
    if failed:
        print(f"Failed     : {failed}")
        sys.exit(1)


if __name__ == "__main__":
    main()
