# PythonGuard

AI-powered Python security code reviewer combining static analysis (Layer 1), RAG retrieval over CWE/Bandit/style corpora (Layer 2), and local LLM reasoning (Layer 3).

## Running the UI

A Gradio web app is provided at `ui/app.py`. It lets you paste Python code, pick a local LLM, and get back severity-tagged findings with CWE citations and fix suggestions.

### 1. Install dependencies

```bash
pip install gradio faiss-cpu sentence-transformers llama-cpp-python huggingface_hub python-dotenv
```

### 2. Download models

The pipeline needs the bi-encoder (`all-MiniLM-L6-v2`, ~90 MB), the cross-encoder (`ms-marco-MiniLM-L-6-v2`, ~80 MB), and at least one LLM (GGUF, ~4 GB each). All of these are pulled by the same script.

```bash
# All LLMs + cross-encoder
python3 download_llm_models.py

# Or just one LLM (recommended for first run)
python3 download_llm_models.py --models qwen2.5
```

Models land under `models/<key>/`. The FAISS indexes under `faiss_index/indexes/` are already built and committed.

If a model on HuggingFace is gated, add a token to `.env`:

```
HF_TOKEN=hf_xxx
```

### 3. Launch the UI

```bash
python3 ui/app.py
```

Open http://127.0.0.1:7860 in your browser.

### Using the app

- Paste Python code into the left panel (or pick an example below the input).
- Choose a model from the dropdown — `qwen2.5`, `llama3.1`, or `mistral`. Only models you've downloaded will load successfully.
- Click **Analyze**. The first call for a given model loads it into memory (slow); subsequent calls reuse the cached runner.
- Findings appear on the right, sorted CRITICAL → WARNING → INFO, each with line number, CWE citation, explanation, and a fix suggestion when available.

### Troubleshooting

- **`FileNotFoundError: Path .../models/all-MiniLM-L6-v2 not found`** — the bi-encoder hasn't been downloaded. Run `python3 download_llm_models.py --skip-cross-encoder` (or with no flags) to fetch it.
- **`FileNotFoundError` for a `.gguf` file** — run the download script for that model key.
- **First analysis is very slow / RAM spikes** — expected: a 7B Q4 model takes 5–15 s to load and uses ~5 GB RAM.
- **Port 7860 already in use** — edit `server_port` at the bottom of `ui/app.py`.
