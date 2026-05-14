"""
PythonGuard — Gradio UI

Launch:
    python3 ui/app.py
    # opens http://127.0.0.1:7860
"""

import sys
import traceback
from pathlib import Path

# Allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

import gradio as gr

from layer3.llm_runner import LLMRunner
from layer3.review import review

# ── Model cache ───────────────────────────────────────────────────────────────

_runners: dict[str, LLMRunner] = {}


def _get_runner(model_name: str) -> LLMRunner:
    if model_name not in _runners:
        _runners[model_name] = LLMRunner(model_name)
    return _runners[model_name]


# ── HTML rendering ────────────────────────────────────────────────────────────

_SEVERITY_STYLE = {
    "CRITICAL": {
        "border": "#dc2626",
        "bg":     "#fef2f2",
        "badge":  "#dc2626",
        "label":  "CRITICAL",
        "dot":    "🔴",
    },
    "WARNING": {
        "border": "#d97706",
        "bg":     "#fffbeb",
        "badge":  "#d97706",
        "label":  "WARNING",
        "dot":    "🟡",
    },
    "INFO": {
        "border": "#2563eb",
        "bg":     "#eff6ff",
        "badge":  "#2563eb",
        "label":  "INFO",
        "dot":    "🔵",
    },
}

_DEFAULT_STYLE = {
    "border": "#6b7280",
    "bg":     "#f9fafb",
    "badge":  "#6b7280",
    "label":  "UNKNOWN",
    "dot":    "⚪",
}


def _severity_style(severity: str) -> dict:
    return _SEVERITY_STYLE.get(severity.upper() if severity else "", _DEFAULT_STYLE)


def _badge(text: str, color: str) -> str:
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:4px;'
        f'font-size:11px;font-weight:700;color:#fff;background:{color};'
        f'letter-spacing:.5px;">{text}</span>'
    )


def _chip(text: str) -> str:
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:4px;'
        f'font-size:11px;font-weight:600;color:#374151;background:#e5e7eb;'
        f'font-family:monospace;">{text}</span>'
    )


def _finding_card(f: dict) -> str:
    sev = f.get("severity", "INFO")
    st = _severity_style(sev)
    line = f.get("line", "?")
    citation = f.get("citation", "")
    explanation = f.get("explanation", "")
    fix = f.get("fix_suggestion", "")

    fix_html = ""
    if fix:
        fix_html = (
            f'<div style="margin-top:8px;padding:8px 10px;background:#f3f4f6;'
            f'border-radius:4px;font-size:13px;color:#111827;">'
            f'<strong style="color:#374151;font-size:11px;text-transform:uppercase;'
            f'letter-spacing:.5px;">Fix suggestion</strong><br>'
            f'<span style="font-family:monospace;color:#111827;">{fix}</span></div>'
        )

    return (
        f'<div style="border-left:4px solid {st["border"]};background:{st["bg"]};'
        f'border-radius:6px;padding:12px 16px;margin-bottom:12px;">'
        f'<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px;">'
        f'{_badge(st["label"], st["badge"])}'
        f'{_chip(f"Line {line}")}'
        f'{_chip(citation) if citation else ""}'
        f'</div>'
        f'<div style="font-size:14px;color:#1f2937;line-height:1.5;">{explanation}</div>'
        f'{fix_html}'
        f'</div>'
    )


def _summary_bar(findings: list[dict]) -> str:
    counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
    for f in findings:
        sev = (f.get("severity") or "").upper()
        if sev in counts:
            counts[sev] += 1

    total = len(findings)
    parts = [f'<strong>{total}</strong> finding{"s" if total != 1 else ""}']
    for sev, count in counts.items():
        if count:
            st = _SEVERITY_STYLE[sev]
            parts.append(
                f'<span style="color:{st["badge"]};">{st["dot"]} {count} {sev}</span>'
            )

    return (
        f'<div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;'
        f'padding:10px 14px;background:#f9fafb;border:1px solid #e5e7eb;'
        f'border-radius:6px;margin-bottom:16px;font-size:14px;color:#374151;">'
        + "  ·  ".join(parts)
        + "</div>"
    )


def _render_findings(findings: list[dict]) -> str:
    if not findings:
        return (
            '<div style="padding:16px 20px;background:#f0fdf4;border:1px solid #bbf7d0;'
            'border-radius:6px;color:#166534;font-size:14px;font-weight:600;">'
            "✅ No security issues found."
            "</div>"
        )

    # Sort: CRITICAL first, then WARNING, then INFO
    _order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    sorted_findings = sorted(
        findings,
        key=lambda f: (_order.get((f.get("severity") or "").upper(), 3), f.get("line") or 0),
    )

    cards = "".join(_finding_card(f) for f in sorted_findings)
    return _summary_bar(sorted_findings) + cards


# ── Core analyze function ─────────────────────────────────────────────────────

def analyze(code: str, model_name: str) -> str:
    if not code or not code.strip():
        return (
            '<div style="padding:14px 18px;background:#fffbeb;border:1px solid #fde68a;'
            'border-radius:6px;color:#92400e;font-size:14px;">'
            "⚠️ Please paste some Python code before clicking Analyze."
            "</div>"
        )

    try:
        runner = _get_runner(model_name)
        findings = review(code, model_name=model_name, runner=runner)
        return _render_findings(findings)
    except Exception:
        tb = traceback.format_exc()
        return (
            f'<div style="padding:14px 18px;background:#fef2f2;border:1px solid #fecaca;'
            f'border-radius:6px;color:#991b1b;font-size:13px;font-family:monospace;">'
            f"<strong>Error during analysis:</strong><br><pre>{tb}</pre></div>"
        )


# ── Example snippets ──────────────────────────────────────────────────────────

_EXAMPLE_SQL = """\
import sqlite3

def get_user(username: str):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name='" + username + "'")
    return cursor.fetchone()
"""

_EXAMPLE_CMD = """\
import subprocess

def ping(host: str):
    result = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
    return result.stdout.decode()
"""

_EXAMPLE_HARDCODED_SECRET = """\
import requests

DB_PASSWORD = "superSecret123!"
API_KEY = "sk-prod-abc123xyz789"

def fetch_data(endpoint: str):
    headers = {"Authorization": "Bearer sk-prod-abc123xyz789"}
    return requests.get(endpoint, headers=headers).json()
"""

_EXAMPLE_DESERIALIZE = """\
import pickle

def load_user_session(data: bytes):
    session = pickle.loads(data)
    return session
"""

_EXAMPLE_PATH_TRAVERSAL = """\
import os

def read_file(filename: str) -> str:
    base_dir = "/var/www/uploads"
    path = os.path.join(base_dir, filename)
    with open(path) as f:
        return f.read()
"""

_EXAMPLE_CLEAN = """\
def add(a: int, b: int) -> int:
    return a + b

def greet(name: str) -> str:
    return f"Hello, {name}!"
"""

# ── Gradio app ────────────────────────────────────────────────────────────────

_CSS = """
    #header { text-align: center; padding: 8px 0 4px; }
    #header h1 { font-size: 2rem; font-weight: 800; color: #1f2937; }
    #header p  { color: #6b7280; font-size: 0.95rem; margin-top: 4px; }
    .analyze-btn { font-size: 1rem !important; font-weight: 700 !important; }
"""

with gr.Blocks(title="PythonGuard") as demo:

    with gr.Column(elem_id="header"):
        gr.HTML(
            "<h1>🔒 PythonGuard</h1>"
            "<p>AI-powered Python security code reviewer — Layer 1 static analysis "
            "+ RAG retrieval + LLM reasoning</p>"
        )

    with gr.Row():
        with gr.Column(scale=3):
            code_input = gr.Code(
                language="python",
                label="Python Code",
                lines=22,
                value=_EXAMPLE_SQL,
            )
            with gr.Row():
                model_dd = gr.Dropdown(
                    choices=["qwen2.5", "llama3.1", "mistral"],
                    value="qwen2.5",
                    label="Model",
                    scale=1,
                )
                run_btn = gr.Button(
                    "🔍  Analyze",
                    variant="primary",
                    scale=2,
                    elem_classes=["analyze-btn"],
                )

        with gr.Column(scale=2):
            gr.Markdown("### Results")
            output_html = gr.HTML(
                value='<div style="color:#9ca3af;font-size:14px;padding:12px 0;">'
                      "Results will appear here after analysis.</div>"
            )

    gr.Examples(
        examples=[
            [_EXAMPLE_SQL,              "qwen2.5"],
            [_EXAMPLE_CMD,              "qwen2.5"],
            [_EXAMPLE_HARDCODED_SECRET, "qwen2.5"],
            [_EXAMPLE_DESERIALIZE,      "qwen2.5"],
            [_EXAMPLE_PATH_TRAVERSAL,   "qwen2.5"],
            [_EXAMPLE_CLEAN,            "qwen2.5"],
        ],
        inputs=[code_input, model_dd],
        label="Example snippets",
        example_labels=[
            "SQL injection (CWE-89)",
            "Command injection (CWE-78)",
            "Hardcoded secrets (CWE-259)",
            "Insecure deserialization (CWE-502)",
            "Path traversal (CWE-22)",
            "Clean code (no issues)",
        ],
    )

    run_btn.click(
        fn=analyze,
        inputs=[code_input, model_dd],
        outputs=output_html,
    )

if __name__ == "__main__":
    demo.launch(
        server_name="127.0.0.1",
        server_port=7860,
        share=False,
        theme=gr.themes.Soft(primary_hue="red", neutral_hue="slate"),
        css=_CSS,
    )
