"""
PythonGuard — End-to-end pipeline entry point.

Input  : a Python file (or stdin)
Output : JSON array of issues, each with line, severity, explanation,
         fix_suggestion, and citation.

Usage:
    python3 main.py <file.py>                    # review a file
    python3 main.py <file.py> --model llama3.1   # choose model
    cat file.py | python3 main.py -              # read from stdin
    python3 main.py <file.py> --json-only        # suppress summary, raw JSON only
"""

import argparse
import json
import sys
import time

SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",  # red
    "WARNING":  "\033[93m",  # yellow
    "INFO":     "\033[94m",  # blue
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def _color(text: str, severity: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{SEVERITY_COLOR.get(severity, '')}{text}{RESET}"


def print_summary(findings: list[dict], code: str, elapsed: float):
    lines = code.splitlines()
    counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
    for f in findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

    print(f"\n{BOLD}{'─'*64}{RESET}")
    print(f"{BOLD}  PythonGuard Results  {RESET}({elapsed:.1f}s)")
    print(f"{'─'*64}")
    crit_str = f"CRITICAL: {counts['CRITICAL']}"
    warn_str = f"WARNING: {counts['WARNING']}"
    info_str = f"INFO: {counts['INFO']}"
    print(f"  {_color(crit_str, 'CRITICAL')}  {_color(warn_str, 'WARNING')}  {_color(info_str, 'INFO')}")
    print(f"{'─'*64}\n")

    if not findings:
        print("  No issues found.")
        return

    for f in sorted(findings, key=lambda x: (x.get("line", 0))):
        sev      = f.get("severity", "INFO")
        line_no  = f.get("line", "?")
        citation = f.get("citation", "heuristic")
        expl     = f.get("explanation", "")
        fix      = f.get("fix_suggestion", "")

        # Show the source line if available
        src_line = ""
        if isinstance(line_no, int) and 0 < line_no <= len(lines):
            src_line = f"    {lines[line_no - 1].strip()}"

        print(f"  {_color(f'[{sev}]', sev)} Line {line_no}  citation: {citation}")
        if src_line:
            print(f"\033[2m{src_line}{RESET}")
        print(f"  {expl}")
        print(f"  {BOLD}Fix:{RESET} {fix}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="PythonGuard: RAG-based Python security code reviewer"
    )
    parser.add_argument(
        "file",
        help="Python file to review, or '-' to read from stdin",
    )
    parser.add_argument(
        "--model",
        default="qwen2.5",
        choices=["qwen2.5", "llama3.1", "mistral"],
        help="LLM to use (default: qwen2.5)",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=5,
        help="Retrieved chunks per index (default: 5)",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Print raw JSON output only, no summary",
    )
    args = parser.parse_args()

    # Read input code
    if args.file == "-":
        code = sys.stdin.read()
        source = "stdin"
    else:
        try:
            code = open(args.file, encoding="utf-8").read()
            source = args.file
        except FileNotFoundError:
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)

    if not args.json_only:
        print(f"{BOLD}PythonGuard{RESET} reviewing {source!r} with model={args.model} ...")

    # Run the full pipeline
    from layer3.review import review

    t0 = time.time()
    findings = review(code, model_name=args.model, top_k=args.top_k)
    elapsed  = time.time() - t0

    # Output
    if args.json_only:
        print(json.dumps(findings, indent=2))
    else:
        print_summary(findings, code, elapsed)
        print(f"{BOLD}JSON output:{RESET}")
        print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
