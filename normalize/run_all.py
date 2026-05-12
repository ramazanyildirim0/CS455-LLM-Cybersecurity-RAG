"""Run all normalizers and print a final summary."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import normalize_semgrep
import normalize_cwe
import normalize_owasp
import normalize_peps
import normalize_bug_patterns

print("=" * 55)
print("Step 1/5  Semgrep rules (official + trailofbits)")
print("=" * 55)
normalize_semgrep.run()

print()
print("=" * 55)
print("Step 2/5  CWE XML")
print("=" * 55)
normalize_cwe.run()

print()
print("=" * 55)
print("Step 3/5  OWASP Cheat Sheets")
print("=" * 55)
normalize_owasp.run()

print()
print("=" * 55)
print("Step 4/5  PEP style documents")
print("=" * 55)
normalize_peps.run()

print()
print("=" * 55)
print("Step 5/5  Bug pattern datasets")
print("=" * 55)
normalize_bug_patterns.run()

print()
print("=" * 55)
print("SUMMARY")
print("=" * 55)
normalized_dir = Path(__file__).parent.parent / "normalized"
total = 0
for f in sorted(normalized_dir.glob("*.jsonl")):
    n = sum(1 for _ in open(f, encoding="utf-8"))
    total += n
    print(f"  {f.name:<35} {n:>6} chunks")
print(f"  {'TOTAL':<35} {total:>6} chunks")
