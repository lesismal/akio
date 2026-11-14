#!/usr/bin/env python3
"""Per-crate coverage table (Markdown) from `cargo llvm-cov report --json --summary-only`.

usage: summary.py <coverage.json> [--files N]   (N: also list the N least covered files)
"""
import collections
import json
import re
import sys

data = json.load(open(sys.argv[1]))["data"][0]
top = int(sys.argv[sys.argv.index("--files") + 1]) if "--files" in sys.argv else 0

crates = collections.defaultdict(lambda: [0, 0, 0, 0])  # lines covered/total, fns covered/total
files = []
for f in data["files"]:
    m = re.search(r"crates/([^/]+)/src/", f["filename"])
    if not m:
        continue
    lines, fns = f["summary"]["lines"], f["summary"]["functions"]
    c = crates[m[1]]
    c[0] += lines["covered"]
    c[1] += lines["count"]
    c[2] += fns["covered"]
    c[3] += fns["count"]
    files.append((lines["count"] - lines["covered"], lines["percent"], f["filename"].split("crates/")[-1]))


def pct(a, b):
    return f"{100 * a / b:.1f}%" if b else "-"


print("| crate | lines | line cov | fn cov |")
print("|---|---:|---:|---:|")
for name in sorted(crates):
    c = crates[name]
    print(f"| {name} | {c[1]} | {pct(c[0], c[1])} | {pct(c[2], c[3])} |")
t = data["totals"]
print(f"| **total** | {t['lines']['count']} | **{t['lines']['percent']:.1f}%** "
      f"| {t['functions']['percent']:.1f}% |")
if top:
    print("\nLeast covered files (uncovered lines):\n")
    for missed, p, name in sorted(files, reverse=True)[:top]:
        print(f"- `{name}`: {missed} lines uncovered ({p:.1f}%)")
