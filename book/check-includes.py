#!/usr/bin/env python3
"""Checks every {{#include path[:anchor]}} in book/*/src: the file exists, the anchor (if any) is
defined with ANCHOR/ANCHOR_END in it, and the included text is not empty. mdBook only warns
about a missing anchor and renders an empty block, so CI runs this before `mdbook build`.

Usage: python3 book/check-includes.py   (exit status 1 on any problem)
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent
INCLUDE = re.compile(r"\{\{#include\s+([^}:\s]+)(?::([^}\s]+))?\s*\}\}")

problems = []
count = 0
for md in sorted(ROOT.glob("*/src/**/*.md")):
    for m in INCLUDE.finditer(md.read_text(encoding="utf-8")):
        count += 1
        target = (md.parent / m.group(1)).resolve()
        where = f"{md.relative_to(ROOT)}: {m.group(0)}"
        if not target.is_file():
            problems.append(f"{where}: no such file")
            continue
        sel = m.group(2)
        text = target.read_text(encoding="utf-8")
        if sel is None or re.fullmatch(r"\d*(:\d*)?", sel):
            continue  # whole file or a line range
        start = re.search(rf"ANCHOR:\s*{re.escape(sel)}\b", text)
        end = re.search(rf"ANCHOR_END:\s*{re.escape(sel)}\b", text)
        if not start or not end or end.start() <= start.end():
            problems.append(f"{where}: anchor '{sel}' missing or unterminated")
            continue
        body = text[start.end():end.start()].split("\n", 1)[-1]
        if not body.strip():
            problems.append(f"{where}: anchor '{sel}' is empty")

for p in problems:
    print(p, file=sys.stderr)
print(f"{count} includes checked, {len(problems)} problem(s)")
sys.exit(1 if problems else 0)
