#!/usr/bin/env python3
"""Checks every {{#include path[:anchor]}} in book/*/src: the file exists, the anchor (if any) is
defined with ANCHOR/ANCHOR_END in it, and the included text is not empty. mdBook only warns
about a missing anchor and renders an empty block, so CI runs this before `mdbook build`.

Also checks that the two languages cover the same sections: the same files, and in each file the
same sequence of heading levels (outside code blocks), the same includes and the same number of
code blocks, table rows and list items.

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

FENCE = re.compile(r"^(```|~~~)")


def outline(md):
    """Heading levels, includes, code blocks and table rows of one chapter, in order."""
    heads, includes, blocks, rows, items = [], [], 0, 0, 0
    in_code = False
    for line in md.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line):
            in_code = not in_code
            blocks += in_code
            continue
        # A translated include (x.zh-CN.md for x.md) counts as the same include.
        includes += [re.sub(r"\.zh-CN\.md", ".md", m.group(0)) for m in INCLUDE.finditer(line)]
        if in_code:
            continue
        m = re.match(r"^(#{1,6})\s", line)
        if m:
            heads.append(len(m.group(1)))
        if line.startswith("|") and not re.match(r"^\|[\s|:-]+\|$", line):
            rows += 1
        if re.match(r"^\s*([-*]|\d+\.)\s", line):
            items += 1
    return heads, includes, blocks, rows, items


langs = sorted(d.name for d in ROOT.iterdir() if (d / "src").is_dir())
trees = {lang: {p.relative_to(ROOT / lang / "src") for p in (ROOT / lang / "src").rglob("*.md")}
         for lang in langs}
first = langs[0]
for lang in langs[1:]:
    for rel in sorted(trees[first] ^ trees[lang]):
        problems.append(f"{rel}: only in {first if rel in trees[first] else lang}")
    for rel in sorted(trees[first] & trees[lang]):
        a, b = outline(ROOT / first / "src" / rel), outline(ROOT / lang / "src" / rel)
        for what, x, y in zip(("heading levels", "includes", "code blocks", "table rows", "list items"), a, b):
            if x != y:
                problems.append(f"{rel}: {first} and {lang} differ in {what}: {x} vs {y}")

for p in problems:
    print(p, file=sys.stderr)
print(f"{count} includes checked, {len(trees[first])} chapters compared across {', '.join(langs)}, "
      f"{len(problems)} problem(s)")
sys.exit(1 if problems else 0)
