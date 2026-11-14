#!/usr/bin/env python3
"""Inventory of `unsafe` in the workspace (docs/unsafe-review.md).

Counts `unsafe` blocks, `unsafe fn`s and `unsafe impl`s per crate, split into library code
(`src/`) and tests/examples/benches, and checks that each one is preceded by a `SAFETY:`
comment (blocks, impls) or has a `# Safety` doc section (fns). Clippy enforces the same
(`undocumented_unsafe_blocks`, `missing_safety_doc`) but only for code it compiles on the host,
so this script also covers the Linux-only modules when run on macOS and vice versa.

Usage: tools/unsafe-inventory.py [--markdown] [--check]
  --markdown  print the table as Markdown (for docs/unsafe-review.md)
  --check     exit 1 if any unsafe site lacks its comment
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLOCK = re.compile(r"\bunsafe\s*\{")
FN = re.compile(r"\bunsafe\s+(extern\s+\"[^\"]*\"\s+)?fn\b")
IMPL = re.compile(r"\bunsafe\s+impl\b")
LOOKBACK = 12  # lines above a site searched for its comment


def strip_line(line):
    """Drops `//` comments and string literals (roughly) so they do not count as sites."""
    line = re.sub(r'"(\\.|[^"\\])*"', '""', line)
    i = line.find("//")
    return line if i < 0 else line[:i]


def documented(lines, idx, kind):
    lo = max(0, idx - LOOKBACK)
    window = lines[lo : idx + 1]
    if kind == "fn":
        if any("# Safety" in l for l in window):
            return True
        # A method of an `unsafe impl Trait for T`: the trait documents the contract, and the
        # impl itself carries the `SAFETY:` comment.
        if lines[idx][:1].isspace():
            for l in reversed(lines[max(0, idx - 40) : idx]):
                if re.match(r"\s*(pub(\([^)]*\))?\s+)?unsafe\s+impl\b.*\bfor\b", l):
                    return True
                if re.match(r"\S", l) and not l.startswith("}"):
                    break
        return False
    # The comment may sit on the same line, just above, or above the enclosing statement.
    return any("SAFETY:" in l for l in window)


def scan(path):
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    sites = []
    for i, raw in enumerate(lines):
        code = strip_line(raw)
        if code.lstrip().startswith("//"):
            continue
        for kind, rx in (("impl", IMPL), ("fn", FN), ("block", BLOCK)):
            for _ in rx.finditer(code):
                sites.append((kind, i + 1, documented(lines, i, kind)))
    return sites


def crates():
    for base in ("crates", "tools"):
        d = os.path.join(ROOT, base)
        for name in sorted(os.listdir(d)):
            if os.path.isfile(os.path.join(d, name, "Cargo.toml")):
                yield name, os.path.join(d, name)


def main():
    markdown = "--markdown" in sys.argv
    check = "--check" in sys.argv
    rows, missing = [], []
    for name, path in crates():
        counts = {"lib": {"block": 0, "fn": 0, "impl": 0}, "other": {"block": 0, "fn": 0, "impl": 0}}
        for dirpath, dirnames, files in os.walk(path):
            dirnames[:] = [d for d in dirnames if d not in ("target",)]
            for fn in files:
                if not fn.endswith(".rs"):
                    continue
                p = os.path.join(dirpath, fn)
                rel = os.path.relpath(p, path)
                part = "lib" if rel.startswith("src" + os.sep) else "other"
                for kind, line, ok in scan(p):
                    counts[part][kind] += 1
                    if not ok:
                        missing.append(f"{os.path.relpath(p, ROOT)}:{line}: unsafe {kind} without "
                                       + ("`# Safety` doc" if kind == "fn" else "`SAFETY:` comment"))
        rows.append((name, counts))

    if markdown:
        print("| Crate | blocks | `unsafe fn` | `unsafe impl` | tests/examples/benches |")
        print("|---|---:|---:|---:|---:|")
    else:
        print(f"{'crate':<16} {'blocks':>6} {'fn':>4} {'impl':>4}   {'tests/examples':>14}")
    tot = {"block": 0, "fn": 0, "impl": 0, "other": 0}
    for name, c in rows:
        other = sum(c["other"].values())
        for k in ("block", "fn", "impl"):
            tot[k] += c["lib"][k]
        tot["other"] += other
        if markdown:
            print(f"| {name} | {c['lib']['block']} | {c['lib']['fn']} | {c['lib']['impl']} | {other} |")
        else:
            print(f"{name:<16} {c['lib']['block']:>6} {c['lib']['fn']:>4} {c['lib']['impl']:>4}   {other:>14}")
    if markdown:
        print(f"| **total** | **{tot['block']}** | **{tot['fn']}** | **{tot['impl']}** | **{tot['other']}** |")
    else:
        print(f"{'total':<16} {tot['block']:>6} {tot['fn']:>4} {tot['impl']:>4}   {tot['other']:>14}")

    for m in missing:
        print(m, file=sys.stderr)
    if check and missing:
        print(f"{len(missing)} undocumented unsafe site(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
