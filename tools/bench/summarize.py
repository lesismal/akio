#!/usr/bin/env python3
"""Turns the TSV rows of the benchmark scripts into Markdown tables.

    tools/bench/summarize.py /tmp/bench-echo.tsv [/tmp/bench-http.tsv ...]

Rows are `suite<TAB>case<TAB>server<TAB>round<TAB>value`. Each cell is the median over rounds,
followed by the spread (min-max as a percentage of the median) when there is more than one round.
"""
import statistics
import sys
from collections import OrderedDict

ORDER = ["akio-epoll", "akio-uring", "tokio", "hyper", "monoio-uring", "monoio-epoll", "fib"]


def main():
    data = OrderedDict()
    for path in sys.argv[1:]:
        for line in open(path):
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 5:
                continue
            suite, case, kind, _round, value = parts
            try:
                v = float(value)
            except ValueError:
                continue
            data.setdefault(suite, OrderedDict()).setdefault(case, {}).setdefault(kind, []).append(v)
    for suite, cases in data.items():
        kinds = [k for k in ORDER if any(k in c for c in cases.values())]
        kinds += sorted({k for c in cases.values() for k in c} - set(kinds))
        print(f"\n### {suite}\n")
        print("| case | " + " | ".join(kinds) + " |")
        print("|---|" + "---:|" * len(kinds))
        for case, by_kind in cases.items():
            cells = []
            for k in kinds:
                vs = by_kind.get(k)
                if not vs:
                    cells.append("")
                    continue
                m = statistics.median(vs)
                cell = f"{m:,.0f}"
                if len(vs) > 1 and m:
                    cell += f" (±{(max(vs) - min(vs)) / m * 50:.0f}%)"
                cells.append(cell)
            print(f"| {case} | " + " | ".join(cells) + " |")


if __name__ == "__main__":
    main()
