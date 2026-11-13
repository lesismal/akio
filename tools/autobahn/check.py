#!/usr/bin/env python3
"""Fails unless every Autobahn case in <reports>/index.json behaved OK (or INFORMATIONAL).

usage: check.py <reports-dir> [agent]
"""
import collections
import json
import sys

reports = sys.argv[1]
index = json.load(open(f"{reports}/index.json"))
agents = [sys.argv[2]] if len(sys.argv) > 2 else list(index)
bad = 0
for agent in agents:
    cases = index[agent]
    counts = collections.Counter(c["behavior"] for c in cases.values())
    print(f"{agent}: {len(cases)} cases {dict(counts)}")
    for name, c in sorted(cases.items()):
        ok = ("OK", "INFORMATIONAL")
        if c["behavior"] not in ok or c["behaviorClose"] not in ok:
            print(f"  {name}: behavior={c['behavior']} close={c['behaviorClose']}")
            bad += 1
sys.exit(1 if bad else 0)
