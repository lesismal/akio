#!/usr/bin/env bash
# Line/region coverage of each fuzz target's corpus over the only sources (dependencies and the
# fuzzing harnesses excluded). Needs nightly, cargo-fuzz and llvm-tools-preview.
#
#   fuzz/coverage.sh [target...]     # prints "<target> lines% regions% functions%"
set -eu
cd "$(dirname "$0")"
TOOLCHAIN=${TOOLCHAIN:-+nightly}
HOST=$(rustc $TOOLCHAIN -vV | sed -n 's/^host: //p')
SYSROOT=$(rustc $TOOLCHAIN --print sysroot)
COV=$(find "$SYSROOT" -name llvm-cov -type f | head -1)
IGNORE='(\.cargo|rustc|/registry/|/fuzzing\.rs|fuzz_targets)'
for t in ${@:-$(cargo $TOOLCHAIN fuzz list)}; do
    cargo $TOOLCHAIN fuzz coverage "$t" "corpus/$t" >/dev/null 2>&1
    bin=target/$HOST/coverage/$HOST/release/$t
    "$COV" report "$bin" -instr-profile="coverage/$t/coverage.profdata" \
        -ignore-filename-regex="$IGNORE" >"coverage/$t/report.txt"
    awk -v t="$t" '/^TOTAL/ {print t, "lines", $10, "regions", $4, "functions", $7}' \
        "coverage/$t/report.txt"
done
