#!/usr/bin/env bash
# Line coverage of the workspace with cargo-llvm-cov, both I/O backends merged into one report.
#   tools/coverage/run.sh            -> target/coverage/{lcov.info,coverage.json,summary.md}
# Linux only for the io_uring half (skipped elsewhere). Needs cargo-llvm-cov and the
# llvm-tools-preview rustup component. Tests run one at a time, as in CI.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
OUT=${OUT:-$ROOT/target/coverage}
mkdir -p "$OUT"
# Test, example and tool code is not what we measure.
IGNORE='(/tests/|/examples/|/benches/|tools/)'

cargo llvm-cov clean --workspace
echo "== tests, epoll/kqueue backend"
cargo llvm-cov --no-report --workspace -- --test-threads=1
if [ "$(uname -s)" = Linux ]; then
  # The crates whose tests honour AKIO_TEST_BACKEND.
  echo "== tests, io_uring backend"
  AKIO_TEST_BACKEND=uring cargo llvm-cov --no-report -p akio -p akio-http -p akio-ws \
    -- --test-threads=1
fi
cargo llvm-cov report --lcov --output-path "$OUT/lcov.info" --ignore-filename-regex "$IGNORE"
cargo llvm-cov report --json --summary-only --output-path "$OUT/coverage.json" \
  --ignore-filename-regex "$IGNORE"
python3 "$ROOT/tools/coverage/summary.py" "$OUT/coverage.json" | tee "$OUT/summary.md"
