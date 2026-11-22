#!/usr/bin/env bash
# BoGo, BoringSSL's TLS test suite (ssl/test/runner), against akio-tls through the shim in
# crates/akio-tls/examples/bogo-shim.rs. Needs git, Go (1.27 or later for the pinned BoringSSL)
# and python3:
#
#   tools/interop/tls/bogo.sh [runner flags, e.g. -test 'Basic-*;Resume-*' -num-workers 8]
#
# It builds the shim, clones BoringSSL at a pinned commit into $OUT/boringssl unless
# BORINGSSL_DIR points at a checkout already, builds the runner, runs every test not disabled in
# tools/interop/tls/bogo_config.json and prints a summary: passed, failed, unimplemented (the
# shim exits 89 for a flag asking for something akio-tls does not do or cannot report, which
# the runner counts as a skip) and disabled (the config's DisabledTests, each with its reason:
# whole areas akio-tls does not implement, then single tests that fail for a known reason). The
# run passes when nothing failed. -loose-errors is on: the shim reports akio-tls's own error
# messages, not BoringSSL's error codes, so an expected failure counts whatever the reason.
# The JSON results and the log are in $OUT (default /tmp/bogo-run).
set -u
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT=${OUT:-/tmp/bogo-run}
COMMIT=${BORINGSSL_COMMIT:-ddd732967025c608598b9984a1ada358fa82f6f0}
BSSL=${BORINGSSL_DIR:-$OUT/boringssl}
TARGET=${CARGO_TARGET_DIR:-$ROOT/target}
CONFIG=$ROOT/tools/interop/tls/bogo_config.json
mkdir -p "$OUT"

(cd "$ROOT" && cargo build -q --release -p akio-tls --example bogo-shim) || exit 1
SHIM=$TARGET/release/examples/bogo-shim

if [ ! -d "$BSSL/ssl/test/runner" ]; then
    git init -q "$BSSL" &&
        git -C "$BSSL" fetch -q --depth 1 https://github.com/google/boringssl "$COMMIT" &&
        git -C "$BSSL" checkout -q FETCH_HEAD || exit 1
fi
RUNNER=$OUT/runner.test
if [ ! -x "$RUNNER" ] || [ "$BSSL/ssl/test/runner/runner.go" -nt "$RUNNER" ]; then
    (cd "$BSSL/ssl/test/runner" && go test -c -o "$RUNNER" .) || exit 1
fi

# The runner reads its certificates relative to its own directory.
cd "$BSSL/ssl/test/runner" || exit 1
"$RUNNER" -test.run TestAll -test.timeout 0 -shim-path "$SHIM" -shim-config "$CONFIG" \
    -allow-unimplemented -loose-errors -pipe=false -json-output "$OUT/results.json" "$@" \
    > "$OUT/runner.log" 2>&1
grep -a -A8 '^FAILED' "$OUT/runner.log" | head -200

python3 - "$OUT/results.json" "$OUT/runner.log" <<'EOF'
import json, re, sys
tests = json.load(open(sys.argv[1]))["tests"]
count = {"PASS": 0, "FAIL": 0, "SKIP": 0}
for r in tests.values():
    count[r["actual"]] = count.get(r["actual"], 0) + 1
# The runner's last status line ends with the number of tests, disabled ones included.
status = re.findall(r"(\d+)/(\d+)/(\d+)/(\d+)/(\d+)", open(sys.argv[2], errors="replace").read())
total = int(status[-1][4]) if status else len(tests)
ran = sum(count.values())
print(f"BoGo: {count['PASS']} passed, {count['FAIL']} failed, {count['SKIP']} unimplemented, "
      f"{total - ran} disabled (or not selected), {total} tests")
sys.exit(1 if count["FAIL"] else 0)
EOF
