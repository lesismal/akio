#!/usr/bin/env bash
# akio-arpc <-> fib's Go arpc, both directions: plain, then with the gzip and trace-value coders,
# middleware that needs the value and client pools. Needs Go and a fib checkout (FIB_DIR, by
# default the one next to the main checkout of this repository).
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
FIB=${FIB_DIR:-$(cd "$(git -C "$ROOT" rev-parse --git-common-dir)/../.." && pwd)/fib}
OUT=${TMPDIR:-/tmp}/akio-arpc-interop
mkdir -p "$OUT"
cd "$ROOT" && cargo build -q --release -p akio-arpc --example arpc-interop
BIN=$ROOT/target/release/examples/arpc-interop
# Build from a copy whose go.mod points at $FIB.
rm -rf "$OUT/go" && cp -R "$ROOT/tools/interop/arpc" "$OUT/go"
(cd "$OUT/go" && go mod edit -replace "github.com/lesismal/fib=$FIB" && GOFLAGS=-mod=mod go build -o "$OUT/arpc-go" .)
"$BIN" server 127.0.0.1:9101 > "$OUT/rust-server.log" 2>&1 &
RS=$!
"$OUT/arpc-go" server 127.0.0.1:9100 > "$OUT/go-server.log" 2>&1 &
GS=$!
"$BIN" server-coded 127.0.0.1:9103 > "$OUT/rust-coded.log" 2>&1 &
RC=$!
"$OUT/arpc-go" server-coded 127.0.0.1:9102 > "$OUT/go-coded.log" 2>&1 &
GC=$!
trap 'kill $RS $GS $RC $GC 2>/dev/null || true' EXIT
sleep 1
echo "Go client -> akio server:"; "$OUT/arpc-go" client 127.0.0.1:9101
echo "akio client -> Go server:"; "$BIN" client 127.0.0.1:9100
grep -q "note from go" "$OUT/rust-server.log" && echo "notify from Go arrived"
echo "Go pool, coders -> akio server:"; "$OUT/arpc-go" client-coded 127.0.0.1:9103
echo "akio pool, coders -> Go server:"; "$BIN" client-coded 127.0.0.1:9102
grep -q 'coded notify: 1300 bytes, trace Some("from go")' "$OUT/rust-coded.log" && echo "coded notify from Go arrived"
