#!/usr/bin/env bash
# only-arpc <-> fib's Go arpc, both directions. Needs Go and the fib checkout next to this repository.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT" && cargo build -q --release -p only-arpc --example arpc-interop
BIN=$ROOT/target/release/examples/arpc-interop
cd "$ROOT/tools/interop/arpc" && GOFLAGS=-mod=mod go build -o /tmp/arpc-go .
"$BIN" server 127.0.0.1:9101 > /tmp/arpc-rust-server.log 2>&1 &
RS=$!
/tmp/arpc-go server 127.0.0.1:9100 > /tmp/arpc-go-server.log 2>&1 &
GS=$!
trap 'kill $RS $GS 2>/dev/null || true' EXIT
sleep 1
echo "Go client -> only server:"; /tmp/arpc-go client 127.0.0.1:9101
echo "only client -> Go server:"; "$BIN" client 127.0.0.1:9100
grep -q "note from go" /tmp/arpc-rust-server.log && echo "notify from Go arrived"
