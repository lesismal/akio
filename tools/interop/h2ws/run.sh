#!/usr/bin/env bash
# only-http <-> Go's net/http: WebSocket over HTTP/2 (RFC 8441), both directions, over h2c and
# TLS. Needs Go 1.24 or later (extended CONNECT behind GODEBUG=http2xconnect=1).
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT=${TMPDIR:-/tmp}
cd "$ROOT" && cargo build -q --release -p only-http --example h2-ws-interop
RS=$ROOT/target/release/examples/h2-ws-interop
cd "$ROOT/tools/interop/h2ws" && GOFLAGS=-mod=mod go build -tags http2legacy -o "$OUT/h2ws-go" .
export GODEBUG=http2xconnect=1
"$OUT/h2ws-go" server 127.0.0.1:9420 127.0.0.1:9421 > "$OUT/h2ws-go-server.log" 2>&1 &
GS=$!
"$RS" server 127.0.0.1:9422 127.0.0.1:9423 > "$OUT/h2ws-rust-server.log" 2>&1 &
RSV=$!
trap 'kill $GS $RSV 2>/dev/null || true' EXIT
sleep 1
"$OUT/h2ws-go" client 127.0.0.1:9422 127.0.0.1:9423
"$RS" client 127.0.0.1:9420 127.0.0.1:9421
echo "h2 websocket interop: all passed"
