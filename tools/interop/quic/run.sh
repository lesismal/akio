#!/usr/bin/env bash
# only-quic <-> quic-go raw QUIC, both directions: an echo of 50 concurrent streams and 20
# datagrams; then with Retry address validation on the server, 1-RTT key updates started by
# only-quic every 5000 packets, and a 150 MB stream (which also crosses quic-go's own key update
# interval of 100k packets). Needs Go.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT" && cargo build -q --release -p only-quic --example quic-interop
RS=$ROOT/target/release/examples/quic-interop
GO=${TMPDIR:-/tmp}/quic-go-echo
cd "$ROOT/tools/interop/quic" && GOFLAGS=-mod=mod go build -o "$GO" .
LOG=${TMPDIR:-/tmp}
"$GO" server 127.0.0.1:9500 > "$LOG/quic-go-server.log" 2>&1 &
G1=$!
"$GO" server 127.0.0.1:9502 retry > "$LOG/quic-go-server-retry.log" 2>&1 &
G2=$!
"$RS" server 127.0.0.1:9501 > "$LOG/quic-rust-server.log" 2>&1 &
R1=$!
"$RS" server 127.0.0.1:9503 retry ku 5000 > "$LOG/quic-rust-server-retry.log" 2>&1 &
R2=$!
trap 'kill $G1 $G2 $R1 $R2 2>/dev/null || true' EXIT
sleep 1
echo "== quic-go client -> only-quic server"
"$GO" client 127.0.0.1:9501
echo "== only-quic client -> quic-go server"
"$RS" client 127.0.0.1:9500
echo "== quic-go client -> only-quic server (Retry, key updates, 150 MB)"
"$GO" client 127.0.0.1:9503 bulk 150
echo "== only-quic client -> quic-go server (Retry, key updates, 150 MB)"
"$RS" client 127.0.0.1:9502 bulk 150 ku 5000
echo "quic interop: all passed"
