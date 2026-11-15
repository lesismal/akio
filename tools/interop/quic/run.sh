#!/usr/bin/env bash
# only-quic <-> quic-go raw QUIC, both directions: an echo of 50 concurrent streams and 20
# datagrams; then with Retry address validation on the server, 1-RTT key updates started by
# only-quic every 5000 packets, and a 150 MB stream (which also crosses quic-go's own key update
# interval of 100k packets); then QUIC version 2 both ways, client migration to a new socket
# both ways (only-quic's with BBR), and, on Linux, ECN validated against quic-go. Needs Go.
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
"$GO" server 127.0.0.1:9504 v2 > "$LOG/quic-go-server-v2.log" 2>&1 &
G3=$!
"$RS" server 127.0.0.1:9505 v2 > "$LOG/quic-rust-server-v2.log" 2>&1 &
R3=$!
trap 'kill $G1 $G2 $G3 $R1 $R2 $R3 2>/dev/null || true' EXIT
sleep 1
echo "== quic-go client -> only-quic server"
"$GO" client 127.0.0.1:9501
echo "== only-quic client -> quic-go server"
"$RS" client 127.0.0.1:9500
echo "== quic-go client -> only-quic server (Retry, key updates, 150 MB)"
"$GO" client 127.0.0.1:9503 bulk 150
echo "== only-quic client -> quic-go server (Retry, key updates, 150 MB)"
"$RS" client 127.0.0.1:9502 bulk 150 ku 5000
# quic-go derives QUIC v2 key update secrets with the v1 label "quic ku" (RFC 9369 3.3.2 says
# "quicv2 ku", as its test vector A.5 shows) and starts its first key update after 100 packets:
# the v2 runs stay below that ("small").
echo "== quic-go client -> only-quic server (QUIC v2 only)"
"$GO" client 127.0.0.1:9505 v2 small
echo "== only-quic client -> quic-go server (QUIC v2 only)"
"$RS" client 127.0.0.1:9504 v2 small
echo "== quic-go client migrating -> only-quic server"
"$GO" client 127.0.0.1:9501 migrate
echo "== only-quic client migrating (BBR) -> quic-go server"
"$RS" client 127.0.0.1:9500 migrate bbr bulk 20
if [ "$(uname)" = Linux ]; then
    echo "== only-quic client -> quic-go server (ECN validated)"
    "$RS" client 127.0.0.1:9500 ecn
fi
echo "quic interop: all passed"
