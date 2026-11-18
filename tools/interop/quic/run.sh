#!/usr/bin/env bash
# only-quic <-> quic-go raw QUIC, both directions: an echo of 50 concurrent streams and 20
# datagrams; then with Retry address validation on the server, 1-RTT key updates started by
# only-quic every 5000 packets, and a 150 MB stream (which also crosses quic-go's own key update
# interval of 100k packets); then QUIC version 2 both ways, client migration to a new socket
# both ways (only-quic's with BBR), 0-RTT both ways (v1, and v2 kept short), and, on Linux and
# macOS, ECN validated against quic-go. Then servers preferring the other version (compatible version
# negotiation, RFC 9368 section 4): quic-go does not implement RFC 9368 (it sends no
# version_information and drops packets of another version), so its clients must keep the
# version they started in; only-quic's own client follows the switch over real UDP sockets
# (ngtcp2, which implements it, is in ngtcp2-cvn.sh). Needs Go.
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
"$GO" server 127.0.0.1:9506 0rtt > "$LOG/quic-go-server-0rtt.log" 2>&1 &
G4=$!
"$RS" server 127.0.0.1:9507 0rtt > "$LOG/quic-rust-server-0rtt.log" 2>&1 &
R4=$!
"$GO" server 127.0.0.1:9508 v2 0rtt > "$LOG/quic-go-server-v2-0rtt.log" 2>&1 &
G5=$!
"$RS" server 127.0.0.1:9509 v2 0rtt > "$LOG/quic-rust-server-v2-0rtt.log" 2>&1 &
R5=$!
"$RS" server 127.0.0.1:9511 prefer-v2 0rtt > "$LOG/quic-rust-server-prefer-v2.log" 2>&1 &
R6=$!
"$RS" server 127.0.0.1:9513 prefer-v1 > "$LOG/quic-rust-server-prefer-v1.log" 2>&1 &
R7=$!
trap 'kill $G1 $G2 $G3 $G4 $G5 $R1 $R2 $R3 $R4 $R5 $R6 $R7 2>/dev/null || true' EXIT
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
# 0-RTT: each client resumes a first connection's session and sends a stream before the
# handshake completes; it fails unless the server accepted 0-RTT (and the server logs it).
echo "== quic-go client -> only-quic server (0-RTT)"
"$GO" client 127.0.0.1:9507 0rtt
grep -q "0-RTT stream" "$LOG/quic-rust-server-0rtt.log" || { echo "FAIL: no 0-RTT stream on only-quic"; exit 1; }
echo "== only-quic client -> quic-go server (0-RTT)"
"$RS" client 127.0.0.1:9506 0rtt
grep -q "0-RTT used" "$LOG/quic-go-server-0rtt.log" || { echo "FAIL: no 0-RTT on quic-go"; exit 1; }
echo "== quic-go client -> only-quic server (0-RTT, QUIC v2)"
"$GO" client 127.0.0.1:9509 0rtt v2 small
grep -q "0-RTT stream" "$LOG/quic-rust-server-v2-0rtt.log" || { echo "FAIL: no v2 0-RTT stream on only-quic"; exit 1; }
echo "== only-quic client -> quic-go server (0-RTT, QUIC v2)"
"$RS" client 127.0.0.1:9508 0rtt v2 small
grep -q "0-RTT used" "$LOG/quic-go-server-v2-0rtt.log" || { echo "FAIL: no v2 0-RTT on quic-go"; exit 1; }
echo "== quic-go client (v1) -> only-quic server preferring v2: stays in v1, 0-RTT too"
"$GO" client 127.0.0.1:9511
"$GO" client 127.0.0.1:9511 0rtt
grep -q "connected in V1" "$LOG/quic-rust-server-prefer-v2.log" || { echo "FAIL: quic-go client not in v1"; exit 1; }
! grep -q "connected in V2" "$LOG/quic-rust-server-prefer-v2.log" || { echo "FAIL: quic-go client moved to v2"; exit 1; }
echo "== quic-go client (v2 only) -> only-quic server preferring v1: stays in v2"
"$GO" client 127.0.0.1:9513 v2 small
grep -q "connected in V2" "$LOG/quic-rust-server-prefer-v1.log" || { echo "FAIL: quic-go v2 client not in v2"; exit 1; }
echo "== only-quic client (v1) -> only-quic server preferring v2: moved to v2; resumed in v2 with the v2 ticket, 0-RTT"
"$RS" client 127.0.0.1:9511 expect-v2 bulk 20
"$RS" client 127.0.0.1:9511 expect-v2 0rtt small
echo "== only-quic client (v2) -> only-quic server preferring v1: moved to v1"
"$RS" client 127.0.0.1:9513 v2 expect-v1
if [ "$(uname)" = Linux ] || [ "$(uname)" = Darwin ]; then
    echo "== only-quic client -> quic-go server (ECN validated)"
    "$RS" client 127.0.0.1:9500 ecn
fi
echo "quic interop: all passed"
