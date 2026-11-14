#!/usr/bin/env bash
# only-h3 <-> quic-go's http3 and fib's own QUIC/HTTP/3, both directions. Needs Go and the
# fib checkout next to this repository.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT" && cargo build -q --release -p only-h3 --example h3-interop
RS=$ROOT/target/release/examples/h3-interop
cd "$ROOT/tools/interop/h3" && GOFLAGS=-mod=mod go build -o /tmp/h3-go .
cd "$ROOT/tools/interop/h3/fib" && GOFLAGS=-mod=mod go build -o /tmp/h3-fib .
/tmp/h3-go server 127.0.0.1:9400 > /tmp/h3-go-server.log 2>&1 &
GS=$!
"$RS" server 127.0.0.1:9401 > /tmp/h3-rust-server.log 2>&1 &
RSV=$!
/tmp/h3-fib server 127.0.0.1:9402 > /tmp/h3-fib-server.log 2>&1 &
FS=$!
trap 'kill $GS $RSV $FS 2>/dev/null || true' EXIT
sleep 1
/tmp/h3-go client 127.0.0.1:9401
"$RS" client 127.0.0.1:9400
/tmp/h3-fib client 127.0.0.1:9401
"$RS" client-fib 127.0.0.1:9402
echo "h3 interop: all passed"
