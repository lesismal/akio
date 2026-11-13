#!/usr/bin/env bash
# flash-grpc <-> grpc-go, both directions. Needs Go (fetches google.golang.org/grpc).
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT" && cargo build -q --release -p flash-grpc --example grpc-interop
BIN=$ROOT/target/release/examples/grpc-interop
cd "$ROOT/tools/interop/grpc" && GOFLAGS=-mod=mod go build -o /tmp/grpc-go .
"$BIN" server 127.0.0.1:9201 > /tmp/grpc-rust-server.log 2>&1 &
RS=$!
/tmp/grpc-go server 127.0.0.1:9200 > /tmp/grpc-go-server.log 2>&1 &
GS=$!
trap 'kill $RS $GS 2>/dev/null || true' EXIT
sleep 1
echo "grpc-go client -> flash server:"; /tmp/grpc-go client 127.0.0.1:9201
echo "flash client -> grpc-go server:"; "$BIN" client 127.0.0.1:9200
grep -q "x-user=gopher" /tmp/grpc-rust-server.log && echo "metadata from grpc-go arrived"
