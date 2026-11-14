#!/usr/bin/env bash
# only-grpc <-> grpc-go, both directions. Needs Go (fetches google.golang.org/grpc and its
# examples module). The raw-bytes half also runs over TLS (only-tls <-> Go crypto/tls). Two halves:
#   raw bytes:  only-grpc's grpc-interop example <-> the test.Echo methods;
#   protobuf:   only-protobuf messages and only-protobuf-build stubs (tools/protobuf-test,
#               pb-interop) <-> grpc-go's generated route_guide / helloworld code and the
#               well-known types of google.golang.org/protobuf.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT" && cargo build -q --release -p only-grpc --example grpc-interop &&
    cargo build -q --release -p protobuf-test --example pb-interop
BIN=$ROOT/target/release/examples/grpc-interop
PB=$ROOT/target/release/examples/pb-interop
cd "$ROOT/tools/interop/grpc" && GOFLAGS=-mod=mod go build -o /tmp/grpc-go .
"$BIN" server 127.0.0.1:9201 > /tmp/grpc-rust-server.log 2>&1 &
RS=$!
"$PB" server 127.0.0.1:9203 > /tmp/grpc-rust-pb-server.log 2>&1 &
PS=$!
/tmp/grpc-go server 127.0.0.1:9200 > /tmp/grpc-go-server.log 2>&1 &
GS=$!
"$BIN" server 127.0.0.1:9211 tls > /tmp/grpc-rust-tls-server.log 2>&1 &
RT=$!
/tmp/grpc-go server 127.0.0.1:9210 tls > /tmp/grpc-go-tls-server.log 2>&1 &
GT=$!
trap 'kill $RS $PS $GS $RT $GT 2>/dev/null || true' EXIT
sleep 1
echo "grpc-go client -> only server:"; /tmp/grpc-go client 127.0.0.1:9201
echo "only client -> grpc-go server:"; "$BIN" client 127.0.0.1:9200
echo "grpc-go client -> only server over TLS (only-tls, ALPN h2):"; /tmp/grpc-go client 127.0.0.1:9211 tls
echo "only client -> grpc-go server over TLS (only-tls, ALPN h2):"; "$BIN" client 127.0.0.1:9210 tls
grep -q "x-user=gopher" /tmp/grpc-rust-server.log && echo "metadata from grpc-go arrived"
echo "grpc-go generated stubs -> only-protobuf server:"; /tmp/grpc-go pbclient 127.0.0.1:9203
echo "only-protobuf stubs -> grpc-go server:"; "$PB" client 127.0.0.1:9200
