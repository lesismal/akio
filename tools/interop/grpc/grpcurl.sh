#!/usr/bin/env bash
# grpcurl (fullstorydev/grpcurl, built with Go) against only-grpc's server reflection: lists the
# services of the pb-interop server, describes them and their messages, and calls methods with
# JSON requests, all from the descriptors the server sends (no .proto files on grpcurl's side).
#   tools/interop/grpc/grpcurl.sh
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT" && cargo build -q --release -p protobuf-test --example pb-interop
PB=$ROOT/target/release/examples/pb-interop
PORT=${PORT:-9231}
"$PB" server 127.0.0.1:$PORT > /tmp/grpcurl-only-server.log 2>&1 &
S=$!
trap 'kill $S 2>/dev/null || true' EXIT
sleep 1
# grpcurl v1.9.3 with the newest Go protobuf runtime (the release binaries predate edition 2024).
G=/tmp/grpcurl-only
if [ ! -x "$G" ]; then
    B=$(mktemp -d)
    (cd "$B" && printf 'module grpcurlbuild\n\ngo 1.24\n' >go.mod &&
        printf '//go:build tools\n\npackage tools\n\nimport _ "github.com/fullstorydev/grpcurl/cmd/grpcurl"\n' >tools.go &&
        GOFLAGS=-mod=mod go get github.com/fullstorydev/grpcurl/cmd/grpcurl@v1.9.3 google.golang.org/protobuf@latest &&
        GOFLAGS=-mod=mod go build -o "$G" github.com/fullstorydev/grpcurl/cmd/grpcurl)
fi
HOST=127.0.0.1
g() { "$G" -plaintext "$@"; }
set -x
g "$HOST:$PORT" list
g "$HOST:$PORT" list routeguide.RouteGuide
g "$HOST:$PORT" describe routeguide.RouteGuide
g "$HOST:$PORT" describe routeguide.Feature
g "$HOST:$PORT" describe helloworld.HelloRequest
g -d '{"name": "grpcurl"}' "$HOST:$PORT" helloworld.Greeter/SayHello
g -d '{"latitude": 3, "longitude": 4}' "$HOST:$PORT" routeguide.RouteGuide/GetFeature
g -d '{"lo": {"latitude": 1, "longitude": 1}, "hi": {"latitude": 2, "longitude": 2}}' "$HOST:$PORT" routeguide.RouteGuide/ListFeatures
g -use-reflection "$HOST:$PORT" describe grpc.reflection.v1.ServerReflection
# Descriptors Go's protodesc must accept (it validates them): proto2 groups, extensions, closed
# enums, defaults; edition 2024 features and visibility; proto3 optional and the WKTs.
g "$HOST:$PORT" describe test.ext.Base
g "$HOST:$PORT" describe test.ext.level
g "$HOST:$PORT" describe test.ed.Item
g "$HOST:$PORT" describe protobuf_test_messages.proto3.TestAllTypesProto3
g -d '{"id": 7, "meta": {"note": "n"}, "levels": ["HIGH"], "[test.ext.level]": "LOW", "[test.ext.tags]": [1, 2], "[test.ext.at]": "2024-01-02T03:04:05Z"}' "$HOST:$PORT" test.ext.Ext/Echo
g -d '{"id": 1, "name": "", "inner": {"v": 2}, "codes": [1, 2], "kind": "KIND_A", "byName": {"k": {"v": 3}}, "nested": {}}' "$HOST:$PORT" test.ed.Items/Get
set +x
echo "grpcurl against only-grpc reflection: OK"
