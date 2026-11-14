#!/usr/bin/env bash
# Runs h2spec (strict) against only's HTTP/2 server (examples/h2-server).
# Needs docker and a built `h2-server` example. On macOS the container reaches the host through
# host.docker.internal; on Linux it shares the host network.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
if [ "$(uname -s)" = Darwin ]; then HOST=host.docker.internal; NET=""; else HOST=127.0.0.1; NET="--network host"; fi
"${H2_SERVER:-$ROOT/target/release/examples/h2-server}" 0.0.0.0:8082 > /tmp/h2-server.log 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
sleep 1
# shellcheck disable=SC2086
docker run --rm $NET summerwind/h2spec -h "$HOST" -p 8082 -o 3 -S | tee /tmp/h2spec.out
grep -q " 0 failed" /tmp/h2spec.out
