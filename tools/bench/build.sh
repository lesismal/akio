#!/usr/bin/env bash
# Builds everything the benchmark scripts run, in release mode, into $CARGO_TARGET_DIR (default
# /tmp/t). Meant to run inside the flash-bench image (tools/bench/Dockerfile), see docker.sh.
#
#   FIB_SRC  checkout of fib (default /fib); fib-ref is skipped when it is missing.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
T=${CARGO_TARGET_DIR:-/tmp/t}
export CARGO_TARGET_DIR=$T
cd "$ROOT"
cargo build -q --release -p echo-bench --features tls
cargo build -q --release -p flash --example bench-server
cargo build -q --release -p flash-http --example http-bench
# Reference servers: separate workspaces, built into $T/ref so no target/ lands under tools/.
for r in tokio-ref hyper-ref; do
  (cd tools/bench-ref/$r && CARGO_TARGET_DIR=$T/ref cargo build -q --release)
done
FIB_SRC=${FIB_SRC:-/fib}
if [ -d "$FIB_SRC" ] && command -v go >/dev/null; then
  rm -rf /tmp/fibref && cp -r tools/bench-ref/fib-ref /tmp/fibref
  (cd /tmp/fibref && go mod edit -replace "github.com/lesismal/fib=$FIB_SRC" && go mod tidy >/dev/null 2>&1 &&
    go build -o "$T/fib-ref" .)
fi
ls -1 "$T"/release/echo-bench "$T"/release/examples/{bench-server,http-bench} "$T"/ref/release/{tokio-ref,hyper-ref} "$T"/fib-ref 2>&1
