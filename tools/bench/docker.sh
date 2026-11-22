#!/usr/bin/env bash
# Runs a command in the akio-bench image with the repository at /w, fib at /fib, cached cargo
# registry / target / Go module volumes, raised descriptor limits and loopback-friendly sysctls.
#
#   tools/bench/docker.sh 'tools/bench/build.sh && tools/bench/http.sh'
#
#   FIB_DIR   host path of the fib checkout (default: ../fib next to the main checkout of this repository)
#   PRIV=1    run privileged (needed for perf and io_uring on some hosts)
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
FIB_DIR=${FIB_DIR:-$(cd "$ROOT" && git rev-parse --path-format=absolute --git-common-dir | xargs dirname)/../fib}
extra=()
[ "${PRIV:-0}" = 1 ] && extra+=(--privileged)
[ -d "$FIB_DIR" ] && extra+=(-v "$FIB_DIR":/fib:ro)
exec docker run --rm "${extra[@]}" \
  -v "$ROOT":/w -w /w \
  -v akio-cargo-reg:/usr/local/cargo/registry \
  -v akio-bench-target:/tmp/t -e CARGO_TARGET_DIR=/tmp/t -e RUSTUP_TOOLCHAIN=stable \
  -v akio-bench-gomod:/root/go/pkg/mod \
  --ulimit nofile=1048576:1048576 \
  --sysctl net.ipv4.ip_local_port_range="10000 65535" \
  --sysctl net.ipv4.tcp_tw_reuse=1 \
  --sysctl net.core.somaxconn=65535 \
  --sysctl net.ipv4.tcp_max_syn_backlog=65535 \
  akio-bench bash -c "$1"
