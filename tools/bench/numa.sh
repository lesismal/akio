#!/usr/bin/env bash
# NUMA placement A/B (ADR-088): the same akio server with AKIO_NUMA unset (the default: no
# placement) and in each mode of $MODES, rounds interleaved, a fresh server per run.
#
#   tools/bench/numa.sh                      # MODES="off spread spread+cpu spread+cpu+incoming"
#   MODES="off nodes:1+cpu" KIND=akio-uring tools/bench/numa.sh
#
# Cases: HTTP/1.1 /plaintext (256 connections) and pipelined 16 deep, h2c 64 x 16 (h2load),
# TCP echo 64 B x 256 connections (echo-bench). The server runs on $SRV_CPUS with $THREADS
# threads (lib.sh); placement works inside that set (the CPUs the process may use). Needs
# http-bench, bench-server and echo-bench built into $CARGO_TARGET_DIR (build.sh, or
# `cargo build --release -p akio-http --example http-bench -p akio --example bench-server`
# and `cargo build --release` in tools/echo-bench).
set -u
. "$(dirname "$0")/lib.sh"
OUT=${OUT:-/tmp/bench-numa.tsv}
MODES=${MODES:-"off spread spread+cpu spread+cpu+incoming"}
KIND=${KIND:-akio-epoll}
HCONNS=${HCONNS:-256}

h2load_rps() { # <path> [h2load args...]
  local path=$1
  shift
  cli h2load -D "$SECS" -t "$CLI_THREADS" "$@" "http://127.0.0.1:$PORT$path" 2>/dev/null |
    awk '/^finished in/{for(i=1;i<=NF;i++) if($i=="req/s,") print int($(i-1))}'
}

echo "# $(uname -sr), $(nproc) CPUs; $KIND on $SRV_CPUS ($THREADS threads), client on $CLI_CPUS; ${SECS}s x $RUNS rounds; modes: $MODES" >&2
for r in $(seq "$RUNS"); do
  for mode in $MODES; do
    if [ "$mode" = off ]; then unset AKIO_NUMA; else export AKIO_NUMA=$mode; fi
    start_server "$KIND" http
    cli h2load -D 1 -c 16 -t 2 --h1 "http://127.0.0.1:$PORT/plaintext" >/dev/null 2>&1 # warm-up
    record numa "h1 plaintext x $HCONNS" "$mode" "$r" "$(h2load_rps /plaintext --h1 -c "$HCONNS")"
    record numa "h1 pipelined 16 x $HCONNS" "$mode" "$r" "$(h2load_rps /plaintext --h1 -c "$HCONNS" -m 16)"
    record numa "h2c 64 x 16" "$mode" "$r" "$(h2load_rps /plaintext -c 64 -m 16)"
    stop_server
    start_server "$KIND" tcp
    v=$(cli "$ECHO_BENCH" "127.0.0.1:$PORT" 256 64 "$SECS" "$CLI_THREADS" tcp 2>/dev/null | field req/s)
    record numa "tcp echo 64B x 256" "$mode" "$r" "${v:-FAILED}"
    stop_server
  done
done
unset AKIO_NUMA
