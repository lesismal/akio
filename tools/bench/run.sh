#!/usr/bin/env bash
# Benchmark driver for docs/BENCHMARKS.md. Runs on Linux (the docs used a Docker VM).
#
#   tools/bench/run.sh [--secs N] [--runs N] [--only tcp,tls,udp,block]
#
# Needs: cargo, taskset, and the reference servers built where the variables below point:
#   FIB_REF   fib-ref binary (optional; skipped when missing)
#   TOKIO_REF tokio-ref binary (optional)
# The server is pinned to CPUs $SRV_CPUS (default 0-3, four threads) and the load generator to
# $CLI_CPUS (default 4-11), so they do not fight for cores. Every figure is the median of --runs.
set -u
SECS=5; RUNS=3; ONLY=tcp,tls,udp,block
while [ $# -gt 0 ]; do
  case $1 in
    --secs) SECS=$2; shift 2;;
    --runs) RUNS=$2; shift 2;;
    --only) ONLY=$2; shift 2;;
    *) echo "unknown option $1"; exit 2;;
  esac
done
SRV_CPUS=${SRV_CPUS:-0-3}; CLI_CPUS=${CLI_CPUS:-4-11}; THREADS=${THREADS:-4}; CLI_THREADS=${CLI_THREADS:-8}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TARGET=${CARGO_TARGET_DIR:-$ROOT/target}
FLASH=$TARGET/release/examples/bench-server
BENCH=$TARGET/release/echo-bench
FIB_REF=${FIB_REF:-}; TOKIO_REF=${TOKIO_REF:-}
want() { case ",$ONLY," in *",$1,"*) return 0;; esac; return 1; }

PORT=7300
measure() { # <mode> <conns> <size> -> median req/s
  local mode=$1 conns=$2 size=$3
  taskset -c "$CLI_CPUS" "$BENCH" 127.0.0.1:$PORT 8 1 1 4 "$mode" >/dev/null 2>&1 # warm-up, discarded
  for _ in $(seq "$RUNS"); do
    taskset -c "$CLI_CPUS" "$BENCH" 127.0.0.1:$PORT "$conns" "$size" "$SECS" "$CLI_THREADS" "$mode" 2>/dev/null |
      awk '{for(i=1;i<=NF;i++) if($i=="req/s") print $(i-1)}'
  done | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'
}

launch() { # <kind> <proto> <handler> <ms>   (runs the server in the foreground)
  local kind=$1 proto=$2 handler=$3 ms=$4 addr=127.0.0.1:$PORT
  case $kind in
    flash-epoll) exec "$FLASH" "$proto" "$addr" "$THREADS" epoll "$handler" "$ms";;
    flash-uring) exec "$FLASH" "$proto" "$addr" "$THREADS" uring "$handler" "$ms";;
    tokio) exec "$TOKIO_REF" "$proto" "$addr" "$THREADS" "$handler" "$ms";;
    fib) exec "$FIB_REF" "$proto" "$addr" "$([ "$handler" = echo ] && echo echo || echo block)" "$ms";;
  esac
}

kinds() { # <proto> -> the servers that can run it
  local k="flash-epoll"
  case $1 in tcp|tls) k="$k flash-uring";; esac
  [ -x "$TOKIO_REF" ] && k="$k tokio"
  [ -x "$FIB_REF" ] && [ "$1" != tls ] && k="$k fib"
  echo "$k"
}

run_matrix() { # <mode> <proto> <handler> <ms> <conns> <size>
  local mode=$1 proto=$2 handler=$3 ms=$4 conns=$5 size=$6 kind
  for kind in $(kinds "$proto"); do
    PORT=$((PORT+1))
    taskset -c "$SRV_CPUS" bash -c "$(declare -f launch); FLASH=$FLASH TOKIO_REF=$TOKIO_REF FIB_REF=$FIB_REF THREADS=$THREADS PORT=$PORT; launch $kind $proto $handler $ms" >/dev/null 2>&1 &
    local pid=$!
    sleep 1.5
    local r; r=$(measure "$mode" "$conns" "$size")
    kill "$pid" 2>/dev/null; pkill -P "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    printf '%-4s %-12s %-12s conns=%-4s size=%-6s %10s req/s\n' "$mode" "$handler" "$kind" "$conns" "$size" "${r:-FAILED}"
  done
}

echo "# $(uname -sr), $(nproc) CPUs, server on $SRV_CPUS ($THREADS threads), client on $CLI_CPUS ($CLI_THREADS threads), ${SECS}s x ${RUNS} runs, median"
if want tcp; then
  for c in 1 64 512; do run_matrix tcp tcp echo 5 $c 64; done
  run_matrix tcp tcp echo 5 64 16384
fi
if want tls; then run_matrix tls tls echo 5 64 1024; fi
if want udp; then run_matrix udp udp echo 5 64 64; fi
if want block; then
  # 5 ms of blocking work per request, 256 connections: an inline handler can do at most
  # threads / 5 ms, a pool-based one is limited by the pool and the client.
  for h in block-inline block-pool; do run_matrix tcp tcp $h 5 256 64; done
fi
