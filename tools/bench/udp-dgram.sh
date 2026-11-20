#!/usr/bin/env bash
# A/B of UDP 64-byte echo (ADR-065): per-peer listeners of a base build and of the build under
# test, and connectionless datagram listeners (`bench-server udp-dgram`) on epoll and io_uring.
#
#   BASE=/path/target-base NEW=/path/target-new tools/bench/udp-dgram.sh
#
# BASE and NEW are cargo target dirs holding release/examples/bench-server (NEW also
# release/echo-bench). Server on CPUs 0-3 (4 threads), echo-bench 64 sockets x 64 B on CPUs 4-11
# (8 threads), SECS-second runs, ROUNDS rounds in rotating order. Prints per run:
# round variant req/s server-cpu-ns-per-request. Run it under quiet.sh on the bench host.
set -u
: "${BASE:?target dir of the base build}" "${NEW:?target dir of the build under test}"
EB=$NEW/release/echo-bench
ROUNDS=${ROUNDS:-9}
SECS=${SECS:-10}
PORT=${PORT:-7600}
ticks() { awk '{print $14+$15}' "/proc/$1/stat"; }
run() { # <variant> <round>
  local cmd tail
  case $1 in
    base-udp) cmd="$BASE/release/examples/bench-server udp"; tail="epoll echo" ;;
    new-udp) cmd="$NEW/release/examples/bench-server udp"; tail="epoll echo" ;;
    dgram-epoll) cmd="$NEW/release/examples/bench-server udp-dgram"; tail="epoll echo" ;;
    dgram-uring) cmd="$NEW/release/examples/bench-server udp-dgram"; tail="uring echo" ;;
  esac
  PORT=$((PORT + 1))
  # shellcheck disable=SC2086
  taskset -c 0-3 $cmd "127.0.0.1:$PORT" 4 $tail >/dev/null 2>&1 &
  local pid=$!
  sleep 1
  taskset -c 4-11 "$EB" "127.0.0.1:$PORT" 8 64 1 4 udp >/dev/null 2>&1 # warm-up
  local t0 r t1
  t0=$(ticks "$pid")
  r=$(taskset -c 4-11 "$EB" "127.0.0.1:$PORT" 64 64 "$SECS" 8 udp 2>/dev/null |
    awk '{for(i=2;i<=NF;i++) if($i=="req/s") print $(i-1)}' | head -1)
  t1=$(ticks "$pid")
  kill "$pid"
  wait "$pid" 2>/dev/null
  echo "$2 $1 $r $(awk -v d=$((t1 - t0)) -v r="$r" -v s="$SECS" 'BEGIN{ if (r>0) printf "%.0f", d*1e7/(r*s); else print "NA" }')"
}
V=(base-udp new-udp dgram-epoll dgram-uring)
for r in $(seq "$ROUNDS"); do
  for k in 0 1 2 3; do run "${V[$(((k + r) % 4))]}" "$r"; done
done
