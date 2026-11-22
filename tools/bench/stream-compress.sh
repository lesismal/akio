#!/usr/bin/env bash
# A/B of compressed streamed responses (ADR-074): throughput of streamed responses and server
# memory per idle server-sent-events stream, for a base build (streams never compressed) and
# the build under test with and without `Compress::stream`.
#
#   BASE=/path/target-base NEW=/path/target-new tools/bench/stream-compress.sh [tput] [mem]
#
# BASE and NEW are cargo target dirs holding release/examples/stream-bench (the base copy built
# with its `STREAM-ONLY` line removed when the base has no `Compress::stream`). VARIANTS and
# MEM_VARIANTS pick the variants (default: all of them); `base-<coding>` is the base build with
# `stream` and a client accepting only that coding, for an A/B of the encoders themselves. Server on CPUs 0-3 (4 threads), h2load --h1 (64
# connections, 8 threads) on CPUs 4-11; SECS-second runs, ROUNDS rounds in rotating order.
#
# tput prints: round variant path req/s server-cpu-us-per-response body-bytes-per-response
# mem prints:  variant events conns rss-before-KiB rss-after-KiB bytes-per-stream
# Run it under quiet.sh on the bench host.
set -u
: "${BASE:?target dir of the base build}" "${NEW:?target dir of the build under test}"
ROUNDS=${ROUNDS:-3}
SECS=${SECS:-5}
PORT=${PORT:-7700}
CONNS=${CONNS:-1000}
ulimit -n 65536
ticks() { awk '{print $14+$15}' "/proc/$1/stat"; }
rss() { awk '/^VmRSS/{print $2}' "/proc/$1/status"; }
start() { # <variant>: sets PID and PORT; the variant's Accept-Encoding goes to AE
  local bin=$NEW/release/examples/stream-bench mode=stream
  case $1 in
    base) bin=$BASE/release/examples/stream-bench mode=plain AE=gzip ;;
    base-*) bin=$BASE/release/examples/stream-bench AE=${1#base-} ;;
    off) mode=plain AE=gzip ;;
    identity) AE=identity ;;
    *) AE=$1 ;;
  esac
  # A port still held by an earlier run's sockets (or another user) makes the server exit:
  # try the next one.
  for _ in $(seq 20); do
    PORT=$((PORT + 1))
    taskset -c 0-3 "$bin" serve "127.0.0.1:$PORT" 4 "$mode" >/dev/null 2>&1 &
    PID=$!
    sleep 1
    kill -0 "$PID" 2>/dev/null && return
  done
  echo "# $1: the server does not start" >&2
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null; }
tput() { # <variant> <path> <round>
  start "$1"
  taskset -c 4-11 h2load --h1 -D 1 -c 16 -t 4 -H "accept-encoding: $AE" "http://127.0.0.1:$PORT$2" >/dev/null 2>&1
  local t0 out t1
  t0=$(ticks "$PID")
  out=$(taskset -c 4-11 h2load --h1 -D "$SECS" -c 64 -t 8 -H "accept-encoding: $AE" "http://127.0.0.1:$PORT$2" 2>/dev/null)
  t1=$(ticks "$PID")
  stop
  echo "$out" | awk -v r="$3" -v v="$1" -v p="$2" -v d=$((t1 - t0)) '
    /^requests:/ { for (i = 1; i <= NF; i++) if ($i == "succeeded,") ok = $(i - 1) }
    /^finished in/ { for (i = 1; i <= NF; i++) if ($i == "req/s,") rps = $(i - 1) }
    /^traffic:/ { n = split($0, a, /[()]/); data = a[n - 1] }
    END { printf "%s %s %s %.0f %.1f %.0f\n", r, v, p, rps, (ok ? d * 1e4 / ok : 0), (ok ? data / ok : 0) }'
}
mem() { # <variant> <events>
  start "$1"
  local before log hold after held
  before=$(rss "$PID")
  log=$(mktemp)
  taskset -c 4-11 "$NEW/release/examples/stream-bench" hold "127.0.0.1:$PORT" "$CONNS" "$2" "$AE" >"$log" 2>&1 &
  hold=$!
  for _ in $(seq 2400); do
    grep -q '^ready' "$log" && break
    kill -0 "$hold" 2>/dev/null || break
    sleep 0.25
  done
  sleep 1
  after=$(rss "$PID")
  held=$(awk '/^ready/{print $2}' "$log")
  kill "$hold"
  wait "$hold" 2>/dev/null
  stop
  rm -f "$log"
  echo "$1 $2 ${held:-0} $before $after $(((after - before) * 1024 / ${held:-1}))"
  sleep 2
}
WHAT=${*:-tput mem}
read -r -a V <<<"${VARIANTS:-base off identity gzip br zstd}"
read -r -a MV <<<"${MEM_VARIANTS:-base off gzip br zstd}"
if [[ " $WHAT " == *" tput "* ]]; then
  for r in $(seq "$ROUNDS"); do
    for path in /sse /bulk; do
      for k in $(seq 0 $((${#V[@]} - 1))); do tput "${V[$(((k + r) % ${#V[@]}))]}" "$path" "$r"; done
    done
  done
fi
if [[ " $WHAT " == *" mem "* ]]; then
  for events in 3 6000; do
    for v in "${MV[@]}"; do mem "$v" "$events"; done
  done
fi
