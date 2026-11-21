#!/usr/bin/env bash
# Kernel TLS in the engine (ADR-067, docs/BENCHMARKS.md "Kernel TLS in the engine"): an
# interleaved A/B of TLS echo, full handshakes and HTTPS between builds and `ONLY_KTLS` modes.
# Linux; h2load on PATH.
#
# Binaries (each directory holds echo-bench, bench-server and http-bench, release builds):
#   BASE_DIR  the revision to compare against           (variant `base`)
#   NEW_DIR   this revision, default features           (variant `new`)
#   NEWK_DIR  this revision with `--features only/ktls`  (variants `off`, `hw`, `sw`, `swtx`)
#   e.g. cargo build --release -p echo-bench --features tls
#        cargo build --release -p only --example bench-server --features only/ktls
#        cargo build --release -p only-http --example http-bench --features only/ktls
#
# Knobs: VARIANTS ("base new hw sw"), RUNS (8), SECS (5), ECHO_SIZES ("1024 16384"; empty skips
# the echo cases), SRV_CPUS (0-3), CLI_CPUS (4-11), OUT (/tmp/bench-ktls-engine.tsv). Before
# every run it waits (up to 2 min) for the host to be under 15% busy. Prints and appends TSV:
# case variant backend round value; tools/bench/summarize.py or a spreadsheet takes it from there.
set -u
SRV=${SRV_CPUS:-0-3}
CLI=${CLI_CPUS:-4-11}
SECS=${SECS:-5}
RUNS=${RUNS:-8}
PORT=${PORT:-7600}
OUT=${OUT:-/tmp/bench-ktls-engine.tsv}
VARIANTS=${VARIANTS:-"base new hw sw"}
EB=${NEW_DIR:?set NEW_DIR}/echo-bench

srv_env() {
  case $1 in
    hw) echo "ONLY_KTLS=hardware" ;;
    sw) echo "ONLY_KTLS=software" ;;
    swtx) echo "ONLY_KTLS=software-tx" ;;
    *) echo "ONLY_KTLS=off" ;;
  esac
}
bindir() {
  case $1 in
    base) echo "${BASE_DIR:?set BASE_DIR}" ;;
    new) echo "$NEW_DIR" ;;
    *) echo "${NEWK_DIR:?set NEWK_DIR}" ;;
  esac
}

busy_pct() { # how busy all CPUs were over the last second, in percent
  local a b
  a=$(awk '/^cpu /{print $2+$3+$4+$7+$8, $2+$3+$4+$5+$6+$7+$8}' /proc/stat)
  sleep 1
  b=$(awk '/^cpu /{print $2+$3+$4+$7+$8, $2+$3+$4+$5+$6+$7+$8}' /proc/stat)
  echo "$a $b" | awk '{d=$4-$2; print (d>0) ? int(100*($3-$1)/d) : 0}'
}
wait_quiet() {
  local b
  for _ in $(seq 120); do
    b=$(busy_pct)
    [ "$b" -le 15 ] && return 0
  done
  echo "host still ${b}% busy, running anyway" >&2
}
wait_port() { for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && return 0; sleep 0.1; done; return 1; }

start() { # <variant> <cmd...>: ADDR in the command becomes the server address
  local v=$1 a
  shift
  wait_quiet
  PORT=$((PORT + 1))
  while [ -n "$(ss -Htan "sport = :$PORT" 2>/dev/null | head -1)" ]; do PORT=$((PORT + 1)); done
  local args=()
  for a in "$@"; do args+=("${a/ADDR/0.0.0.0:$PORT}"); done
  env "$(srv_env "$v")" taskset -c "$SRV" "${args[@]}" >/dev/null 2>&1 &
  SPID=$!
  wait_port $PORT || echo "server $v did not start" >&2
}
stop() { kill "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null; }
rec() { printf '%s\t%s\t%s\t%s\t%s\n' "$@" | tee -a "$OUT"; }
field() { awk -v w="$1" '{for(i=2;i<=NF;i++) if($i==w) print $(i-1)}' | head -1; }

for r in $(seq "$RUNS"); do
  for be in epoll uring; do
    for v in $VARIANTS; do
      d=$(bindir "$v")
      for sz in ${ECHO_SIZES-1024 16384}; do
        start "$v" "$d/bench-server" tls ADDR 4 $be echo
        taskset -c "$CLI" "$EB" "127.0.0.1:$PORT" 8 64 1 4 tls >/dev/null 2>&1
        x=$(taskset -c "$CLI" "$EB" "127.0.0.1:$PORT" 64 "$sz" "$SECS" 8 tls 2>/dev/null | field req/s)
        stop
        rec "tls-echo-$sz" "$v" $be "$r" "${x:-FAILED}"
      done
      start "$v" "$d/bench-server" tls ADDR 4 $be echo
      x=$(taskset -c "$CLI" "$EB" "127.0.0.1:$PORT" 32 0 "$SECS" 1 tlshs 2>/dev/null | field handshakes/s)
      stop
      rec tls-handshakes "$v" $be "$r" "${x:-FAILED}"
      start "$v" "$d/http-bench" ADDR 4 $be tls
      taskset -c "$CLI" h2load --h1 -c 64 -t 8 -D 2 "https://127.0.0.1:$PORT/plaintext" >/dev/null 2>&1
      x=$(taskset -c "$CLI" h2load --h1 -c 64 -t 8 -D "$SECS" "https://127.0.0.1:$PORT/plaintext" 2>&1 |
        sed -n 's/^finished in .*, \([0-9.]*\) req\/s, .*/\1/p')
      stop
      rec https-plaintext "$v" $be "$r" "${x:-FAILED}"
    done
  done
done
