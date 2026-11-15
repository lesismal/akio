# Shared helpers of the benchmark scripts (sourced, not run). Linux only (taskset, /proc).
#
# Knobs (environment):
#   SRV_CPUS     CPUs the server is pinned to            (default 0-3)
#   CLI_CPUS     CPUs the load generator is pinned to    (default 4-11)
#   THREADS      server I/O threads / tokio workers      (default 4)
#   CLI_THREADS  load generator threads                  (default 8)
#   SECS         seconds per measurement                 (default 5)
#   RUNS         rounds; every figure is their median    (default 3)
#   KINDS        servers to run, e.g. "only-epoll fib"  (default: all that apply)
#   OUT          TSV file the raw results are appended to (default /tmp/bench-<suite>.tsv)
#
# Each round runs every case against every server in turn, with a fresh server per run, so a
# burst of noise from the shared host lands on one run of each server rather than on one server.
SRV_CPUS=${SRV_CPUS:-0-3}
CLI_CPUS=${CLI_CPUS:-4-11}
THREADS=${THREADS:-4}
CLI_THREADS=${CLI_THREADS:-8}
SECS=${SECS:-5}
RUNS=${RUNS:-3}
T=${CARGO_TARGET_DIR:-/tmp/t}
ECHO_BENCH=$T/release/echo-bench
BENCH_SERVER=$T/release/examples/bench-server
HTTP_BENCH=$T/release/examples/http-bench
TOKIO_REF=$T/ref/release/tokio-ref
HYPER_REF=$T/ref/release/hyper-ref
FIB_REF=$T/fib-ref
PORT=${PORT:-7400} # below the ephemeral range (docker.sh sets it to 10000-65535)
SPID=

# server_cmd <kind> <proto> <addr>: the command line of one server. Protocols: tcp, tls, udp
# (echo), http (HTTP/1.1 + h2c: /plaintext, /json), https (the same over TLS 1.3, ALPN h2 and
# http/1.1), ws (echo on /ws). Empty when unsupported.
server_cmd() {
  local kind=$1 proto=$2 addr=$3
  case $kind in
    base-*) # the only servers built from another revision, in $BASE_DIR (A/B runs)
      [ -n "${BASE_DIR:-}" ] || return 0
      BENCH_SERVER=$BASE_DIR/bench-server HTTP_BENCH=$BASE_DIR/http-bench server_cmd "only-${kind#base-}" "$proto" "$addr"
      return 0
      ;;
  esac
  case $kind:$proto in
    only-epoll:tcp | only-epoll:tls | only-epoll:udp) echo "$BENCH_SERVER $proto $addr $THREADS epoll echo" ;;
    only-uring:tcp | only-uring:tls) echo "$BENCH_SERVER $proto $addr $THREADS uring echo" ;;
    only-epoll:http | only-epoll:ws) echo "$HTTP_BENCH $addr $THREADS epoll" ;;
    only-uring:http | only-uring:ws) echo "$HTTP_BENCH $addr $THREADS uring" ;;
    only-epoll:https) echo "$HTTP_BENCH $addr $THREADS epoll tls" ;;
    only-uring:https) echo "$HTTP_BENCH $addr $THREADS uring tls" ;;
    tokio:tcp | tokio:tls | tokio:udp | tokio:ws) [ -x "$TOKIO_REF" ] && echo "$TOKIO_REF $proto $addr $THREADS" ;;
    hyper:http) [ -x "$HYPER_REF" ] && echo "$HYPER_REF $addr $THREADS" ;;
    fib:tcp | fib:tls | fib:udp | fib:http | fib:https | fib:ws) [ -x "$FIB_REF" ] && echo "$FIB_REF $proto $addr" ;;
  esac
  return 0
}

# kinds_for <proto>: the servers (of $KINDS) that can serve it.
kinds_for() {
  local k out=
  for k in ${KINDS:-only-epoll only-uring tokio hyper fib}; do
    [ -n "$(server_cmd "$k" "$1" x)" ] && out="$out $k"
  done
  echo "$out"
}

wait_port() { # <port>: until something accepts on it (5 s at most)
  local i
  for i in $(seq 50); do
    (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

# busy_pct: how busy all CPUs of this (VM) kernel were over the last second, in percent.
busy_pct() {
  local a b
  a=$(awk '/^cpu /{print $2+$3+$4+$7+$8, $2+$3+$4+$5+$6+$7+$8}' /proc/stat)
  sleep 1
  b=$(awk '/^cpu /{print $2+$3+$4+$7+$8, $2+$3+$4+$5+$6+$7+$8}' /proc/stat)
  echo "$a $b" | awk '{d=$4-$2; print (d>0) ? int(100*($3-$1)/d) : 0}'
}

# wait_quiet: before a run, wait (up to $QUIET_WAIT checks of about a second, default 120) while other work on
# the machine keeps more than $MAX_BUSY percent (default 15) of the CPUs busy. Work outside the
# VM (the host's own processes) is not visible here; that noise stays.
wait_quiet() {
  local waited=0 b
  while :; do
    b=$(busy_pct)
    [ "$b" -le "${MAX_BUSY:-15}" ] && break
    waited=$((waited + 1))
    [ "$waited" -ge "${QUIET_WAIT:-120}" ] && { echo "host still ${b}% busy, running anyway" >&2; break; }
  done
}

# start_server <kind> <proto>: picks a fresh port (in $PORT), starts the server pinned to
# $SRV_CPUS, waits until it listens. The pid is in $SPID.
start_server() {
  local cmd
  [ "${QUIET:-1}" = 1 ] && wait_quiet
  PORT=$((PORT + 1))
  cmd=$(server_cmd "$1" "$2" "0.0.0.0:$PORT")
  # shellcheck disable=SC2086
  taskset -c "$SRV_CPUS" $cmd >/dev/null 2>&1 &
  SPID=$!
  if [ "$2" = udp ]; then sleep 1; else wait_port "$PORT" || echo "server $1 $2 did not start" >&2; fi
}

stop_server() {
  [ -n "$SPID" ] || return 0
  kill "$SPID" 2>/dev/null
  wait "$SPID" 2>/dev/null
  SPID=
}

cli() { taskset -c "$CLI_CPUS" "$@"; }

# field <name>: the number before word <name> on stdin ("123 req/s" -> 123 for "req/s").
field() { awk -v w="$1" '{for(i=2;i<=NF;i++) if($i==w) print $(i-1)}' | head -1; }

# record <suite> <case> <kind> <round> <value>
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$@" | tee -a "$OUT"; }

rss_kib() { awk '/^VmRSS/{print $2}' "/proc/$1/status"; }

trap 'stop_server' EXIT
