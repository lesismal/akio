#!/usr/bin/env bash
# CPU profile of one server under load, with perf (needs a privileged container: PRIV=1
# tools/bench/docker.sh 'tools/bench/profile.sh h1 akio-epoll').
#
#   tools/bench/profile.sh <h1|pipelined|h2|h2tls|ws|tcp> <kind> [seconds=5]
#
# HTTP/1.1 load comes from wrk, or from `h2load --h1` when wrk is not installed (H1GEN).
# Builds the akio servers with frame pointers and line tables into $CARGO_TARGET_DIR/prof, runs
# the load from http.sh / echo.sh against it and prints the top symbols (self time) and the
# report to /tmp/perf-<case>-<kind>.txt.
set -u
. "$(dirname "$0")/lib.sh"
CASE=$1 KIND=$2 D=${3:-5}
QUIET=0
cd "$(dirname "$0")/../.."
P=$T/prof
RUSTFLAGS="-C force-frame-pointers=yes" CARGO_TARGET_DIR=$P cargo build -q --release \
  --config 'profile.release.debug="line-tables-only"' \
  -p akio-http --example http-bench -p only --example bench-server
BENCH_SERVER=$P/release/examples/bench-server
HTTP_BENCH=$P/release/examples/http-bench
case $CASE in h1 | pipelined | h2) proto=http ;; h2tls) proto=https ;; ws) proto=ws ;; *) proto=tcp ;; esac
start_server "$KIND" "$proto"
H1GEN=${H1GEN:-$(command -v wrk >/dev/null && echo wrk || echo h2load)}
case $H1GEN:$CASE in
  h2load:h1 | h2load:pipelined) # no wrk: h2load --h1, pipelining with -m 16
    m=1
    [ "$CASE" = pipelined ] && m=16
    cli h2load --h1 -D "$((D + 2))" -c 256 -m "$m" -t "$CLI_THREADS" "http://127.0.0.1:$PORT/plaintext" >/tmp/load.txt 2>&1 &
    ;;
  *:h1) cli wrk -t "$CLI_THREADS" -c 256 -d "$((D + 2))s" "http://127.0.0.1:$PORT/plaintext" >/tmp/load.txt 2>&1 & ;;
  *:pipelined)
    printf 'init=function(a) local r={} for i=1,16 do r[i]=wrk.format(nil,"/plaintext") end req=table.concat(r) end\nrequest=function() return req end\n' >/tmp/p.lua
    cli wrk -t "$CLI_THREADS" -c 256 -d "$((D + 2))s" -s /tmp/p.lua "http://127.0.0.1:$PORT/plaintext" >/tmp/load.txt 2>&1 &
    ;;
  *:h2) cli h2load -D "$((D + 2))" -c 64 -m 16 -t "$CLI_THREADS" "http://127.0.0.1:$PORT/plaintext" >/tmp/load.txt 2>&1 & ;;
  *:h2tls) cli h2load -D "$((D + 2))" -c 64 -m 16 -t "$CLI_THREADS" "https://127.0.0.1:$PORT/plaintext" >/tmp/load.txt 2>&1 & ;;
  *:ws) cli "$ECHO_BENCH" "127.0.0.1:$PORT" 256 64 "$((D + 2))" "$CLI_THREADS" ws >/tmp/load.txt 2>&1 & ;;
  *:tcp) cli "$ECHO_BENCH" "127.0.0.1:$PORT" 256 64 "$((D + 2))" "$CLI_THREADS" tcp >/tmp/load.txt 2>&1 & ;;
esac
LPID=$!
sleep 1
cpu_ticks() { awk '{print $14 + $15}' "/proc/$SPID/stat"; }
t0=$(cpu_ticks)
perf record -q -F 1999 -g -p "$SPID" -o /tmp/perf.data -- sleep "$D" 2>/dev/null
t1=$(cpu_ticks)
wait "$LPID"
# How many CPUs the server kept busy: well below $THREADS means the load generator is the limit.
echo "server CPU: $(awk -v a="$t0" -v b="$t1" -v d="$D" -v hz="$(getconf CLK_TCK)" 'BEGIN{printf "%.2f", (b-a)/hz/d}') of $THREADS threads"
stop_server
grep -E "Requests/sec|req/s|finished in" /tmp/load.txt
R=/tmp/perf-$CASE-$KIND.txt
perf report -i /tmp/perf.data --no-children --stdio --percent-limit 0.7 2>/dev/null >"$R"
perf report -i /tmp/perf.data --no-children --stdio -g none --percent-limit 0.5 2>/dev/null |
  grep -E '^ +[0-9]' | head -45
echo "full report: $R"
