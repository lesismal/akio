#!/usr/bin/env bash
# CPU profile of one server under load, with perf (needs a privileged container: PRIV=1
# tools/bench/docker.sh 'tools/bench/profile.sh h1 flash-epoll').
#
#   tools/bench/profile.sh <h1|pipelined|h2|ws|tcp> <kind> [seconds=5]
#
# Builds the flash servers with frame pointers and line tables into $CARGO_TARGET_DIR/prof, runs
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
  -p flash-http --example http-bench -p flash --example bench-server
BENCH_SERVER=$P/release/examples/bench-server
HTTP_BENCH=$P/release/examples/http-bench
case $CASE in h1 | pipelined | h2) proto=http ;; ws) proto=ws ;; *) proto=tcp ;; esac
start_server "$KIND" "$proto"
case $CASE in
  h1) cli wrk -t "$CLI_THREADS" -c 256 -d "$((D + 2))s" "http://127.0.0.1:$PORT/plaintext" >/tmp/load.txt 2>&1 & ;;
  pipelined)
    printf 'init=function(a) local r={} for i=1,16 do r[i]=wrk.format(nil,"/plaintext") end req=table.concat(r) end\nrequest=function() return req end\n' >/tmp/p.lua
    cli wrk -t "$CLI_THREADS" -c 256 -d "$((D + 2))s" -s /tmp/p.lua "http://127.0.0.1:$PORT/plaintext" >/tmp/load.txt 2>&1 &
    ;;
  h2) cli h2load -D "$((D + 2))" -c 64 -m 16 -t "$CLI_THREADS" "http://127.0.0.1:$PORT/plaintext" >/tmp/load.txt 2>&1 & ;;
  ws) cli "$ECHO_BENCH" "127.0.0.1:$PORT" 256 64 "$((D + 2))" "$CLI_THREADS" ws >/tmp/load.txt 2>&1 & ;;
  tcp) cli "$ECHO_BENCH" "127.0.0.1:$PORT" 256 64 "$((D + 2))" "$CLI_THREADS" tcp >/tmp/load.txt 2>&1 & ;;
esac
LPID=$!
sleep 1
perf record -q -F 1999 -g -p "$SPID" -o /tmp/perf.data -- sleep "$D" 2>/dev/null
wait "$LPID"
stop_server
grep -E "Requests/sec|req/s|finished in" /tmp/load.txt
R=/tmp/perf-$CASE-$KIND.txt
perf report -i /tmp/perf.data --no-children --stdio --percent-limit 0.7 2>/dev/null >"$R"
perf report -i /tmp/perf.data --no-children --stdio -g none --percent-limit 0.5 2>/dev/null |
  grep -E '^ +[0-9]' | head -45
echo "full report: $R"
