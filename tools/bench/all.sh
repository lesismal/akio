#!/usr/bin/env bash
# The whole campaign of docs/BENCHMARKS.md, inside the flash-bench image:
#
#   docker build -t flash-bench tools/bench
#   PRIV=1 tools/bench/docker.sh 'tools/bench/build.sh && tools/bench/all.sh /w/target/bench-results'
#
# Writes <dir>/{echo,http,mem,ab}.tsv and <dir>/summary.md. Set BASE_DIR to a directory holding
# bench-server and http-bench built from another revision to add the A/B rows (ab.tsv).
set -u
D=${1:-/tmp/bench-results}
mkdir -p "$D"
B=$(dirname "$0")
OUT=$D/echo.tsv "$B/echo.sh"
OUT=$D/http.tsv "$B/http.sh"
OUT=$D/mem.tsv KINDS="${MEM_KINDS:-flash-epoll flash-uring tokio hyper fib}" "$B/mem.sh"
if [ -n "${BASE_DIR:-}" ]; then
  OUT=$D/ab.tsv KINDS="base-epoll flash-epoll base-uring flash-uring" "$B/http.sh" plaintext,pipelined,json,h2
  OUT=$D/ab.tsv KINDS="base-epoll flash-epoll base-uring flash-uring" SIZES=64 CONNS="64 1024" "$B/echo.sh" tcp
  OUT=$D/abmem.tsv KINDS="base-epoll flash-epoll base-uring flash-uring" "$B/mem.sh" tcp:echo:10000 http:http:10000 ws:ws:10000
fi
"$B/summarize.py" "$D"/*.tsv >"$D/summary.md"
cat "$D/summary.md"
