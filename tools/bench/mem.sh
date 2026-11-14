#!/usr/bin/env bash
# Memory per connection: the server's RSS growth divided by the connections held open.
#
#   tools/bench/mem.sh [spec ...]     spec = <proto>:<hold kind>:<connections>
#
# Default specs: tcp:tcp:10000 tcp:tcp:100000 tcp:echo:10000 http:http:10000 ws:ws:10000
# tls:tls:10000. `hold kind` is what each connection goes through once before it idles
# (see echo-bench's hold-<kind> modes): tcp = connect only, echo = one 64-byte echo, http = one
# keep-alive GET, ws = upgrade + one 64-byte echo, tls = handshake + one 64-byte echo.
# Connections are spread over 127.0.0.1-4 so one client can hold more than 64k.
#
# The tokio reference reads into a per-connection buffer; it gets TOKIO_REF_BUF=4096 here (the
# 64 KiB of the throughput runs would mostly be untouched memory anyway).
set -u
. "$(dirname "$0")/lib.sh"
OUT=${OUT:-/tmp/bench-mem.tsv}
QUIET=0
SPECS=${*:-tcp:tcp:10000 tcp:tcp:100000 tcp:echo:10000 http:http:10000 ws:ws:10000 tls:tls:10000}
export TOKIO_REF_BUF=${TOKIO_REF_BUF:-4096}
ADDRS() { echo "127.0.0.1:$PORT,127.0.0.2:$PORT,127.0.0.3:$PORT,127.0.0.4:$PORT"; }

for r in $(seq "${MEM_RUNS:-1}"); do
  for spec in $SPECS; do
    IFS=: read -r proto kind n <<<"$spec"
    for k in $(kinds_for "$proto"); do
      start_server "$k" "$proto"
      sleep 0.5
      base=$(rss_kib "$SPID")
      log=$(mktemp)
      taskset -c "$CLI_CPUS" "$ECHO_BENCH" "$(ADDRS)" "$n" 64 600 "$CLI_THREADS" "hold-$kind" >"$log" 2>&1 &
      cpid=$!
      for _ in $(seq 1200); do grep -q '^ready' "$log" && break; kill -0 $cpid 2>/dev/null || break; sleep 0.25; done
      sleep 2
      rss=$(rss_kib "$SPID")
      held=$(awk '/^ready/{print $2}' "$log")
      kill $cpid 2>/dev/null
      wait $cpid 2>/dev/null
      stop_server
      if [ -n "$held" ] && [ "$held" -gt 0 ]; then
        per=$(((rss - base) * 1024 / held))
        echo "# $k $proto/$kind: base ${base} KiB, with $held conns ${rss} KiB" >&2
      else
        per=FAILED
        echo "# $k $proto/$kind: $(cat "$log")" >&2
      fi
      record mem "$proto/$kind x $n (bytes/conn)" "$k" "$r" "$per"
      rm -f "$log"
      sleep 2 # let the kernel finish closing the held connections
    done
  done
done
