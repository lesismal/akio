#!/usr/bin/env bash
# io_uring send mechanisms on a raw ring (docs/BENCHMARKS.md, "io_uring features evaluation"):
# the test-only responder in crates/only-uring/src/eval.rs, answering `h2load --h1` with one
# fixed response per request, sent with write(2), IORING_OP_SEND or IORING_OP_SEND_ZC, with or
# without registered files (direct accept). Every round runs every size x mode on a fresh server.
# Prints and appends to $OUT: case, mode, round, requests/s, server CPU-ms per 1000 requests.
#
#   SIZES="13:16 1024:1 16384:1 65536:1 262144:1"   body bytes:requests in flight per connection
#   MODES="write:0 send:0 send:1 zc:0 zc:1"           mode:registered files
#
# Knobs as in lib.sh: SRV_CPUS, CLI_CPUS, THREADS, CLI_THREADS, SECS, RUNS; HCONNS (256).
set -u
. "$(dirname "$0")/lib.sh"
OUT=${OUT:-/tmp/bench-uring-eval.tsv}
SIZES=${SIZES:-"13:16 1024:1 16384:1 65536:1 262144:1"}
MODES=${MODES:-"write:0 send:0 send:1 zc:0 zc:1"}
HCONNS=${HCONNS:-256}
E=$(cd "$(dirname "$0")/../.." && cargo test --release -p only-uring --lib --no-run 2>&1 |
  sed -n 's/.*Executable .*(\(.*\))$/\1/p' | head -1)
[ -x "$E" ] || { echo "could not build the only-uring test binary" >&2; exit 1; }
HZ=$(getconf CLK_TCK)
cpu() { awk '{print $14+$15}' "/proc/$1/stat"; }
echo "# $(uname -sr), server on $SRV_CPUS ($THREADS threads), client on $CLI_CPUS ($CLI_THREADS threads); ${SECS}s x $RUNS rounds" >&2
for r in $(seq "$RUNS"); do
  for sz in $SIZES; do
    size=${sz%:*} m=${sz#*:}
    for md in $MODES; do
      mode=${md%:*} fixed=${md#*:}
      PORT=$((PORT + 1))
      while [ -n "$(ss -Htuan "sport = :$PORT" 2>/dev/null | head -1)" ]; do PORT=$((PORT + 1)); done
      EVAL_MODE=$mode EVAL_FIXED=$fixed EVAL_SECS=$((SECS + 4)) EVAL_SIZE=$size \
        EVAL_THREADS=$THREADS EVAL_ADDR=127.0.0.1:$PORT \
        taskset -c "$SRV_CPUS" "$E" --ignored --exact eval::eval_server >/dev/null 2>&1 &
      SPID=$!
      wait_port "$PORT"
      cli h2load -D 1 -t 4 --h1 -c 32 "http://127.0.0.1:$PORT/x" >/dev/null 2>&1 # warm-up
      c0=$(cpu "$SPID")
      v=$(cli h2load -D "$SECS" -t "$CLI_THREADS" --h1 -c "$HCONNS" -m "$m" "http://127.0.0.1:$PORT/x" 2>/dev/null |
        awk '/^finished in/{for(i=1;i<=NF;i++) if($i=="req/s,") print int($(i-1))}')
      c1=$(cpu "$SPID")
      wait "$SPID"
      SPID=
      cpk=$(awk -v a="$c0" -v b="$c1" -v v="${v:-0}" -v s="$SECS" -v hz="$HZ" \
        'BEGIN{ if (v>0) printf "%.4f", (b-a)*1000/hz/(v*s/1000); else print "NA"}')
      printf '%s\t%s\t%s\t%s\t%s\n' "${size}B m$m" "$mode$([ "$fixed" = 1 ] && echo +fixed)" "$r" "${v:-FAILED}" "$cpk" | tee -a "$OUT"
    done
  done
done
