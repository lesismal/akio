#!/usr/bin/env bash
# Echo benchmarks: TCP (sizes x connections), UDP, TLS echo and TLS handshake rate.
#
#   tools/bench/echo.sh [tcp,udp,tls,tlshs]      (default: all)
#
# See lib.sh for the knobs (CPUs, threads, seconds, rounds). Raw rows go to $OUT, summarise them
# with tools/bench/summarize.py. Built by tools/bench/build.sh.
set -u
. "$(dirname "$0")/lib.sh"
OUT=${OUT:-/tmp/bench-echo.tsv}
ONLY=${1:-tcp,udp,tls,tlshs}
want() { case ",$ONLY," in *",$1,"*) return 0 ;; esac; return 1; }
SIZES=${SIZES:-64 1024 16384}
CONNS=${CONNS:-64 256 1024}

# one <suite> <proto> <case> <round> <echo-bench args after addr...>
one() {
  local suite=$1 proto=$2 case=$3 round=$4 kind v
  shift 4
  for kind in $(kinds_for "$proto"); do
    start_server "$kind" "$proto"
    cli "$ECHO_BENCH" "127.0.0.1:$PORT" 8 64 1 4 "$([ "$proto" = tlshs ] && echo tls || echo "$proto")" >/dev/null 2>&1 # warm-up
    v=$(cli "$ECHO_BENCH" "127.0.0.1:$PORT" "$@" 2>/dev/null | field "$([ "${*: -1}" = tlshs ] && echo handshakes/s || echo req/s)")
    stop_server
    record "$suite" "$case" "$kind" "$round" "${v:-FAILED}"
  done
}

echo "# $(uname -sr), $(nproc) CPUs; server on $SRV_CPUS ($THREADS threads), client on $CLI_CPUS ($CLI_THREADS threads); ${SECS}s x $RUNS rounds" >&2
for r in $(seq "$RUNS"); do
  if want tcp; then
    for s in $SIZES; do for c in $CONNS; do
      one tcp tcp "${s}B x $c" "$r" "$c" "$s" "$SECS" "$CLI_THREADS" tcp
    done; done
  fi
  want udp && one udp udp "64B x 64" "$r" 64 64 "$SECS" "$CLI_THREADS" udp
  want tls && one tls tls "1KiB x 64" "$r" 64 1024 "$SECS" "$CLI_THREADS" tls
  if want tlshs; then
    # Full handshakes (no resumption), TLS 1.3, ECDSA P-256 certificate; 32 client workers.
    for kind in $(kinds_for tls); do
      start_server "$kind" tls
      v=$(cli "$ECHO_BENCH" "127.0.0.1:$PORT" 32 0 "$SECS" 1 tlshs 2>/dev/null | field handshakes/s)
      stop_server
      record tlshs "handshakes/s" "$kind" "$r" "${v:-FAILED}"
    done
  fi
done
