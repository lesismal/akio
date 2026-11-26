#!/usr/bin/env bash
# Shared I/O groups (ADR-130): N HTTP listeners on one server, each with I/O threads of its own
# (`Listener::threads`, every listener before ADR-130) against all of them sharing one group
# (`EngineBuilder::io_threads`), same build, same CPUs, interleaved in every round.
#
#   tools/bench/shared.sh [all,pipelined,h2,one]   (default: all of them)
#
#   all        HTTP/1.1 plaintext, the load spread over the N listeners at once (one h2load each)
#   pipelined  the same with 16 requests in flight per connection
#   h2         h2c, 16 streams per connection, over the N listeners at once
#   one        HTTP/1.1 plaintext on the first listener only, the others idle
#
# Every case is the sum of the per-listener requests/s. Servers ($MODES): `dedicated` (N x
# $THREADS I/O threads) and `shared` ($THREADS I/O threads), each also `-pinned`
# (`AKIO_PIN_IO_THREADS=1`: one CPU per I/O thread), on epoll and, where it runs, io_uring
# ($BACKENDS, default "epoll uring"). Further suffixes: `-inline` serves HTTP/2 on the I/O
# threads (`run_on_pool` off, `AKIO_BENCH_H2_INLINE=1`); `-pool<N>` keeps N of the server's CPUs
# for the logical pool and pins $THREADS - N I/O threads to the others (`AKIO_POOL_CPUS=N`). Also recorded per run: the server's threads and its CPU
# seconds per million requests of the `all` case. Knobs as in lib.sh, plus LISTENERS (default 3);
# HTTP/1.1 is driven by `h2load --h1` (one generator per listener, so wrk is not used).
set -u
. "$(dirname "$0")/lib.sh"
OUT=${OUT:-/tmp/bench-shared.tsv}
ONLY=${1:-all,pipelined,h2,one}
want() { case ",$ONLY," in *",$1,"*) return 0 ;; esac; return 1; }
LISTENERS=${LISTENERS:-3}
BACKENDS=${BACKENDS:-epoll uring}
MODES=${MODES:-dedicated shared dedicated-pinned shared-pinned}
HCONNS=${HCONNS:-256}
HTTP_BENCH=${HTTP_BENCH:-${CARGO_TARGET_DIR:-/tmp/t}/release/examples/http-bench}

# start_multi <mode> <backend>: the server with $LISTENERS listeners from $PORT up, pinned to
# $SRV_CPUS. The pid is in $SPID.
start_multi() {
  local mode=$1 backend=$2 shared=0 pin=0 inline=0 pool=0 threads=$THREADS i busy
  case $mode in shared*) shared=1 ;; esac
  case $mode in *-pinned*) pin=1 ;; esac
  case $mode in *-inline*) inline=1 ;; esac
  case $mode in *-pool[0-9]*)
    pool=${mode##*-pool}
    pin=1
    threads=$((THREADS - pool))
    ;;
  esac
  # Ports still held by sockets of an earlier run are skipped (see start_server).
  while :; do
    PORT=$((PORT + LISTENERS + 1))
    busy=
    for i in $(seq 0 $((LISTENERS - 1))); do
      [ -n "$(ss -Htuan "sport = :$((PORT + i))" 2>/dev/null | head -1)" ] && busy=1
    done
    [ -z "$busy" ] && break
  done
  AKIO_BENCH_LISTENERS=$LISTENERS AKIO_BENCH_SHARED=$shared AKIO_PIN_IO_THREADS=$pin \
    AKIO_BENCH_H2_INLINE=$inline AKIO_POOL_CPUS=$pool \
    taskset -c "$SRV_CPUS" "$HTTP_BENCH" "127.0.0.1:$PORT" "$threads" "$backend" >/dev/null 2>&1 &
  SPID=$!
  for i in $(seq 0 $((LISTENERS - 1))); do wait_port $((PORT + i)); done
}

# multi_rps <n> <h2load args...>: runs one h2load per listener among the first <n>, at once,
# splitting $HCONNS and $CLI_THREADS between them; prints the summed requests/s.
multi_rps() {
  local n=$1
  shift
  local conns=$((HCONNS / n)) threads=$((CLI_THREADS / n)) tmp
  [ "$threads" -ge 1 ] || threads=1
  tmp=$(mktemp -d)
  for i in $(seq 0 $((n - 1))); do
    cli h2load -D "$SECS" -t "$threads" -c "$conns" "$@" "http://127.0.0.1:$((PORT + i))/plaintext" \
      >"$tmp/$i" 2>/dev/null &
  done
  wait
  cat "$tmp"/* | awk '/^finished in/{for(i=1;i<=NF;i++) if($i=="req/s,") s+=$(i-1)} END{print int(s)}'
  rm -rf "$tmp"
}

# cpu_secs <pid>: user + system CPU seconds of the process so far.
cpu_secs() {
  awk -v hz="$(getconf CLK_TCK)" '{print ($14 + $15) / hz}' "/proc/$1/stat"
}

echo "# $(uname -sr), $(nproc) CPUs; server on $SRV_CPUS ($LISTENERS listeners, $THREADS threads each or shared), client on $CLI_CPUS ($CLI_THREADS threads); ${SECS}s x $RUNS rounds" >&2
for r in $(seq "$RUNS"); do
  for backend in $BACKENDS; do
    for mode in $MODES; do
      kind="$mode-$backend"
      wait_quiet
      start_multi "$mode" "$backend"
      cli h2load -D 1 -c 16 -t 2 --h1 "http://127.0.0.1:$PORT/plaintext" >/dev/null 2>&1 # warm-up
      record shared "server threads" "$kind" "$r" "$(awk '/^Threads/{print $2}' "/proc/$SPID/status")"
      if want all; then
        c0=$(cpu_secs "$SPID")
        rps=$(multi_rps "$LISTENERS" --h1)
        c1=$(cpu_secs "$SPID")
        record shared "h1 plaintext x $HCONNS over $LISTENERS listeners" "$kind" "$r" "$rps"
        record shared "server CPU s per 1M requests (h1 over $LISTENERS)" "$kind" "$r" \
          "$(awk -v a="$c0" -v b="$c1" -v n="$rps" -v s="$SECS" 'BEGIN{printf "%.2f", (b - a) / (n * s) * 1e6}')"
      fi
      want pipelined && record shared "h1 pipelined 16 x $HCONNS over $LISTENERS listeners" "$kind" "$r" "$(multi_rps "$LISTENERS" --h1 -m 16)"
      want h2 && record shared "h2c 64 conns x 16 streams over $LISTENERS listeners" "$kind" "$r" "$(HCONNS=64 multi_rps "$LISTENERS" -m 16)"
      want one && record shared "h1 plaintext x $HCONNS on 1 of $LISTENERS listeners" "$kind" "$r" "$(multi_rps 1 --h1)"
      stop_server
    done
  done
done
