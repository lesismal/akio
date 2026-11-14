#!/usr/bin/env bash
# HTTP and WebSocket benchmarks.
#
#   tools/bench/http.sh [plaintext,pipelined,json,h2,ws]      (default: all)
#
# HTTP/1.1 with wrk (pipelined: 16 requests per write via a Lua script), HTTP/2 (h2c, prior
# knowledge) with h2load, WebSocket echo with echo-bench. See lib.sh for the knobs.
set -u
. "$(dirname "$0")/lib.sh"
OUT=${OUT:-/tmp/bench-http.tsv}
ONLY=${1:-plaintext,pipelined,json,h2,ws}
want() { case ",$ONLY," in *",$1,"*) return 0 ;; esac; return 1; }
HCONNS=${HCONNS:-256}
LUA=$(mktemp --suffix=.lua)
cat >"$LUA" <<'EOF'
init = function(args)
  local r = {}
  for i = 1, 16 do r[i] = wrk.format(nil, "/plaintext") end
  req = table.concat(r)
end
request = function() return req end
EOF

# wrk_rps <path> [extra wrk args...]: requests/s of one run against $PORT.
wrk_rps() {
  local path=$1
  shift
  cli wrk -t "$CLI_THREADS" -c "$HCONNS" -d "${SECS}s" "$@" "http://127.0.0.1:$PORT$path" 2>/dev/null |
    awk '/^Requests\/sec/{print int($2)} /Non-2xx/{print "NON2XX" > "/dev/stderr"}'
}

h2_rps() { # <conns> <streams>
  cli h2load -D "$SECS" -c "$1" -m "$2" -t "$CLI_THREADS" "http://127.0.0.1:$PORT/plaintext" 2>/dev/null |
    awk '/^finished in/{for(i=1;i<=NF;i++) if($i=="req/s,") print int($(i-1))}
         /^requests:/{for(i=1;i<=NF;i++) if($i=="failed,"||$i=="errored,") if($(i-1)>0) print "H2ERR " $0 > "/dev/stderr"}'
}

echo "# $(uname -sr), $(nproc) CPUs; server on $SRV_CPUS ($THREADS threads), client on $CLI_CPUS ($CLI_THREADS threads); ${SECS}s x $RUNS rounds" >&2
for r in $(seq "$RUNS"); do
  for kind in $(kinds_for http); do
    start_server "$kind" http
    cli wrk -t 2 -c 16 -d 1s "http://127.0.0.1:$PORT/plaintext" >/dev/null 2>&1 # warm-up
    want plaintext && record h1 "plaintext x $HCONNS" "$kind" "$r" "$(wrk_rps /plaintext)"
    want pipelined && record h1 "plaintext pipelined 16 x $HCONNS" "$kind" "$r" "$(wrk_rps /plaintext -s "$LUA")"
    want json && record h1 "json x $HCONNS" "$kind" "$r" "$(wrk_rps /json)"
    if want h2; then
      record h2 "h2c 64 conns x 16 streams" "$kind" "$r" "$(h2_rps 64 16)"
    fi
    stop_server
  done
  if want ws; then
    for kind in $(kinds_for ws); do
      for spec in "64 256" "1024 256"; do
        set -- $spec
        start_server "$kind" ws
        v=$(cli "$ECHO_BENCH" "127.0.0.1:$PORT" "$2" "$1" "$SECS" "$CLI_THREADS" ws 2>/dev/null | field req/s)
        stop_server
        record ws "${1}B x $2" "$kind" "$r" "${v:-FAILED}"
      done
    done
  fi
done
rm -f "$LUA"
