#!/usr/bin/env bash
# HTTP and WebSocket benchmarks.
#
#   tools/bench/http.sh [plaintext,pipelined,json,h2,h2many,h2tls,ws,wsz]   (default: all but h2many,h2tls)
#
# HTTP/1.1 with wrk (pipelined: 16 requests per write via a Lua script), HTTP/2 (h2c, prior
# knowledge) with h2load, WebSocket echo with echo-bench. See lib.sh for the knobs.
# H1GEN=h2load (the default when wrk is not installed) drives HTTP/1.1 with `h2load --h1`
# instead, pipelining with `-m 16`. h2many: h2c, 16 connections x 128 streams; h2tls: HTTP/2
# over TLS 1.3 (ALPN h2), 64 connections x 16 streams, on a server started with TLS.
set -u
. "$(dirname "$0")/lib.sh"
OUT=${OUT:-/tmp/bench-http.tsv}
ONLY=${1:-plaintext,pipelined,json,h2,ws}
H1GEN=${H1GEN:-$(command -v wrk >/dev/null && echo wrk || echo h2load)}
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

# wrk_rps <path> [extra wrk args...]: requests/s of one run against $PORT. With H1GEN=h2load,
# `-s <lua>` (the pipelining script) becomes `-m 16`.
wrk_rps() {
  local path=$1
  shift
  if [ "$H1GEN" = h2load ]; then
    local m=1
    [ "${1:-}" = -s ] && m=16
    h2load_rps http "$path" --h1 -c "$HCONNS" -m "$m"
    return
  fi
  cli wrk -t "$CLI_THREADS" -c "$HCONNS" -d "${SECS}s" "$@" "http://127.0.0.1:$PORT$path" 2>/dev/null |
    awk '/^Requests\/sec/{print int($2)} /Non-2xx/{print "NON2XX" > "/dev/stderr"}'
}

h2_rps() { h2load_rps http /plaintext -c "$1" -m "$2"; } # <conns> <streams>

h2load_rps() { # <http|https> <path> [h2load args...]
  local scheme=$1 path=$2
  shift 2
  cli h2load -D "$SECS" -t "$CLI_THREADS" "$@" "$scheme://127.0.0.1:$PORT$path" 2>/dev/null |
    awk '/^finished in/{for(i=1;i<=NF;i++) if($i=="req/s,") print int($(i-1))}
         /^requests:/{for(i=1;i<=NF;i++) if($i=="failed,"||$i=="errored,") if($(i-1)>0) print "H2ERR " $0 > "/dev/stderr"}'
}

echo "# $(uname -sr), $(nproc) CPUs; server on $SRV_CPUS ($THREADS threads), client on $CLI_CPUS ($CLI_THREADS threads); ${SECS}s x $RUNS rounds" >&2
for r in $(seq "$RUNS"); do
  for kind in $(kinds_for http); do
    start_server "$kind" http
    if [ "$H1GEN" = h2load ]; then # warm-up
      cli h2load -D 1 -c 16 -t 2 --h1 "http://127.0.0.1:$PORT/plaintext" >/dev/null 2>&1
    else
      cli wrk -t 2 -c 16 -d 1s "http://127.0.0.1:$PORT/plaintext" >/dev/null 2>&1
    fi
    want plaintext && record h1 "plaintext x $HCONNS" "$kind" "$r" "$(wrk_rps /plaintext)"
    want pipelined && record h1 "plaintext pipelined 16 x $HCONNS" "$kind" "$r" "$(wrk_rps /plaintext -s "$LUA")"
    want json && record h1 "json x $HCONNS" "$kind" "$r" "$(wrk_rps /json)"
    want h2 && record h2 "h2c 64 conns x 16 streams" "$kind" "$r" "$(h2_rps 64 16)"
    want h2many && record h2 "h2c 16 conns x 128 streams" "$kind" "$r" "$(h2_rps 16 128)"
    stop_server
  done
  if want h2tls; then
    for kind in $(kinds_for https); do
      start_server "$kind" https
      cli h2load -D 1 -c 8 -m 4 -t 2 "https://127.0.0.1:$PORT/plaintext" >/dev/null 2>&1 # warm-up
      record h2 "h2 TLS 64 conns x 16 streams" "$kind" "$r" "$(h2load_rps https /plaintext -c 64 -m 16)"
      stop_server
    done
  fi
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
  if want wsz; then
    # permessage-deflate (no context takeover): compressed requests, the server inflates them
    # and compresses replies of 128 bytes and more.
    for kind in $(kinds_for ws); do
      for spec in "64 256" "1024 256"; do
        set -- $spec
        start_server "$kind" ws
        v=$(cli "$ECHO_BENCH" "127.0.0.1:$PORT" "$2" "$1" "$SECS" "$CLI_THREADS" wsz 2>/dev/null | field req/s)
        stop_server
        record wsz "${1}B x $2" "$kind" "$r" "${v:-FAILED}"
      done
    done
  fi
done
rm -f "$LUA"
