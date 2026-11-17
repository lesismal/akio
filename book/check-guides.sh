#!/usr/bin/env bash
# Runs every program the books take code from, so the snippets are not only compiled
# (book/build.sh) but exercised:
#
#   * every `guide-*` example: each starts its servers, drives them with its own clients and
#     exits 0, or fails (non-zero exit, panic or timeout);
#   * the serve-only examples the books include (guide-media, guide-media-rtsp, echo,
#     udp-echo, hello, prefork-http): started, probed from outside (TCP/UDP echo, HTTP/1.1,
#     HTTP/2, RTSP OPTIONS, RTMP connect), then stopped;
#   * the gRPC chapter's generated stubs (tools/protobuf-test): its gRPC test.
#
#   book/check-guides.sh                 # all of them
#   book/check-guides.sh guide-h3 echo   # only these
#   GUIDE_TIMEOUT=120 book/check-guides.sh
#
# The serve-only examples listen on fixed ports (8080, 1935, 8554, 8000-8001, 7002). On
# Linux the script re-runs itself in a private network namespace (`unshare -rn`) when it can,
# so nothing else on the host is in the way; elsewhere (macOS, containers without unshare) a
# busy port fails the example with the process holding it. Uses CARGO_TARGET_DIR. Needs
# python3; curl for the HTTP/2 probe (skipped without it).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
timeout_s="${GUIDE_TIMEOUT:-90}"

if [[ -z "${ONLY_GUIDES_NETNS:-}" ]]; then
  # Build first: the private network namespace below has no network for cargo or rustup.
  echo "building examples..."
  cargo build --workspace --examples --quiet
  cargo test --no-run --quiet -p protobuf-test --test grpc
  if [[ "$(uname -s)" == Linux ]] && unshare -rn true 2>/dev/null && command -v ip >/dev/null; then
    exec env ONLY_GUIDES_NETNS=1 unshare -rn bash -c 'ip link set lo up && exec "$0" "$@"' "$0" "$@"
  fi
fi
bin="${CARGO_TARGET_DIR:-$root/target}/debug/examples"
logs="$(mktemp -d "${TMPDIR:-/tmp}/only-guides.XXXXXX")"

# Every guide example in the workspace, plus the serve-only programs the books include.
guides=()
while IFS= read -r f; do guides+=("$(basename "$f" .rs)"); done < <(
  find crates -path '*/examples/guide-*.rs' | sort -t/ -k4)
serve_only=(guide-media guide-media-rtsp echo udp-echo hello prefork-http)
all=()
for g in "${guides[@]}"; do
  case " ${serve_only[*]} " in *" $g "*) ;; *) all+=("$g") ;; esac
done
all+=("${serve_only[@]}" grpc-stubs)
if [[ $# -gt 0 ]]; then all=("$@"); fi

pass=()
fail=()

# run_bounded SECS LOG CMD...: runs CMD, kills it after SECS; returns its status (124 on timeout).
run_bounded() {
  local secs=$1 log=$2
  shift 2
  "$@" >"$log" 2>&1 &
  local pid=$! waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if ((waited >= secs * 10)); then
      kill -9 "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      echo "TIMEOUT after ${secs}s" >>"$log"
      return 124
    fi
    sleep 0.1
    waited=$((waited + 1))
  done
  wait "$pid"
}

# port_free PROTO PORT: fails, naming the holder, when something already listens there.
port_free() {
  python3 - "$1" "$2" <<'EOF'
import socket, sys
proto, port = sys.argv[1], int(sys.argv[2])
if proto == "tcp":  # SO_REUSEPORT listeners do not stop a bind: try to connect too
    try:
        socket.create_connection(("127.0.0.1", port), 1).close()
        sys.exit(f"tcp port {port} is busy (something accepts connections there)")
    except OSError:
        pass
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # TIME_WAIT from a last run is fine
try:
    s.bind(("127.0.0.1", port))
except OSError as e:
    sys.exit(f"{proto} port {port} is busy ({e.strerror})")
EOF
}

# wait_port PORT: waits up to 15 s for a TCP listener on 127.0.0.1:PORT.
wait_port() {
  python3 - "$1" <<'EOF'
import socket, sys, time
deadline = time.time() + 15
while time.time() < deadline:
    try:
        socket.create_connection(("127.0.0.1", int(sys.argv[1])), 1).close()
        sys.exit(0)
    except OSError:
        time.sleep(0.1)
sys.exit(f"nothing listens on {sys.argv[1]}")
EOF
}

# http_get URL EXPECT: GET over HTTP/1.1, the body must contain EXPECT.
http_get() {
  python3 - "$1" "$2" <<'EOF'
import sys, urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
body = opener.open(sys.argv[1], timeout=10).read().decode("utf-8", "replace")
if sys.argv[2] not in body:
    sys.exit(f"GET {sys.argv[1]}: {body!r} lacks {sys.argv[2]!r}")
print(f"GET {sys.argv[1]}: {body.strip()[:80]!r}")
EOF
}

# tcp_exchange PORT SEND EXPECT: sends SEND, the answer must contain EXPECT.
tcp_exchange() {
  python3 - "$@" <<'EOF'
import socket, sys
port, send, expect = int(sys.argv[1]), sys.argv[2].encode().decode("unicode_escape"), sys.argv[3]
s = socket.create_connection(("127.0.0.1", port), 5)
s.settimeout(5)
s.sendall(send.encode("latin-1"))
got = b""
while expect.encode() not in got:
    chunk = s.recv(4096)
    if not chunk:
        break
    got += chunk
if expect.encode() not in got:
    sys.exit(f"tcp {port}: got {got[:200]!r}, expected {expect!r}")
print(f"tcp {port}: {got.decode('latin-1')[:80]!r}")
EOF
}

# rtmp_handshake PORT: sends C0+C1, expects S0 (version 3) and S1+S2 (1536 bytes each).
rtmp_handshake() {
  python3 - "$1" <<'EOF'
import os, socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
s.settimeout(5)
s.sendall(b"\x03" + bytes(8) + os.urandom(1528))
got = b""
while len(got) < 1 + 2 * 1536:
    chunk = s.recv(8192)
    if not chunk:
        break
    got += chunk
if got[:1] != b"\x03" or len(got) < 1 + 2 * 1536:
    sys.exit(f"rtmp: got {len(got)} bytes starting {got[:1]!r}, expected S0 S1 S2")
print("rtmp: S0 S1 S2 received")
EOF
}

# udp_exchange PORT SEND EXPECT
udp_exchange() {
  python3 - "$@" <<'EOF'
import socket, sys, time
port, send, expect = int(sys.argv[1]), sys.argv[2].encode(), sys.argv[3].encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
for _ in range(15):  # the server may still be starting: retry
    s.sendto(send, ("127.0.0.1", port))
    try:
        got = s.recv(65536)
    except socket.timeout:
        continue
    if expect in got:
        print(f"udp {port}: {got[:80]!r}")
        sys.exit(0)
    sys.exit(f"udp {port}: got {got!r}, expected {expect!r}")
sys.exit(f"udp {port}: no answer")
EOF
}

# serve LOG PORTS -- CMD...: checks the ports are free, starts CMD in the background (pid in
# $server), waits for the first TCP port.
server=""
serve() {
  local log=$1
  shift
  local ports=()
  while [[ $1 != -- ]]; do ports+=("$1"); shift; done
  shift
  local p
  for p in "${ports[@]}"; do port_free "${p%%/*}" "${p##*/}"; done
  "$@" >"$log" 2>&1 &
  server=$!
  for p in "${ports[@]}"; do
    if [[ ${p%%/*} == tcp ]]; then wait_port "${p##*/}"; break; fi
  done
}

stop() {
  local sig=${1:-TERM}
  [[ -n $server ]] || return 0
  kill "-$sig" "$server" 2>/dev/null || true
  local i
  for i in $(seq 100); do kill -0 "$server" 2>/dev/null || break; sleep 0.1; done
  kill -9 "$server" 2>/dev/null || true
  wait "$server" 2>/dev/null || true
  server=""
}

# probe NAME: the checks of one serve-only program (runs in a subshell; non-zero = failure).
probe() {
  local log=$1
  case $2 in
    guide-media)
      # ONLY_MEDIA_SECS stops it by itself; probe RTMP and the HTTP side meanwhile.
      serve "$log" tcp/1935 tcp/8080 -- env ONLY_MEDIA_SECS=4 "$bin/guide-media"
      rtmp_handshake 1935
      http_get http://127.0.0.1:8080/streams ''
      wait "$server"
      server=""
      ;;
    guide-media-rtsp)
      serve "$log" tcp/8554 tcp/8080 udp/8000 udp/8001 -- env ONLY_RTSP_SECS=4 "$bin/guide-media-rtsp"
      tcp_exchange 8554 'OPTIONS rtsp://127.0.0.1:8554/live/cam RTSP/1.0\r\nCSeq: 1\r\n\r\n' 'RTSP/1.0 200'
      # WHEP without a WebRTC engine: the endpoint is there and answers 501 (NoMedia).
      tcp_exchange 8080 'POST /whep/live/cam HTTP/1.1\r\nHost: x\r\nContent-Type: application/sdp\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' 'HTTP/1.1 '
      wait "$server"
      server=""
      ;;
    echo)
      # The book uses 7000; any port does (macOS's AirPlay receiver listens on *:7000).
      local port
      port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
      serve "$log" "tcp/$port" -- "$bin/echo" "127.0.0.1:$port"
      tcp_exchange "$port" 'hello\n' 'hello'
      stop
      ;;
    udp-echo)
      serve "$log" udp/7002 -- "$bin/udp-echo"
      udp_exchange 7002 'hello' 'hello'
      stop
      ;;
    hello)
      serve "$log" tcp/8080 -- "$bin/hello"
      http_get http://127.0.0.1:8080/users/7 '7'
      if command -v curl >/dev/null; then
        curl -sS --noproxy '*' --http2-prior-knowledge -o /dev/null -w 'h2 / -> %{http_version} %{http_code}\n' \
          http://127.0.0.1:8080/ | tee /dev/stderr | grep -q '^h2 / -> 2 200$'
      fi
      stop
      ;;
    prefork-http)
      serve "$log" tcp/8080 -- "$bin/prefork-http"
      http_get http://127.0.0.1:8080/ ''
      http_get http://127.0.0.1:8080/ ''
      stop TERM # drains and stops the workers
      ;;
    grpc-stubs)
      cargo test --offline --quiet -p protobuf-test --test grpc >"$log" 2>&1
      ;;
    *)
      echo "unknown program $2" >&2
      return 1
      ;;
  esac
}

for name in "${all[@]}"; do
  log="$logs/$name.log"
  start=$(date +%s)
  case " ${serve_only[*]} grpc-stubs " in
    *" $name "*)
      # Not in a condition: `set -e` must stay in force inside the probe.
      (trap stop EXIT; probe "$log" "$name") >"$logs/$name.probe" 2>&1 &
      if wait $!; then rc=0; else rc=$?; fi
      cat "$logs/$name.probe" >>"$log"
      ;;
    *)
      if [[ ! -x "$bin/$name" ]]; then
        echo "no such example: $name" >"$log"
        rc=127
      elif run_bounded "$timeout_s" "$log" "$bin/$name"; then rc=0; else rc=$?; fi
      ;;
  esac
  secs=$(($(date +%s) - start))
  if [[ $rc == 0 ]]; then
    printf 'ok    %-20s %3ss\n' "$name" "$secs"
    pass+=("$name")
  else
    printf 'FAIL  %-20s %3ss (status %s, log %s)\n' "$name" "$secs" "$rc" "$log"
    tail -15 "$log" | sed 's/^/      /'
    fail+=("$name")
  fi
done

echo "${#pass[@]} passed, ${#fail[@]} failed ($(uname -sm)${ONLY_GUIDES_NETNS:+, private netns})"
[[ ${#fail[@]} == 0 && -z "${GUIDE_KEEP_LOGS:-}" ]] && rm -rf "$logs"
[[ ${#fail[@]} == 0 ]]
