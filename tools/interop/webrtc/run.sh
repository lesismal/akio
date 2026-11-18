#!/usr/bin/env bash
# only-webrtc / only-turn <-> pion (webrtc v4, turn v5): data channels and RTP media in both
# offer directions, PLI, WebRTC through a only TURN relay, the pion/turn client against
# only-turn over UDP, TCP and TLS, the only_turn client against pion/turn and only-turn over
# UDP, TCP and TLS, Endpoint relayed candidates (on only-turn and pion/turn, allocated over UDP,
# TCP and TLS), ICE-TCP both ways (only passive with pion active, only active with pion passive,
# pion active to the ICE-lite server's passive candidate) and simulcast sending (pion receives
# the three RIDs);
# and fib's Go WebRTC (data channels, both directions) when the fib checkout is next to this
# repository (or at $FIB_DIR). Needs Go. With COTURN=1 also runs coturn's turnutils_uclient
# against only-turn, both in Docker (the only TURN server is built for Linux in rust:1).
# linux.sh runs all of it in Linux containers, coturn over TCP/TLS included.
# RS / GO: prebuilt binaries (skips the builds).
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
if [ -z "${RS:-}" ]; then
  (cd "$ROOT" && cargo build -q --release -p only-webrtc --example webrtc-interop)
  RS=$ROOT/target/release/examples/webrtc-interop
fi
if [ -z "${GO:-}" ]; then
  (cd "$ROOT/tools/interop/webrtc" && GOFLAGS=-mod=mod go build -o /tmp/webrtc-pion .)
  GO=/tmp/webrtc-pion
fi
PIDS=""
trap 'kill $PIDS 2>/dev/null || true' EXIT

$RS server 127.0.0.1:9500 127.0.0.1:9501 2>/tmp/webrtc-only-server.log & PIDS="$PIDS $!"
$GO server 127.0.0.1:9502 & PIDS="$PIDS $!"
$RS turn 127.0.0.1:9503 127.0.0.1 alice wonderland 127.0.0.1:9513 127.0.0.1:9514 2>/dev/null & PIDS="$PIDS $!"
$GO turn-server 127.0.0.1:9520 127.0.0.1:9521 127.0.0.1:9522 alice wonderland 2>/dev/null & PIDS="$PIDS $!"
$GO server-tcp 127.0.0.1:9505 2>/tmp/webrtc-pion-tcp.log & PIDS="$PIDS $!"
$GO server-tcp-passive 127.0.0.1:9507 127.0.0.1:9508 2>/tmp/webrtc-pion-tcp-passive.log & PIDS="$PIDS $!"
$RS server 127.0.0.1:9509 127.0.0.1:9510 127.0.0.1:9511 2>/tmp/webrtc-only-server-tcp.log & PIDS="$PIDS $!"
$GO server-simulcast 127.0.0.1:9506 2>/dev/null & PIDS="$PIDS $!"
sleep 1

echo "== pion offers to the only ICE-lite server"
$GO client-dc 127.0.0.1:9501
$GO client-media 127.0.0.1:9501
echo "== only (full ICE Endpoint) offers to pion"
$RS client 127.0.0.1:9502 dc
$RS client 127.0.0.1:9502 media
echo "== pion over a only TURN relay (relay-only policy) to the only server"
$GO client-turn 127.0.0.1:9501 127.0.0.1:9503 alice wonderland
echo "== pion/turn client against only-turn (UDP, TCP, TLS)"
$GO turn-raw 127.0.0.1:9503 alice wonderland
$GO turn-raw-tcp 127.0.0.1:9513 alice wonderland
$GO turn-raw-tls 127.0.0.1:9514 alice wonderland
echo "== only_turn client against pion/turn and only-turn (UDP, TCP, TLS)"
for s in "udp 9520" "tcp 9521" "tls 9522" "udp 9503" "tcp 9513" "tls 9514"; do
  set -- $s
  $RS turn-client "$1" "127.0.0.1:$2" alice wonderland
done
echo "== only Endpoint with relayed candidates only (on only-turn, on pion/turn) to pion"
$RS client 127.0.0.1:9502 dc-relay 127.0.0.1:9503 alice wonderland
$RS client 127.0.0.1:9502 dc-relay 127.0.0.1:9520 alice wonderland
echo "== only Endpoint with relayed candidates allocated over TCP and TLS (only-turn, pion/turn)"
for u in "turn:127.0.0.1:9513?transport=tcp" "turns:127.0.0.1:9514" \
  "turn:127.0.0.1:9521?transport=tcp" "turns:127.0.0.1:9522"; do
  $RS client 127.0.0.1:9502 dc-relay-url "$u" alice wonderland
done
echo "== only Endpoint with its passive ICE-TCP candidate only to pion (active TCP only)"
$RS client 127.0.0.1:9505 dc-tcp
echo "== only Endpoint with its active ICE-TCP candidate only to pion (passive TCP only)"
$RS client 127.0.0.1:9507 dc-active
echo "== pion (active TCP only) to the only ICE-lite server's passive ICE-TCP candidate"
$GO client-dc-tcp 127.0.0.1:9510
echo "== only simulcast (h/m/l) to pion"
$RS client 127.0.0.1:9506 simulcast

FIB_DIR=${FIB_DIR:-$ROOT/../fib}
if [ -d "$FIB_DIR/webrtc" ]; then
  echo "== fib (Go, lesismal/fib/webrtc) <-> only, both directions"
  W=$(mktemp -d)
  printf 'go 1.27.3\n\nuse %s\n\nreplace github.com/lesismal/fib => %s\n' \
    "$ROOT/tools/interop/webrtc/fib" "$(cd "$FIB_DIR" && pwd)" > "$W/go.work"
  (cd "$ROOT/tools/interop/webrtc/fib" && GOWORK="$W/go.work" go build -o /tmp/webrtc-fib .)
  /tmp/webrtc-fib server 127.0.0.1:9504 & PIDS="$PIDS $!"
  sleep 1
  /tmp/webrtc-fib client-dc 127.0.0.1:9501
  $RS client 127.0.0.1:9504 dc
else
  echo "== fib: skipped (no checkout at $FIB_DIR; set FIB_DIR)"
fi

if [ "${COTURN:-0}" = 1 ]; then
  echo "== coturn turnutils_uclient against only-turn (Docker)"
  docker run --rm -v "$ROOT":/w -w /w -v only-cargo-reg:/usr/local/cargo/registry \
    -v only-webrtc-target:/tmp/t -e CARGO_TARGET_DIR=/tmp/t rust:1 \
    cargo build -q --release -p only-webrtc --example webrtc-interop
  docker rm -f only-turn-it >/dev/null 2>&1 || true
  docker run -d --name only-turn-it -v only-webrtc-target:/tmp/t rust:1 \
    /tmp/t/release/examples/webrtc-interop turn 127.0.0.1:3478 127.0.0.1 alice wonderland >/dev/null
  sleep 2
  docker run --rm --network container:only-turn-it coturn/coturn:4.6 turnutils_uclient -y -n 20 \
    -m 2 -l 100 -u alice -w wonderland -r only -p 3478 127.0.0.1 2>&1 | tee /tmp/uclient.log | tail -4
  docker rm -f only-turn-it >/dev/null
  awk -F'tot_send_msgs=|, tot_recv_msgs=' '/start_mclient: tot_send_msgs=/ { s = $2; r = $3 }
    END { exit !(s + 0 > 0 && s + 0 == r + 0) }' /tmp/uclient.log
  grep -q "Total lost packets 0 " /tmp/uclient.log
fi
echo "webrtc interop: all passed"
