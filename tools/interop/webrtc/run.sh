#!/usr/bin/env bash
# flash-webrtc / flash-turn <-> pion (webrtc v4, turn v5): data channels and RTP media in both
# offer directions, PLI, WebRTC through a flash TURN relay, and the pion/turn client against
# flash-turn. Needs Go. With COTURN=1 also runs coturn's turnutils_uclient against flash-turn,
# both in Docker (the flash TURN server is built for Linux in rust:1).
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT" && cargo build -q --release -p flash-webrtc --example webrtc-interop
RS=$ROOT/target/release/examples/webrtc-interop
cd "$ROOT/tools/interop/webrtc" && GOFLAGS=-mod=mod go build -o /tmp/webrtc-pion .
GO=/tmp/webrtc-pion
PIDS=""
trap 'kill $PIDS 2>/dev/null || true' EXIT

$RS server 127.0.0.1:9500 127.0.0.1:9501 2>/tmp/webrtc-flash-server.log & PIDS="$PIDS $!"
$GO server 127.0.0.1:9502 & PIDS="$PIDS $!"
$RS turn 127.0.0.1:9503 127.0.0.1 alice wonderland 2>/dev/null & PIDS="$PIDS $!"
sleep 1

echo "== pion offers to the flash ICE-lite server"
$GO client-dc 127.0.0.1:9501
$GO client-media 127.0.0.1:9501
echo "== flash (full ICE Endpoint) offers to pion"
$RS client 127.0.0.1:9502 dc
$RS client 127.0.0.1:9502 media
echo "== pion over a flash TURN relay (relay-only policy) to the flash server"
$GO client-turn 127.0.0.1:9501 127.0.0.1:9503 alice wonderland
echo "== pion/turn client against flash-turn"
$GO turn-raw 127.0.0.1:9503 alice wonderland

if [ "${COTURN:-0}" = 1 ]; then
  echo "== coturn turnutils_uclient against flash-turn (Docker)"
  docker run --rm -v "$ROOT":/w -w /w -v flash-cargo-reg:/usr/local/cargo/registry \
    -v flash-webrtc-target:/tmp/t -e CARGO_TARGET_DIR=/tmp/t rust:1 \
    cargo build -q --release -p flash-webrtc --example webrtc-interop
  docker rm -f flash-turn-it >/dev/null 2>&1 || true
  docker run -d --name flash-turn-it -v flash-webrtc-target:/tmp/t rust:1 \
    /tmp/t/release/examples/webrtc-interop turn 127.0.0.1:3478 127.0.0.1 alice wonderland >/dev/null
  sleep 2
  docker run --rm --network container:flash-turn-it coturn/coturn:4.6 turnutils_uclient -y -n 20 \
    -m 2 -l 100 -u alice -w wonderland -r flash -p 3478 127.0.0.1 2>&1 | tee /tmp/uclient.log | tail -4
  docker rm -f flash-turn-it >/dev/null
  grep -q "tot_send_msgs=20, tot_recv_msgs=20" /tmp/uclient.log
  grep -q "Total lost packets 0 " /tmp/uclient.log
fi
echo "webrtc interop: all passed"
