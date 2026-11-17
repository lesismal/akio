#!/usr/bin/env bash
# run.sh in Linux containers (Docker), plus coturn: the only example is built in rust:1, the
# pion side cross-compiled, and coturn runs next to them (same network namespace):
#   - turnutils_uclient against only-turn over UDP, TCP (-t) and TLS (-S);
#   - the only_turn client against coturn over UDP, TCP and TLS;
#   - an only Endpoint with relayed candidates from coturn, to pion.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
ARCH=$(docker version -f '{{.Server.Arch}}')
OUT=$ROOT/target/interop-linux && mkdir -p "$OUT"
(cd "$ROOT/tools/interop/webrtc" && GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 GOFLAGS=-mod=mod \
  go build -o "$OUT/webrtc-pion" .)
docker run --rm -v "$ROOT":/w -w /w -v only-cargo-reg:/usr/local/cargo/registry \
  -v only-webrtc-target:/tmp/t -e CARGO_TARGET_DIR=/tmp/t rust:1 \
  cargo build -q --release -p only-webrtc --example webrtc-interop
docker rm -f only-webrtc-it only-coturn-it >/dev/null 2>&1 || true
trap 'docker rm -f only-webrtc-it only-coturn-it >/dev/null 2>&1 || true' EXIT
docker run -d --name only-webrtc-it -v "$ROOT":/w -w /w -v only-webrtc-target:/tmp/t rust:1 \
  sleep infinity >/dev/null
RS=/tmp/t/release/examples/webrtc-interop
docker exec only-webrtc-it openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj /CN=localhost -days 1 -keyout /tmp/t/coturn.key -out /tmp/t/coturn.crt 2>/dev/null
docker exec only-webrtc-it chmod 644 /tmp/t/coturn.key /tmp/t/coturn.crt # coturn runs as nobody
docker run -d --name only-coturn-it --network container:only-webrtc-it -v only-webrtc-target:/tmp/t \
  coturn/coturn:4.6 -n --listening-ip=127.0.0.1 --listening-port=3478 --tls-listening-port=5349 \
  --relay-ip=127.0.0.1 --realm=only --user=alice:wonderland --lt-cred-mech --fingerprint \
  --allow-loopback-peers --no-cli --cert=/tmp/t/coturn.crt --pkey=/tmp/t/coturn.key \
  --no-dtls --log-file=stdout >/dev/null
docker exec -e RS=$RS -e GO=/w/target/interop-linux/webrtc-pion only-webrtc-it \
  bash tools/interop/webrtc/run.sh
echo "== coturn turnutils_uclient against only-turn (UDP, TCP, TLS)"
docker exec -d only-webrtc-it $RS turn 127.0.0.1:9603 127.0.0.1 alice wonderland \
  127.0.0.1:9613 127.0.0.1:9614
sleep 1
for f in "9603" "9613 -t" "9614 -t -S"; do
  set -- $f
  port=$1; shift
  docker exec only-coturn-it turnutils_uclient -y -n 20 -m 2 -l 100 -u alice -w wonderland \
    -r only -p "$port" "$@" 127.0.0.1 >/tmp/uclient.log 2>&1 || { tail -20 /tmp/uclient.log; exit 1; }
  grep -E "start_mclient: tot_send_msgs=|Total lost" /tmp/uclient.log
  awk -F'tot_send_msgs=|, tot_recv_msgs=' '/start_mclient: tot_send_msgs=/ { s = $2; r = $3 }
    END { exit !(s + 0 > 0 && s + 0 == r + 0) }' /tmp/uclient.log
  grep -q "Total lost packets 0 " /tmp/uclient.log
done
echo "== only_turn client against coturn (UDP, TCP, TLS)"
for s in "udp 3478" "tcp 3478" "tls 5349"; do
  set -- $s
  docker exec only-webrtc-it $RS turn-client "$1" "127.0.0.1:$2" alice wonderland
done
echo "== only Endpoint with relayed candidates from coturn, to pion"
docker exec -d only-webrtc-it /w/target/interop-linux/webrtc-pion server 127.0.0.1:9602
sleep 1
docker exec only-webrtc-it $RS client 127.0.0.1:9602 dc-relay 127.0.0.1:3478 alice wonderland
echo "webrtc linux interop: all passed"
