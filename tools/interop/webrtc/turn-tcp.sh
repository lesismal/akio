#!/usr/bin/env bash
# TURN TCP allocations (RFC 6062, ADR-076) across implementations, in Linux containers
# (Docker): the akio example is built in rust:1, the pion side cross-compiled, and coturn runs
# next to them (same network namespace) with its TCP and TLS listeners (self-signed):
#   - coturn's turnutils_uclient with TCP relays (-T: pairs of clients, each Connecting to the
#     other's relayed address, so Connect, ConnectionAttempt and ConnectionBind all run) against
#     akio-turn over TCP and TLS;
#   - the akio_turn client (Connect, then a peer connecting with a permission; ConnectionBind
#     on new connections; 20 messages and 1 MiB echoed) against coturn, pion/turn and
#     akio-turn over TCP and TLS;
#   - the engine-driven akio_turn client (TcpAllocation: data connections are engine
#     connections whose ConnectionBind is a transport layer) the same way;
#   - pion/turn's TCP allocation client (Dial and Accept) against akio-turn and coturn.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
ARCH=$(docker version -f '{{.Server.Arch}}')
OUT=$ROOT/target/interop-linux && mkdir -p "$OUT"
(cd "$ROOT/tools/interop/webrtc" && GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 GOFLAGS=-mod=mod \
  go build -o "$OUT/webrtc-pion" .)
docker run --rm -v "$ROOT":/w -w /w -v akio-cargo-reg:/usr/local/cargo/registry \
  -v akio-turntcp-target:/tmp/t -e CARGO_TARGET_DIR=/tmp/t rust:1 \
  cargo build -q --release -p akio-turn --example turn-tcp-interop
docker rm -f akio-turntcp-it akio-coturntcp-it >/dev/null 2>&1 || true
trap 'docker rm -f akio-turntcp-it akio-coturntcp-it >/dev/null 2>&1 || true' EXIT
docker run -d --name akio-turntcp-it -v "$ROOT":/w -w /w -v akio-turntcp-target:/tmp/t rust:1 \
  sleep infinity >/dev/null
RS=/tmp/t/release/examples/turn-tcp-interop
GO=/w/target/interop-linux/webrtc-pion
docker exec akio-turntcp-it openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj /CN=localhost -days 1 -keyout /tmp/t/coturn.key -out /tmp/t/coturn.crt 2>/dev/null
docker exec akio-turntcp-it chmod 644 /tmp/t/coturn.key /tmp/t/coturn.crt # coturn runs as nobody
docker run -d --name akio-coturntcp-it --network container:akio-turntcp-it \
  -v akio-turntcp-target:/tmp/t coturn/coturn:4.6 -n --listening-ip=127.0.0.1 \
  --listening-port=3478 --tls-listening-port=5349 --relay-ip=127.0.0.1 --realm=akio \
  --user=alice:wonderland --lt-cred-mech --fingerprint --allow-loopback-peers --no-cli \
  --cert=/tmp/t/coturn.crt --pkey=/tmp/t/coturn.key --no-dtls --log-file=stdout >/dev/null
docker exec -d akio-turntcp-it $RS server 127.0.0.1:9813 127.0.0.1:9814 alice wonderland
docker exec -d akio-turntcp-it $GO turn-server 127.0.0.1:9903 127.0.0.1:9913 127.0.0.1:9914 \
  alice wonderland
sleep 2
echo "== coturn turnutils_uclient with TCP relays (-T) against akio-turn (TCP, TLS)"
for f in "9813" "9814 -S"; do
  set -- $f
  port=$1; shift
  docker exec akio-coturntcp-it turnutils_uclient -T -n 20 -m 2 -l 100 -u alice -w wonderland \
    -p "$port" "$@" 127.0.0.1 >/tmp/uclient-tcp.log 2>&1 || { tail -20 /tmp/uclient-tcp.log; exit 1; }
  grep -E "start_mclient: tot_send_msgs=|Total lost" /tmp/uclient-tcp.log
  awk -F'tot_send_msgs=|, tot_recv_msgs=' '/start_mclient: tot_send_msgs=/ { s = $2; r = $3 }
    END { exit !(s + 0 > 0 && s + 0 == r + 0) }' /tmp/uclient-tcp.log
  grep -q "Total lost packets 0 " /tmp/uclient-tcp.log
done
echo "== akio_turn client with a TCP allocation against coturn, pion/turn and akio-turn"
for s in "tcp 3478" "tls 5349" "tcp 9913" "tls 9914" "tcp 9813" "tls 9814"; do
  set -- $s
  docker exec akio-turntcp-it $RS client "$1" "127.0.0.1:$2" alice wonderland
done
echo "== engine-driven akio_turn client (TcpAllocation) against coturn, pion/turn and akio-turn"
for s in "tcp 3478" "tls 5349" "tcp 9913" "tls 9914" "tcp 9813" "tls 9814"; do
  set -- $s
  docker exec akio-turntcp-it $RS engine-client "$1" "127.0.0.1:$2" alice wonderland
done
echo "== pion/turn TCP allocation client against akio-turn and coturn"
docker exec akio-turntcp-it $GO turn-tcp-raw 127.0.0.1:9813 alice wonderland
docker exec akio-turntcp-it $GO turn-tcp-raw 127.0.0.1:3478 alice wonderland
echo "turn tcp allocations interop: all passed"
