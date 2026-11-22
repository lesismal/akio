#!/usr/bin/env bash
# TURN dual allocations (RFC 8656 ADDITIONAL-ADDRESS-FAMILY, ADR-083) and ECN across the relay,
# in Linux containers (Docker, IPv6 loopback on): the only example is built in rust:1, the pion
# side cross-compiled, and coturn runs next to them (same network namespace) relaying from
# 127.0.0.1 and ::1:
#   - coturn's turnutils_uclient with dual allocations (-Z) and IPv6 relays (-x), clients
#     sending to each other's relayed addresses (-y), against akio-turn (and coturn itself);
#   - the akio_turn client asking for a dual allocation (peers on 127.0.0.1 and ::1, ECN marks
#     both ways) against coturn (two relayed addresses), pion/turn (one: it ignores the
#     attribute) and akio-turn (two, and the codepoints must be copied);
#   - pion/turn's client asking for IPv4 or IPv6 relays (REQUESTED-ADDRESS-FAMILY) against
#     akio-turn and coturn.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
ARCH=$(docker version -f '{{.Server.Arch}}')
OUT=$ROOT/target/interop-linux && mkdir -p "$OUT"
VOL=${AKIO_TURNDUAL_VOLUME:-akio-turndual-target}
(cd "$ROOT/tools/interop/webrtc" && GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 GOFLAGS=-mod=mod \
  go build -o "$OUT/webrtc-pion" .)
docker run --rm -v "$ROOT":/w -w /w -v akio-cargo-reg:/usr/local/cargo/registry \
  -v "$VOL":/tmp/t -e CARGO_TARGET_DIR=/tmp/t rust:1 \
  cargo build -q --release -p akio-turn --example turn-dual-interop
docker rm -f akio-turndual-it akio-coturndual-it >/dev/null 2>&1 || true
trap 'docker rm -f akio-turndual-it akio-coturndual-it >/dev/null 2>&1 || true' EXIT
docker run -d --name akio-turndual-it --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --sysctl net.ipv6.conf.lo.disable_ipv6=0 -v "$ROOT":/w -w /w -v "$VOL":/tmp/t rust:1 \
  sleep infinity >/dev/null
RS=/tmp/t/release/examples/turn-dual-interop
GO=/w/target/interop-linux/webrtc-pion
docker run -d --name akio-coturndual-it --network container:akio-turndual-it coturn/coturn:4.6 \
  -n --listening-ip=127.0.0.1 --listening-port=3478 --relay-ip=127.0.0.1 --relay-ip=::1 \
  --realm=only --user=alice:wonderland --lt-cred-mech --fingerprint --allow-loopback-peers \
  --no-cli --no-tls --no-dtls --log-file=stdout >/dev/null
docker exec -d akio-turndual-it $RS server 127.0.0.1:9823 alice wonderland
docker exec -d akio-turndual-it $GO turn-server 127.0.0.1:9903 127.0.0.1:9913 127.0.0.1:9914 \
  alice wonderland
sleep 2
uclient() { # port, flags...
  port=$1; shift
  docker exec akio-coturndual-it turnutils_uclient -y -n 20 -m 2 -l 100 -u alice -w wonderland \
    -p "$port" "$@" 127.0.0.1 >/tmp/uclient-dual.log 2>&1 || { tail -20 /tmp/uclient-dual.log; exit 1; }
  grep -E "start_mclient: tot_send_msgs=|Total lost" /tmp/uclient-dual.log
  awk -F'tot_send_msgs=|, tot_recv_msgs=' '/start_mclient: tot_send_msgs=/ { s = $2; r = $3 }
    END { exit !(s + 0 > 0 && s + 0 == r + 0) }' /tmp/uclient-dual.log
  grep -q "Total lost packets 0 " /tmp/uclient-dual.log
}
for port in 9823 3478; do
  echo "== coturn turnutils_uclient: dual allocations (-Z) against port $port"
  uclient "$port" -Z
  echo "== coturn turnutils_uclient: IPv6 relays (-x) against port $port"
  uclient "$port" -x
done
echo "== akio_turn client, dual allocation: coturn (2 relays), pion/turn (1), akio-turn (2, ECN)"
docker exec akio-turndual-it $RS client 127.0.0.1:3478 alice wonderland 2
docker exec akio-turndual-it $RS client 127.0.0.1:9903 alice wonderland 1
docker exec akio-turndual-it $RS client 127.0.0.1:9823 alice wonderland 2 ecn
echo "== pion/turn client, REQUESTED-ADDRESS-FAMILY IPv4 and IPv6: akio-turn, coturn"
for s in 9823 3478; do
  for f in 4 6; do
    docker exec akio-turndual-it $GO turn-family-raw "127.0.0.1:$s" alice wonderland "$f"
  done
done
echo "turn dual allocations interop: all passed"
