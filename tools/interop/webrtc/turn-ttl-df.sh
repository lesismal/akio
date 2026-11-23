#!/usr/bin/env bash
# The TTL across a TURN relay (RFC 5766 section 12, RFC 8656 section 13) and DONT-FRAGMENT
# (RFC 8656 sections 11.2 and 14), in Linux containers (Docker): the akio_turn client and the
# servers (akio-turn, coturn) share one container, the peer runs in another across the Docker
# bridge (a 1500-byte link). The client sends with TTL 40 and the peer answers with TTL 50; the
# client then sends Send indications: 100 bytes with DONT-FRAGMENT, 2000 bytes without and with
# it, 100 bytes with it again, then 100 bytes with TTL 1. akio-turn must relay with TTL 39 and
# 49, fragment the big one without DF and refuse it with DF (EMSGSIZE), telling the client with
# ICMP 3/4 and MTU 1500 (RFC 8656 section 14, ADR-091), and drop the TTL 1 one telling the
# client with ICMP 11/0; coturn's behaviour is printed.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
VOL=${AKIO_TURNDUAL_VOLUME:-akio-turndual-target}
docker run --rm -v "$ROOT":/w -w /w -v akio-cargo-reg:/usr/local/cargo/registry \
  -v "$VOL":/tmp/t -e CARGO_TARGET_DIR=/tmp/t rust:1 \
  cargo build -q --release -p akio-turn --example turn-ttl-df-interop
docker rm -f akio-ttldf-it akio-ttldf-peer akio-coturnttldf-it >/dev/null 2>&1 || true
trap 'docker rm -f akio-ttldf-it akio-ttldf-peer akio-coturnttldf-it >/dev/null 2>&1 || true' EXIT
RS=/tmp/t/release/examples/turn-ttl-df-interop
for c in akio-ttldf-it akio-ttldf-peer; do
  docker run -d --name $c -v "$ROOT":/w -w /w -v "$VOL":/tmp/t rust:1 sleep infinity >/dev/null
done
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }
HOST=$(ip_of akio-ttldf-it)
PEER=$(ip_of akio-ttldf-peer)
echo "client and servers on $HOST, peer on $PEER (MTU $(docker exec akio-ttldf-it cat /sys/class/net/eth0/mtu))"
docker run -d --name akio-coturnttldf-it --network container:akio-ttldf-it coturn/coturn:4.6 \
  -n --listening-ip=127.0.0.1 --listening-port=3478 --relay-ip="$HOST" \
  --realm=akio --user=alice:wonderland --lt-cred-mech --fingerprint \
  --no-cli --no-tls --no-dtls --log-file=stdout >/dev/null
docker exec -d akio-ttldf-it $RS server 127.0.0.1:9823 "$HOST" alice wonderland
docker exec -d akio-ttldf-peer $RS peer "$PEER:7000"
sleep 2
echo "== coturn 4.6"
docker exec akio-ttldf-it $RS client 127.0.0.1:3478 "$PEER:7000" alice wonderland
echo "== akio-turn"
docker exec akio-ttldf-it $RS client 127.0.0.1:9823 "$PEER:7000" alice wonderland ttl,df,ptb,ttl1
echo "turn TTL / DONT-FRAGMENT interop: all passed"
