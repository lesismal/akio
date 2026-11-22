#!/usr/bin/env bash
# TURN over DTLS (RFC 7350, ADR-054) against coturn, in Linux containers (Docker): the only
# example is built in rust:1 and coturn runs next to it (same network namespace) with its
# DTLS listener on 5349/udp (self-signed certificate):
#   - coturn's turnutils_uclient over DTLS (-S, UDP) against akio-turn's DTLS listener;
#   - the akio_turn client inside an akio-dtls connection against coturn's DTLS listener;
#   - two only Endpoints with relayed candidates only, allocated on coturn over DTLS
#     (turns:...?transport=udp), a data channel echo between them;
#   - the same against akio-turn's DTLS listener.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
docker run --rm -v "$ROOT":/w -w /w -v akio-cargo-reg:/usr/local/cargo/registry \
  -v akio-webrtc-dtls-target:/tmp/t -e CARGO_TARGET_DIR=/tmp/t rust:1 \
  cargo build -q --release -p akio-webrtc --example webrtc-interop
docker rm -f akio-turndtls-it akio-coturndtls-it >/dev/null 2>&1 || true
trap 'docker rm -f akio-turndtls-it akio-coturndtls-it >/dev/null 2>&1 || true' EXIT
docker run -d --name akio-turndtls-it -v "$ROOT":/w -w /w -v akio-webrtc-dtls-target:/tmp/t rust:1 \
  sleep infinity >/dev/null
RS=/tmp/t/release/examples/webrtc-interop
docker exec akio-turndtls-it openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj /CN=localhost -days 1 -keyout /tmp/t/coturn.key -out /tmp/t/coturn.crt 2>/dev/null
docker exec akio-turndtls-it chmod 644 /tmp/t/coturn.key /tmp/t/coturn.crt # coturn runs as nobody
docker run -d --name akio-coturndtls-it --network container:akio-turndtls-it \
  -v akio-webrtc-dtls-target:/tmp/t coturn/coturn:4.6 -n --listening-ip=127.0.0.1 \
  --listening-port=3478 --tls-listening-port=5349 --relay-ip=127.0.0.1 --realm=only \
  --user=alice:wonderland --lt-cred-mech --fingerprint --allow-loopback-peers --no-cli \
  --cert=/tmp/t/coturn.crt --pkey=/tmp/t/coturn.key --no-tcp --no-tls --log-file=stdout >/dev/null
docker exec -d akio-turndtls-it $RS turn 127.0.0.1:9703 127.0.0.1 alice wonderland \
  127.0.0.1:9713 127.0.0.1:9714 127.0.0.1:9715
sleep 2
echo "== coturn turnutils_uclient over DTLS against akio-turn"
docker exec akio-coturndtls-it turnutils_uclient -y -n 20 -m 2 -l 100 -u alice -w wonderland \
  -r only -p 9715 -S 127.0.0.1 >/tmp/uclient-dtls.log 2>&1 || { tail -20 /tmp/uclient-dtls.log; exit 1; }
grep -E "start_mclient: tot_send_msgs=|Total lost" /tmp/uclient-dtls.log
awk -F'tot_send_msgs=|, tot_recv_msgs=' '/start_mclient: tot_send_msgs=/ { s = $2; r = $3 }
  END { exit !(s + 0 > 0 && s + 0 == r + 0) }' /tmp/uclient-dtls.log
grep -q "Total lost packets 0 " /tmp/uclient-dtls.log
echo "== akio_turn client over DTLS against coturn"
docker exec akio-turndtls-it $RS turn-client dtls 127.0.0.1:5349 alice wonderland
echo "== only Endpoints relayed through coturn over DTLS"
docker exec akio-turndtls-it $RS relay-echo "turns:127.0.0.1:5349?transport=udp" alice wonderland
echo "== only Endpoints relayed through akio-turn over DTLS"
docker exec akio-turndtls-it $RS relay-echo "turns:127.0.0.1:9715?transport=udp" alice wonderland
echo "turn over dtls interop: all passed"
