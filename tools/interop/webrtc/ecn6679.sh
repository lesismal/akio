#!/usr/bin/env bash
# RFC 6679's own ECN signalling between two only peers over a real Linux NAT (ADR-082,
# ADR-086), in a Linux container (Docker, privileged for its own network namespaces; nothing
# changes on the host). No browser does RFC 6679 (Chrome reads ECN through RFC 8888 only, see
# ecn.sh), so both ends are the webrtc-interop example: a SIP-style phone in namespace "phone"
# behind an iptables MASQUERADE NAT calls a gateway in namespace "gw"; both mark ECT(1) and run
# the estimator, without RFC 8888, so the codepoints travel in RFC 6679 feedback. The kernel
# sets and reads the codepoint on the sockets; an iptables TOS rule on the router can clear it.
#   1. "rtp" initiation (no ICE, SDES): a quarter of the packets marked until feedback confirms
#      them, then all: the gateway's path becomes "capable".
#   2. "leap" (AKIO_INTEROP_ECN_INIT=leap): every packet marked from the start, "capable".
#   3. "ice" initiation (full ICE on both, DTLS-SRTP): an ECN-marked STUN check, the remote
#      echoes the codepoint it read (ECN-CHECK), "capable".
#   4. "ice" with the router clearing the ECN field: the check comes back Not-ECT, the path
#      fails; the rule is removed and after the first retry (10 s) the path is capable again.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
docker run --rm --privileged -v "$ROOT":/w -w /w -v akio-cargo-reg:/usr/local/cargo/registry \
  -v "${TARGET_VOLUME:-akio-ecnlatch-target}":/tmp/t -e CARGO_TARGET_DIR=/tmp/t rust:1 bash -c '
set -eu
apt-get -qq update >/dev/null && apt-get -qq install -y iproute2 iptables conntrack >/dev/null 2>&1
cargo build -q --release -p akio-webrtc --example webrtc-interop
trap "echo --- logs; tail -n 25 /tmp/gw-*.log /tmp/phone*.log" ERR
RS=/tmp/t/release/examples/webrtc-interop
ip netns add phone; ip netns add gw
ip link add p0 type veth peer name p1; ip link set p1 netns phone
ip link add g0 type veth peer name g1; ip link set g1 netns gw
ip addr add 10.99.0.1/24 dev p0; ip link set p0 up
ip addr add 10.99.1.1/24 dev g0; ip link set g0 up
ip netns exec phone sh -c "ip addr add 10.99.0.2/24 dev p1; ip link set p1 up; ip link set lo up; ip route add default via 10.99.0.1"
ip netns exec gw sh -c "ip addr add 10.99.1.2/24 dev g1; ip link set g1 up; ip link set lo up"
sysctl -qw net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o g0 -p udp -j MASQUERADE --to-ports 40000-40999 --random
iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o g0 -j MASQUERADE
export AKIO_INTEROP_ECN=ect1 AKIO_INTEROP_BWE=1000000 AKIO_INTEROP_LATCH=once AKIO_LOG=akio_webrtc=debug
PORT=5300
gateway() {
  ip netns exec gw env AKIO_INTEROP_SIP=$SIP $RS sip-gateway 10.99.1.2:$PORT 10.99.1.2:$((PORT + 1)) \
    >/tmp/gw-$PORT.log 2>&1 &
  GW=$!
  sleep 0.5
}
phone() { # <n>
  ip netns exec phone env AKIO_INTEROP_SIP=$SIP AKIO_INTEROP_BIND=10.99.0.2:5004 \
    $RS client 10.99.1.2:$((PORT + 1)) sip "$1" 2>/tmp/phone-$PORT.log
}
stat() { grep -o "$1: [^,}]*" /tmp/gw-$PORT.log | tail -1; }
report() {
  echo "gateway: $(stat ecn_state), $(stat ecn_marked_sent), $(stat ecn_failures); $(stat ecn_ect_received) from the phone"
  grep -o "ECN check .* saw [A-Za-z(0-9)]*" /tmp/gw-$PORT.log | head -3 || true
}
want() { [ "$(stat ecn_state)" = "ecn_state: \"$1\"" ] || { echo "FAIL: expected $1"; exit 1; }; }
finish() { kill $GW 2>/dev/null || true; wait $GW 2>/dev/null || true; PORT=$((PORT + 10)); }

echo "== rtp initiation (no ICE)"
SIP=1
gateway; phone 300; report; want capable; finish
echo "== leap of faith"
export AKIO_INTEROP_ECN_INIT=leap
gateway; phone 300; report; want capable
[ "$(stat ecn_failures)" = "ecn_failures: 0" ] || { echo "FAIL: leap failed"; exit 1; }
finish
unset AKIO_INTEROP_ECN_INIT
echo "== ice initiation (an ECN-marked STUN check)"
SIP=ice
gateway; phone 300; report; want capable
grep -q "the remote saw Some(1)" /tmp/gw-$PORT.log || { echo "FAIL: no ECN check echoed ECT(1)"; exit 1; }
finish
echo "== ice initiation through a router that clears ECN, then not: the path fails, retries, recovers"
iptables -t mangle -A FORWARD -p udp -j TOS --set-tos 0x00/0x03
(sleep 4; iptables -t mangle -D FORWARD -p udp -j TOS --set-tos 0x00/0x03; echo "(rule removed)") &
gateway; phone 1000; report
grep -q "the remote saw Some(0)" /tmp/gw-$PORT.log || { echo "FAIL: the cleared check was not seen"; exit 1; }
want capable
[ "$(stat ecn_failures)" != "ecn_failures: 0" ] || { echo "FAIL: no failure recorded"; exit 1; }
finish
echo "ok: ecn6679.sh"
'
