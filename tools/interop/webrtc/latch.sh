#!/usr/bin/env bash
# Latching media without ICE behind a real NAT (ADR-077), in a Linux container (Docker,
# privileged for its own network namespaces; nothing changes on the host): a SIP-style phone
# (SDES-SRTP, no ICE, its private address 10.99.0.2:5004 in c= / m=) in namespace "phone"
# behind an iptables MASQUERADE NAT (random UDP ports 40000-40999) calls a SIP-style gateway
# at 10.99.1.2 in namespace "gw", which has no route back to the private network. The phone
# speaks first; the gateway echoes.
#   1. latching off: the gateway sends to the private address, nothing comes back to the phone;
#   2. ONLY_INTEROP_LATCH=once: the gateway latches onto the NAT's mapping, 100 packets echoed;
#   3. a NAT rebinding mid-call (the phone's conntrack entry deleted, so its next packet gets a
#      new random port): with once the echo stops; with rebind (after 1 s of silence from the
#      old mapping) the gateway follows and 300 packets come back.
# The gateway's statistics say how often it latched.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
docker run --rm --privileged -v "$ROOT":/w -w /w -v only-cargo-reg:/usr/local/cargo/registry \
  -v only-ecnlatch-target:/tmp/t -e CARGO_TARGET_DIR=/tmp/t rust:1 bash -c '
set -eu
apt-get -qq update >/dev/null && apt-get -qq install -y iproute2 iptables conntrack >/dev/null 2>&1
cargo build -q --release -p only-webrtc --example webrtc-interop
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
PORT=5100
gateway() { # <latch> -> starts the gateway on $PORT, its log in /tmp/gw-$PORT.log
  ip netns exec gw env ONLY_INTEROP_LATCH=$1 $RS sip-gateway 10.99.1.2:$PORT 10.99.1.2:$((PORT + 1)) \
    >/tmp/gw-$PORT.log 2>&1 &
  GW=$!
  sleep 0.5
}
phone() { # <n> [rebind-after-seconds]
  if [ -n "${2:-}" ]; then
    (sleep "$2"; conntrack -D -p udp -s 10.99.0.2 >/dev/null 2>&1 || true) &
  fi
  ip netns exec phone env ONLY_INTEROP_SIP=1 ONLY_INTEROP_BIND=10.99.0.2:5004 \
    $RS client 10.99.1.2:$((PORT + 1)) sip "$1" 2>/tmp/phone.log
}
latched() { grep -o "latched: [0-9]*" /tmp/gw-$PORT.log | tail -1; }
finish() { kill $GW 2>/dev/null || true; wait $GW 2>/dev/null || true; PORT=$((PORT + 10)); }

echo "== latching off"
gateway off
if phone 100; then echo "FAIL: echo without latching"; exit 1; fi
echo "no echo; gateway $(latched)"
finish
echo "== latching once"
gateway once
phone 100
echo "gateway $(latched)"
finish
echo "== NAT rebinding, latching once"
gateway once
if phone 300 2; then echo "FAIL: once followed a rebinding"; exit 1; fi
echo "echo stopped after the rebinding; gateway $(latched)"
finish
echo "== NAT rebinding, latching rebind (1 s)"
gateway rebind
phone 300 2
echo "gateway $(latched)"
finish
echo "ok: latch.sh"
'
