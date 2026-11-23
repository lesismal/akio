#!/usr/bin/env bash
# mDNS over IPv4 on two interfaces (ADR-078 update 3), in a Linux container (Docker): no network
# from Docker (`--network none`), two veth pairs a0 <-> a1 and b0 <-> b1 with IPv4 on a0
# (10.66.1.1/24) and b0 (10.66.2.1/24) only, the default route on a0. Two links that are not
# wired to each other: a datagram sent out of a0 or b0 reaches this host's sockets (multicast
# loopback) as arriving on that interface, and the far ends (no IPv4) drop it.
#   1. the akio-webrtc mDNS tests and the engine's multicast tests there, on epoll and with
#      AKIO_TEST_BACKEND=uring: `224.0.0.251` joined and sent to on both interfaces, an IPv4
#      address claimed and answered on its own interface only (none of these tests skipped);
#   2. avahi-daemon (IPv4 only, on b0 alone, check-response-ttl=yes) resolving the name an akio
#      Endpoint conceals 10.66.2.1 behind: b0 is not the default interface, the one a single
#      IPv4 membership used to be limited to;
#   3. the same avahi not resolving the name an Endpoint conceals 10.66.1.1 (a0) behind: the
#      record is not of use on b0's link and is neither announced nor answered there (§6.2);
#   4. an akio Endpoint on 10.66.1.1 resolving a name only avahi publishes on b0 (10.66.2.1, a
#      second Endpoint there) and connecting to it: its queries go out of b0 too.
# The examples and tests are built in rust:1; the image adds avahi, dbus and iproute2 (the same
# image as mdns6.sh).
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
IMG=akio-mdns6-avahi
C=akio-mdns4-it
VOL=akio-mdns4-target
docker run --rm -v "$ROOT":/w -w /w -v akio-cargo-reg:/usr/local/cargo/registry \
  -v $VOL:/tmp/t -e CARGO_TARGET_DIR=/tmp/t rust:1 sh -ec '
  cargo build -q --release -p akio-webrtc --example webrtc-interop
  for t in "-p akio-webrtc --test mdns" "-p akio --test shared_ports" "-p akio-sys --lib"; do
    cargo test --no-run $t 2>&1 | sed -n "s/.*Executable .*(\(.*\))/\1/p" | tail -1
  done >/tmp/t/mdns4-tests.txt
  test "$(grep -c . /tmp/t/mdns4-tests.txt)" = 3'
docker build -q -t $IMG - >/dev/null <<'EOF'
FROM rust:1
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    avahi-daemon avahi-utils dbus iproute2 >/dev/null && rm -rf /var/lib/apt/lists/*
EOF
docker rm -f $C >/dev/null 2>&1 || true
trap 'docker rm -f $C >/dev/null 2>&1 || true' EXIT
# seccomp=unconfined: Docker's default profile blocks io_uring_setup(2).
docker run -d --name $C --network none --cap-add NET_ADMIN --security-opt seccomp=unconfined \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.default.disable_ipv6=0 \
  --sysctl net.ipv6.conf.default.accept_dad=0 --sysctl net.ipv6.conf.all.accept_dad=0 \
  -v $VOL:/tmp/t $IMG sleep infinity >/dev/null
x() { docker exec $C sh -c "$1"; }
x 'ip link add a0 type veth peer name a1 && ip link add b0 type veth peer name b1 &&
   for i in a0 a1 b0 b1; do ip link set $i up; done &&
   ip addr add 10.66.1.1/24 dev a0 && ip addr add 10.66.2.1/24 dev b0 &&
   ip route add default via 10.66.1.254 dev a0 onlink'
x 'ip -br addr; ip route; ip -4 route get 224.0.0.251'
T_MDNS=$(x 'sed -n 1p /tmp/t/mdns4-tests.txt')
T_SHARED=$(x 'sed -n 2p /tmp/t/mdns4-tests.txt')
T_SYS=$(x 'sed -n 3p /tmp/t/mdns4-tests.txt')

echo "== mDNS and multicast tests on two IPv4 links (epoll, then io_uring)"
for b in epoll uring; do
  x "AKIO_TEST_BACKEND=$b $T_SYS iface 2>&1 | grep 'test result'"
  x "AKIO_TEST_BACKEND=$b $T_SHARED --nocapture --test-threads=1 2>&1 | grep -E 'skipped|looped|not sent|test result'" | tee /tmp/mdns4-shared.out
  x "AKIO_TEST_BACKEND=$b $T_MDNS --nocapture 2>&1 | grep -E 'skipped|connected|test result'" | tee /tmp/mdns4-tests.out
  grep -q "2 of 2 interfaces looped back" /tmp/mdns4-shared.out
  if grep -q skipped /tmp/mdns4-tests.out; then echo "FAIL: an mDNS test was skipped"; exit 1; fi
  grep -q "test result: ok" /tmp/mdns4-tests.out
  grep -q "test result: ok" /tmp/mdns4-shared.out
done

echo "== avahi-daemon (IPv4 only, check-response-ttl=yes) on b0"
x 'cat >/etc/avahi/avahi-daemon.conf <<EOC
[server]
use-ipv4=yes
use-ipv6=no
allow-interfaces=b0
check-response-ttl=yes
enable-dbus=yes
ratelimit-burst=1000
[wide-area]
enable-wide-area=no
[publish]
publish-hinfo=no
publish-workstation=no
EOC
mkdir -p /run/dbus && dbus-daemon --system --fork && avahi-daemon -D --no-rlimits --no-drop-root --no-chroot'
for _ in $(seq 50); do x 'avahi-daemon -c' && break; sleep 0.2; done
sleep 2 # avahi probes and announces its host name first
RS=/tmp/t/release/examples/webrtc-interop

echo "== avahi on b0 resolves the name an akio Endpoint conceals 10.66.2.1 (b0) behind"
x "AKIO_LOG=akio_webrtc=debug $RS mdns-conceal '10.66.2.1:0' 12 >/tmp/conceal-b.out 2>/tmp/conceal-b.log &"
for _ in $(seq 50); do x 'grep -q ^name /tmp/conceal-b.out' && break; sleep 0.1; done
NAME_B=$(x 'sed -n "s/^name //p" /tmp/conceal-b.out')
OUT=$(x "timeout 10 avahi-resolve -4 -n $NAME_B" || true)
echo "avahi-resolve $NAME_B: $OUT"
echo "$OUT" | grep -q "10.66.2.1"

echo "== avahi on b0 does not resolve the name an akio Endpoint conceals 10.66.1.1 (a0) behind"
x "AKIO_LOG=akio_webrtc=debug $RS mdns-conceal '10.66.1.1:0' 12 >/tmp/conceal-a.out 2>/tmp/conceal-a.log &"
for _ in $(seq 50); do x 'grep -q ^name /tmp/conceal-a.out' && break; sleep 0.1; done
NAME_A=$(x 'sed -n "s/^name //p" /tmp/conceal-a.out')
OUT=$(x "timeout 6 avahi-resolve -4 -n $NAME_A 2>&1" || true)
echo "avahi-resolve $NAME_A: ${OUT:-(nothing)}"
if echo "$OUT" | grep -q "10.66.1.1"; then echo "FAIL: an a0 address resolved on b0"; exit 1; fi
if x "grep -q 'mdns: answering' /tmp/conceal-a.log"; then echo "FAIL: answered from b0"; exit 1; fi

echo "== an akio Endpoint on 10.66.1.1 resolves a name only avahi publishes on b0, and connects"
PUB=$(x 'cat /proc/sys/kernel/random/uuid').local
x "avahi-publish -a -R $PUB 10.66.2.1 >/tmp/publish.log 2>&1 &"
for _ in $(seq 50); do x "grep -q Established /tmp/publish.log" && break; sleep 0.1; done
x "cat /tmp/publish.log"
x "AKIO_LOG=akio_webrtc=debug $RS mdns-resolve '10.66.1.1:0' '10.66.2.1:0' $PUB 2>/tmp/resolve.log"
x "grep -m1 'mdns: $PUB is' /tmp/resolve.log"
x "grep -qE 'mdns: $PUB is \\[10.66.2.1\\] \\(from 10.66.2.1:5353\\)' /tmp/resolve.log"
echo "mdns over ipv4 on two interfaces: all passed"
