#!/usr/bin/env bash
# mDNS over IPv6 multicast (ADR-054, ADR-078) on an IPv6-only link, in a Linux container
# (Docker): no IPv4 at all (`--network none`), a veth pair v0 <-> v1 with link-local and ULA
# addresses (fd00:6::1 on v0, fd00:6::2 on v1), so ff02::fb is the only mDNS group there is.
#   1. the only-webrtc mDNS tests and the engine's multicast tests in that namespace, on epoll
#      and with ONLY_TEST_BACKEND=uring (no system responder: our sockets answer each other);
#   2. avahi-daemon (IPv6 only, on v1, check-response-ttl=yes: answers sent with a hop limit
#      other than 255 are dropped) resolving the name an only Endpoint conceals fd00:6::1
#      behind (avahi-resolve -6);
#   3. an only Endpoint resolving a name only avahi publishes (avahi-publish -a, fd00:6::2)
#      and connecting to it (webrtc-interop mdns-resolve), the answer arriving over IPv6.
# The examples and tests are built in rust:1; the image adds avahi, dbus and iproute2.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
IMG=only-mdns6-avahi
C=only-mdns6-it
VOL=only-mdns6-target
# One rust:1 run builds the example and the test executables, and lists the latter (the paths
# cargo prints after "Executable") in the target volume.
docker run --rm -v "$ROOT":/w -w /w -v only-cargo-reg:/usr/local/cargo/registry \
  -v $VOL:/tmp/t -e CARGO_TARGET_DIR=/tmp/t rust:1 sh -ec '
  cargo build -q --release -p only-webrtc --example webrtc-interop
  for t in "-p only-webrtc --test mdns" "-p only --test shared_ports" "-p only-sys --lib"; do
    cargo test --no-run $t 2>&1 | sed -n "s/.*Executable .*(\(.*\))/\1/p" | tail -1
  done >/tmp/t/mdns6-tests.txt
  test "$(grep -c . /tmp/t/mdns6-tests.txt)" = 3'
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
x 'ip link add v0 type veth peer name v1 && ip link set v0 up && ip link set v1 up &&
   ip -6 addr add fd00:6::1/64 dev v0 nodad && ip -6 addr add fd00:6::2/64 dev v1 nodad'
for _ in $(seq 50); do
  x 'ip -6 addr show scope link | grep -c "inet6 fe80" | grep -qx 2 && ! ip -6 addr | grep -q tentative' && break
  sleep 0.1
done
x 'ip -br addr'
# No IPv4 multicast here: 224.0.0.251 has no route.
x 'ip -4 route get 224.0.0.251 >/dev/null 2>&1 && { echo "unexpected IPv4 route"; exit 1; } || true'
T_MDNS=$(x 'sed -n 1p /tmp/t/mdns6-tests.txt')
T_SHARED=$(x 'sed -n 2p /tmp/t/mdns6-tests.txt')
T_SYS=$(x 'sed -n 3p /tmp/t/mdns6-tests.txt')

echo "== mDNS and multicast tests on the IPv6-only link (epoll, then io_uring)"
for b in epoll uring; do
  x "ONLY_TEST_BACKEND=$b $T_SYS multicast_hops 2>&1 | grep 'test result'"
  x "ONLY_TEST_BACKEND=$b $T_SHARED --nocapture 2>&1 | grep -E 'skipped|test result'" | tee /tmp/mdns6-shared.out
  x "ONLY_TEST_BACKEND=$b $T_MDNS --nocapture 2>&1 | grep -E 'skipped|test result'" | tee /tmp/mdns6-tests.out
  # Nothing skipped: the IPv6 tests and the concealing ones (over ff02::fb only) all ran.
  if grep -q skipped /tmp/mdns6-tests.out; then echo "FAIL: a test was skipped"; exit 1; fi
  grep -q "test result: ok" /tmp/mdns6-tests.out
  grep -q "test result: ok" /tmp/mdns6-shared.out
done

echo "== avahi-daemon (IPv6 only, check-response-ttl=yes) on v1"
x 'cat >/etc/avahi/avahi-daemon.conf <<EOC
[server]
use-ipv4=no
use-ipv6=yes
allow-interfaces=v1
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

echo "== avahi resolves the name an only Endpoint conceals fd00:6::1 behind"
x "ONLY_LOG=only_webrtc=debug $RS mdns-conceal '[fd00:6::1]:0' 12 >/tmp/conceal.out 2>/tmp/conceal.log &"
for _ in $(seq 50); do x 'grep -q ^name /tmp/conceal.out' && break; sleep 0.1; done
NAME=$(x 'sed -n "s/^name //p" /tmp/conceal.out')
echo "concealed name: $NAME"
OUT=$(x "timeout 10 avahi-resolve -6 -n $NAME" || true)
echo "avahi-resolve: $OUT"
x 'grep -m1 "mdns: answering" /tmp/conceal.log'
echo "$OUT" | grep -q "fd00:6::1"

echo "== an only Endpoint resolves a name only avahi publishes (fd00:6::2) and connects to it"
PUB=$(x 'cat /proc/sys/kernel/random/uuid').local
x "avahi-publish -a -R $PUB fd00:6::2 >/tmp/publish.log 2>&1 &"
for _ in $(seq 50); do x "grep -q Established /tmp/publish.log" && break; sleep 0.1; done
x "cat /tmp/publish.log"
x "ONLY_LOG=only_webrtc=debug $RS mdns-resolve '[fd00:6::1]:0' '[fd00:6::2]:0' $PUB 2>/tmp/resolve.log"
x "grep -m1 'mdns: $PUB is' /tmp/resolve.log"
# Resolved from avahi's answer over IPv6 (an IPv6 source on the mDNS port: there is no IPv4).
x "grep -qE 'mdns: $PUB is \\[fd00:6::2\\] \\(from \\[[0-9a-f:]+(%[0-9]+)?\\]:5353\\)' /tmp/resolve.log"
echo "mdns over ipv6 interop: all passed"
