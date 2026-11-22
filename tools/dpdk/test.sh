#!/usr/bin/env bash
# akio-dpdk end-to-end tests against the Linux kernel stack
# (crates/akio-dpdk/tests/kernel_peer.rs): the userspace stack over a TAP device, over AF_PACKET
# on veth pairs (also with `tc netem` loss / delay / reordering, large windows, 500 concurrent
# connections) and over DPDK's net_tap poll-mode driver (1 and 2 queues), over IPv4 and IPv6
# (ping -6, ECN and pacing on a lossy link, SLAAC and duplicate address detection against
# radvd and the kernel), Accurate ECN against the kernel's (Linux 6.18+: the container's
# net.ipv4.tcp_ecn is set to 3; older kernels skip it), with std UdpSocket /
# TcpStream on the kernel side, and dials from the stack to the kernel. Also runs the
# memory-wire tests and clippy with DPDK linked.
#
#   tools/dpdk/test.sh            # from the repository root, on a host with Docker
#   tools/dpdk/test.sh --inside   # inside a container/VM that already has DPDK, CAP_NET_ADMIN
#                                 # and /dev/net/tun (what the `dpdk` CI job runs)
#
# Docker image: tools/dpdk/Dockerfile (rust:1 + the distribution's dpdk-dev, DPDK 24.11 on
# Debian 13). No hugepages or NIC are needed: the EAL runs with --no-huge --no-shconf --no-pci
# and the port is a net_tap vdev.
set -euo pipefail
cd "$(dirname "$0")/../.."

if [ "${1:-}" != "--inside" ]; then
    docker build -t akio-dpdk-dev tools/dpdk
    exec docker run --rm --cap-add NET_ADMIN --device /dev/net/tun \
        --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.default.disable_ipv6=0 \
        --sysctl net.ipv4.tcp_ecn=1 -e AKIO_TEST_NETNS_SYSCTL=1 -e AKIO_TEST_EXPECT_RADVD=1 \
        -v "$PWD":/w -w /w -v akio-cargo-reg:/usr/local/cargo/registry \
        -e CARGO_TARGET_DIR=/tmp/t akio-dpdk-dev tools/dpdk/test.sh --inside
fi

export AKIO_DPDK_REQUIRE=1 # fail the build if libdpdk is not found
pkg-config --modversion libdpdk
cargo clippy -p akio-dpdk --all-targets --features pmd -- -D warnings
cargo test -p akio-dpdk --features pmd --test memory
# Release build: the throughput checks (netem, window scaling) measure the stack, not debug code.
AKIO_TAP_TEST=1 AKIO_DPDK_TEST=1 cargo test --release -p akio-dpdk --features pmd --test kernel_peer \
    -- --nocapture --test-threads=1
