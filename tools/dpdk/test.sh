#!/usr/bin/env bash
# only-dpdk end-to-end tests against the Linux kernel stack
# (crates/only-dpdk/tests/kernel_peer.rs): the userspace stack over a TAP device, over AF_PACKET
# on veth pairs (also with `tc netem` loss / delay / reordering, large windows, 500 concurrent
# connections) and over DPDK's net_tap poll-mode driver (1 and 2 queues), over IPv4 and IPv6
# (ping -6, ECN and pacing on a lossy link), with std UdpSocket /
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
    docker build -t only-dpdk-dev tools/dpdk
    exec docker run --rm --cap-add NET_ADMIN --device /dev/net/tun \
        --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.default.disable_ipv6=0 \
        --sysctl net.ipv4.tcp_ecn=1 \
        -v "$PWD":/w -w /w -v only-cargo-reg:/usr/local/cargo/registry \
        -e CARGO_TARGET_DIR=/tmp/t only-dpdk-dev tools/dpdk/test.sh --inside
fi

export ONLY_DPDK_REQUIRE=1 # fail the build if libdpdk is not found
pkg-config --modversion libdpdk
cargo clippy -p only-dpdk --all-targets --features pmd -- -D warnings
cargo test -p only-dpdk --features pmd --test memory
# Release build: the throughput checks (netem, window scaling) measure the stack, not debug code.
ONLY_TAP_TEST=1 ONLY_DPDK_TEST=1 cargo test --release -p only-dpdk --features pmd --test kernel_peer \
    -- --nocapture --test-threads=1
