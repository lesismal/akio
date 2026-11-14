#!/usr/bin/env bash
# flash-dpdk end-to-end tests against the Linux kernel stack
# (crates/flash-dpdk/tests/kernel_peer.rs): the userspace stack over smoltcp's TAP device, over
# AF_PACKET on a veth pair and over DPDK's net_tap poll-mode driver (1 and 2 queues), with a std
# UdpSocket / TcpStream on the kernel side. Also runs the memory-wire tests and clippy with DPDK
# linked.
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
    docker build -t flash-dpdk-dev tools/dpdk
    exec docker run --rm --cap-add NET_ADMIN --device /dev/net/tun \
        -v "$PWD":/w -w /w -v flash-cargo-reg:/usr/local/cargo/registry \
        -e CARGO_TARGET_DIR=/tmp/t flash-dpdk-dev tools/dpdk/test.sh --inside
fi

export FLASH_DPDK_REQUIRE=1 # fail the build if libdpdk is not found
pkg-config --modversion libdpdk
cargo clippy -p flash-dpdk --all-targets --features pmd -- -D warnings
cargo test -p flash-dpdk --features pmd --test memory
FLASH_TAP_TEST=1 FLASH_DPDK_TEST=1 cargo test -p flash-dpdk --features pmd --test kernel_peer \
    -- --nocapture --test-threads=1
