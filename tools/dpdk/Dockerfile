# Build/test image for only-dpdk: Rust plus the distribution's DPDK development packages.
# Used by tools/dpdk/test.sh and the `dpdk` CI job.
FROM rust:1
RUN apt-get update \
 && apt-get install -y --no-install-recommends dpdk-dev libdpdk-dev pkg-config iproute2 \
 && rm -rf /var/lib/apt/lists/*
RUN rustup component add clippy rustfmt
