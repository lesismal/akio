# The image tools/interop/bittorrent/run.sh runs in: Rust, aria2, libtorrent 2.0 (Python
# bindings) and nginx (a plain HTTP server with Range support, for web seeds).
FROM rust:1
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      aria2 python3-libtorrent nginx iproute2 >/dev/null \
    && rm -rf /var/lib/apt/lists/*
