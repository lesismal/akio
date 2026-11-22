# Benchmark image for tools/bench (see docs/BENCHMARKS.md):
#   docker build -t akio-bench tools/bench
# Rust toolchain from rust:1, load generators (wrk, h2load), perf, and the Go toolchain fib needs.
FROM rust:1
ARG GO_VERSION=1.27.3
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends wrk nghttp2-client linux-perf procps python3 util-linux \
 && rm -rf /var/lib/apt/lists/*
RUN arch=$(dpkg --print-architecture) \
 && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" | tar -C /usr/local -xz
ENV PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local
