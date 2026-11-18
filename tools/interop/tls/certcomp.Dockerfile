# OpenSSL 3.5 built with brotli, zstd and zlib certificate compression (Debian's OpenSSL has
# zlib and zstd only), plus what tools/interop/tls/run.sh needs (Rust, Go, GnuTLS):
#
#   docker build -t only-certcomp-interop -f tools/interop/tls/certcomp.Dockerfile tools/interop/tls
#   docker run --rm -v "$PWD":/w -w /w -e CARGO_TARGET_DIR=/tmp/t only-certcomp-interop \
#     tools/interop/tls/run.sh
FROM rust:1
RUN apt-get update -qq && apt-get install -y -qq golang-go gnutls-bin libbrotli-dev libzstd-dev \
    zlib1g-dev >/dev/null
RUN curl -sSL https://github.com/openssl/openssl/releases/download/openssl-3.5.4/openssl-3.5.4.tar.gz \
    | tar xz -C /tmp && cd /tmp/openssl-3.5.4 \
    && ./Configure enable-brotli enable-zstd enable-zlib --prefix=/opt/ossl --libdir=lib >/dev/null \
    && make -j"$(nproc)" >/dev/null 2>&1 && make install_sw install_ssldirs >/dev/null && rm -rf /tmp/openssl-3.5.4
ENV PATH=/opt/ossl/bin:$PATH LD_LIBRARY_PATH=/opt/ossl/lib
