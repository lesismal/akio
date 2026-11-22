# Reference DTLS 1.3 peers for tools/interop/dtls/run.sh: OpenSSL 4.1 (built here: Debian ships
# 3.5, which has no DTLS 1.3) and wolfSSL 5.8.4 (DTLS 1.3, connection IDs, 0-RTT, post-handshake
# authentication), on rust:1 so the same image also builds the akio-dtls example.
#   docker build -t akio-dtls-interop tools/interop/dtls
FROM rust:1
RUN apt-get update && apt-get install -y --no-install-recommends autoconf automake libtool \
      perl make gcc git ca-certificates && rm -rf /var/lib/apt/lists/*
ARG OPENSSL_TAG=openssl-4.1.0
ARG WOLFSSL_TAG=v5.8.4-stable
RUN git clone --depth 1 -b "$OPENSSL_TAG" https://github.com/openssl/openssl /src/openssl && \
    cd /src/openssl && ./Configure --prefix=/opt/openssl --libdir=lib no-docs no-tests && \
    make -j"$(nproc)" >/dev/null && make install_sw >/dev/null && rm -rf /src/openssl
RUN git clone --depth 1 -b "$WOLFSSL_TAG" https://github.com/wolfSSL/wolfssl /src/wolfssl && \
    cd /src/wolfssl && ./autogen.sh >/dev/null && \
    ./configure --prefix=/opt/wolfssl --enable-dtls --enable-dtls13 --enable-dtlscid \
      --enable-dtls-frag-ch --enable-session-ticket --enable-psk --enable-curve25519 \
      --enable-ed25519 --enable-aesgcm --enable-chacha --enable-poly1305 --enable-hrrcookie \
      --enable-secure-renegotiation --enable-srtp --enable-keying-material \
      --enable-earlydata --enable-postauth \
      --enable-debug >/dev/null && \
    make -j"$(nproc)" >/dev/null && make install >/dev/null && \
    cp examples/client/.libs/client /opt/wolfssl/bin/wolfssl-client && \
    cp examples/server/.libs/server /opt/wolfssl/bin/wolfssl-server && \
    cp -r certs /opt/wolfssl/certs && rm -rf /src/wolfssl
ENV LD_LIBRARY_PATH=/opt/openssl/lib:/opt/wolfssl/lib
ENV PATH=/opt/openssl/bin:/opt/wolfssl/bin:$PATH
# install_sw installs no openssl.cnf; Debian's works. OPENSSL_armcap=0: OpenSSL 4.1's ARM
# capability probing dies with SIGILL under Docker Desktop on Apple silicon (no effect on x86).
ENV OPENSSL_CONF=/etc/ssl/openssl.cnf OPENSSL_armcap=0
