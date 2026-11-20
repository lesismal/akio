#!/usr/bin/env bash
# only-quic / only-h3 servers against two more QUIC stacks, in Docker (Debian's rust:1 image, which
# ships them; nothing is downloaded or built besides this workspace):
#   - ngtcp2 1.11 + GnuTLS, through libcurl-gnutls (HTTP/3: GET, POST 300 KB echo, streaming,
#     a streamed request body, many requests on one connection: nghttp3's QPACK encoder uses the
#     dynamic table the server allows; then again with the server's own encoder table on);
#   - OpenSSL 3.5's own QUIC stack, through libcurl (HTTP/3, same checks) and `openssl s_client
#     -quic` (raw QUIC: a stream echoed by quic-interop);
#   - libnghttp3's QPACK decoder (the one curl uses) against only-h3's QPACK encoder, through the
#     `qpack-pipe` example (curl advertises no decoder table, so the wire runs above never use it).
# Only the client side of those stacks is packaged there, so this covers our servers.
#
#   tools/interop/quic/docker.sh
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
VOL=${ONLY_INTEROP_TARGET:-only-interop-target}
docker run --rm -v "$ROOT":/w -w /w -v flash-cargo-reg:/usr/local/cargo/registry \
    -v "$VOL":/tmp/t -e CARGO_TARGET_DIR=/tmp/t rust:1 bash -c '
set -eu
cargo build -q --release -p only-h3 --example h3-interop -p only-quic --example quic-interop
cargo build -q --release -p only-h3 --features fuzzing --example qpack-pipe
/tmp/t/release/examples/h3-interop server 127.0.0.1:9401 > /tmp/h3.log 2>&1 &
/tmp/t/release/examples/h3-interop server 127.0.0.1:9403 qpack > /tmp/h3q.log 2>&1 &
/tmp/t/release/examples/quic-interop server 127.0.0.1:9501 > /tmp/q.log 2>&1 &
sleep 1
echo "== ngtcp2 (libcurl-gnutls) client -> only-h3 server"
python3 tools/interop/h3/libcurl-h3.py libcurl-gnutls.so.4 https://127.0.0.1:9401
echo "== OpenSSL QUIC (libcurl) client -> only-h3 server"
python3 tools/interop/h3/libcurl-h3.py libcurl.so.4 https://127.0.0.1:9401
echo "== ngtcp2 (libcurl-gnutls) client -> only-h3 server with a QPACK encoder table"
python3 tools/interop/h3/libcurl-h3.py libcurl-gnutls.so.4 https://127.0.0.1:9403
echo "== OpenSSL QUIC (libcurl) client -> only-h3 server with a QPACK encoder table"
python3 tools/interop/h3/libcurl-h3.py libcurl.so.4 https://127.0.0.1:9403
echo "== curl --http3-only (OpenSSL QUIC) -> only-h3 server"
out=$(curl -sk --http3-only https://127.0.0.1:9401/)
[ "$out" = "hello h3" ] || { echo "FAIL: curl got: $out"; exit 1; }
echo "ok: $out"
echo "== openssl s_client -quic -> only-quic echo server (raw QUIC, ALPN echo)"
msg="hello raw quic $(date +%s)"
got=$( (echo "$msg"; sleep 1) | timeout 10 openssl s_client -quic -alpn echo -connect 127.0.0.1:9501 \
    -servername localhost -quiet 2>/dev/null | head -1)
[ "$got" = "$msg" ] || { echo "FAIL: s_client got: $got"; exit 1; }
echo "ok: $got"
echo "== libnghttp3 QPACK decoder <- only-h3 QPACK encoder (dynamic table)"
python3 tools/interop/h3/nghttp3-qpack.py libnghttp3.so.9 /tmp/t/release/examples/qpack-pipe
echo "docker interop: all passed"
'
