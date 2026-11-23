#!/usr/bin/env bash
# akio-quic / akio-h3 against quiche (Cloudflare), both directions, in Docker (Debian's rust:1
# image). quiche's example apps (`quiche-client`, `quiche-server`) are built from the pinned
# release tag, once, into the volume `quiche-apps-$QUICHE` (BoringSSL from quiche's submodule;
# needs cmake and libclang, installed in the container):
#   - quiche-client -> akio-h3 server: GET (quiche-client starts with a reserved version, so
#     every connection goes through Version Negotiation first), 50 requests on one connection,
#     a 300 KB POST echoed, a streamed response with trailers, 0-RTT with a resumed session (in
#     v1; the server logs the early request), QUIC v1 without negotiation, and client migration
#     to a new source port;
#   - quiche-client (HTTP/0.9 over QUIC, ALPN hq-interop: raw streams) -> akio-quic server, with
#     and without Retry: a small GET and 5 MiB;
#   - akio-h3 client (`H3Client`) -> quiche-server, with Retry (its default) and without: GET,
#     4 MiB, 404, POSTs that quiche answers with 405 after STOP_SENDING (100 B and 3 MiB, the
#     latter far past its stream window), 200 concurrent requests over its 100-stream limit, a
#     streamed response paused and resumed;
#   - akio-quic client (hq-interop) -> quiche-server, with and without Retry: 20 concurrent
#     GETs and 5 MiB.
#
#   tools/interop/quic/quiche.sh
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
VOL=${AKIO_INTEROP_TARGET:-akio-interop-target}
QUICHE=${QUICHE:-0.30.1}
docker run --rm -v "$ROOT":/w -w /w -v akio-cargo-reg:/usr/local/cargo/registry \
    -v "$VOL":/tmp/t -e CARGO_TARGET_DIR=/tmp/t -v "quiche-apps-$QUICHE":/opt/quiche \
    -e QUICHE="$QUICHE" rust:1 bash -c '
set -eu
QD=/opt/quiche/target/release
if [ ! -x $QD/quiche-client ] || [ ! -x $QD/quiche-server ]; then
    echo "== building quiche $QUICHE apps"
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends cmake libclang-dev >/dev/null 2>&1
    rm -rf /opt/quiche/src
    git clone -q --recursive --depth 1 --shallow-submodules --branch "$QUICHE" \
        https://github.com/cloudflare/quiche /opt/quiche/src
    (cd /opt/quiche/src && CARGO_TARGET_DIR=/opt/quiche/target cargo build -q --release -p quiche_apps)
fi
QC=$QD/quiche-client
QS=$QD/quiche-server
cargo build -q --release -p akio-h3 --example h3-interop -p akio-quic --example quic-interop
H3=/tmp/t/release/examples/h3-interop
RQ=/tmp/t/release/examples/quic-interop
cd /tmp
mkdir -p root out
echo "hello from quiche" > root/index.html
head -c 5242880 /dev/zero | tr "\0" W > root/5242880
CERT="--cert /opt/quiche/src/apps/src/bin/cert.crt --key /opt/quiche/src/apps/src/bin/cert.key"
$H3 server 127.0.0.1:9401 0rtt > h3.log 2>&1 &
$RQ server 127.0.0.1:9501 hq > hq.log 2>&1 &
$RQ server 127.0.0.1:9503 hq retry > hq-retry.log 2>&1 &
$QS --listen 127.0.0.1:9411 --root root $CERT > qs-retry.log 2>&1 &
$QS --listen 127.0.0.1:9412 --root root $CERT --no-retry > qs.log 2>&1 &
trap "kill \$(jobs -p) 2>/dev/null || true" EXIT
sleep 1
qc() { timeout 30 $QC --no-verify "$@"; }
expect() { # WHAT GOT WANT
    [ "$2" = "$3" ] || { echo "FAIL: $1: got \"$2\", want \"$3\""; exit 1; }
    echo "ok: $1"
}
echo "== quiche-client -> akio-h3 server"
expect "GET / (after Version Negotiation)" "$(qc https://127.0.0.1:9401/)" "hello h3"
expect "GET / in QUIC v1" "$(qc --wire-version 00000001 https://127.0.0.1:9401/)" "hello h3"
expect "50 requests on one connection" \
    "$(qc -n 50 https://127.0.0.1:9401/user/7 | grep -o "user 7 Http3" | wc -l)" 50
head -c 300000 /dev/urandom > body.bin
rm -f out/*
qc --method POST --body body.bin --dump-responses out https://127.0.0.1:9401/echo
cmp body.bin out/echo && echo "ok: POST /echo, 300 KB"
s=$(qc https://127.0.0.1:9401/stream)
expect "streamed response" "$(echo "$s" | head -1) .. $(echo "$s" | tail -1) ($(echo "$s" | wc -l) lines)" \
    "line 0 .. line 49 (50 lines)"
rm -f sess
qc --session-file sess https://127.0.0.1:9401/ > /dev/null
[ -s sess ] || { echo "FAIL: no session saved"; exit 1; }
# In v1 from the start: quiche-client starting in its reserved version sends its 0-RTT packets
# in that version, the server drops them with the Version Negotiation, and quiche does not
# send the early data again in v1 (the connection resumes without 0-RTT).
expect "GET / in 0-RTT" \
    "$(qc --wire-version 00000001 --session-file sess --early-data https://127.0.0.1:9401/)" "hello h3"
expect "early request on akio-h3" "$(grep -c "early request" h3.log || true)" 1
expect "GET / migrating to a new source port" \
    "$(qc --enable-active-migration --perform-migration https://127.0.0.1:9401/)" "hello h3"
echo "== quiche-client (HTTP/0.9, hq-interop) -> akio-quic server"
for p in 9501 9503; do
    expect "GET /index.html ($p)" "$(qc --http-version HTTP/0.9 https://127.0.0.1:$p/index.html)" "hello hq"
    rm -f out/*
    qc --http-version HTTP/0.9 --dump-responses out https://127.0.0.1:$p/5242880
    cmp root/5242880 out/5242880 && echo "ok: GET /5242880 ($p)"
done
echo "== akio-h3 client -> quiche-server (Retry)"
$H3 client-quiche 127.0.0.1:9411
echo "== akio-h3 client -> quiche-server (no Retry)"
$H3 client-quiche 127.0.0.1:9412
echo "== akio-quic client (hq-interop) -> quiche-server (Retry)"
$RQ client 127.0.0.1:9411 hq 5242880
echo "== akio-quic client (hq-interop) -> quiche-server (no Retry)"
$RQ client 127.0.0.1:9412 hq 5242880
echo "quiche interop: all passed"
'
