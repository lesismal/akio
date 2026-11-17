#!/usr/bin/env bash
# Compatible version negotiation (RFC 9368 section 4) against ngtcp2, which implements it, both
# directions, in Docker (Debian's rust:1 image). ngtcp2's example client and server (1.11, GnuTLS)
# are built from Debian's own source package (`apt-get source ngtcp2`, signed by the archive),
# once, into the volume `ngtcp2-cvn-build`:
#   - ngtcp2 client starting in v1 (listing v1 and v2) -> only-h3 server preferring v2: the
#     connection moves to v2 within the handshake (ngtcp2 logs v2 Handshake packets), the GET
#     succeeds; again with 0-RTT (a resumed request sent early, in v1 packets); a server
#     without the preference keeps v1;
#   - only-quic client starting in v1 -> ngtcp2 server preferring v2: moved to v2; starting in
#     v2 -> ngtcp2 server preferring v1: moved to v1.
#
#   tools/interop/quic/ngtcp2-cvn.sh
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
VOL=${ONLY_INTEROP_TARGET:-only-interop-target}
docker run --rm -v "$ROOT":/w -w /w -v flash-cargo-reg:/usr/local/cargo/registry \
    -v "$VOL":/tmp/t -e CARGO_TARGET_DIR=/tmp/t -v ngtcp2-cvn-build:/opt/ng rust:1 bash -c '
set -eu
sed -i "s/^Types: deb$/Types: deb deb-src/" /etc/apt/sources.list.d/debian.sources
apt-get update -qq
apt-get install -y -qq --no-install-recommends dpkg-dev pkg-config libev-dev libnghttp3-dev \
    libgnutls28-dev openssl >/dev/null 2>&1
NG=$(ls -d /opt/ng/src/ngtcp2-*/ 2>/dev/null | head -1 || true)
if [ -z "$NG" ] || [ ! -x "$NG/examples/gtlsserver" ]; then
    echo "== building ngtcp2 examples from the Debian source package"
    rm -rf /opt/ng/src && mkdir -p /opt/ng/src && cd /opt/ng/src
    apt-get source -qq ngtcp2 >/dev/null 2>&1
    NG=$(ls -d /opt/ng/src/ngtcp2-*/ | head -1)
    cd "$NG"
    ./configure -q --with-gnutls --with-libev --with-libnghttp3 --disable-shared >/dev/null
    make -j"$(nproc)" -s >/dev/null 2>&1
    cd /w
fi
CLI=$NG/examples/gtlsclient
SRV=$NG/examples/gtlsserver
cargo build -q --release -p only-h3 --example h3-interop -p only-quic --example quic-interop
H3=/tmp/t/release/examples/h3-interop
RQ=/tmp/t/release/examples/quic-interop
V2=6b3343cf
cd /tmp
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=localhost \
    -keyout key.pem -out cert.pem >/dev/null 2>&1
mkdir -p htdocs && echo "hello from ngtcp2" > htdocs/index.html
$H3 server 127.0.0.1:9401 prefer-v2 0rtt > h3-prefer.log 2>&1 &
$H3 server 127.0.0.1:9403 > h3-plain.log 2>&1 &
$SRV 127.0.0.1 9411 key.pem cert.pem -d htdocs --preferred-versions v2,v1 > ng-prefer-v2.log 2>&1 &
$SRV 127.0.0.1 9413 key.pem cert.pem -d htdocs --preferred-versions v1,v2 > ng-prefer-v1.log 2>&1 &
trap "kill \$(jobs -p) 2>/dev/null || true" EXIT
sleep 1
# The versions of the Handshake packets an ngtcp2 client received ("pkt rx ... version=0x...
# type=Handshake" in its debug output).
hs_versions() { grep -E "pkt rx .*type=Handshake" "$1" | grep -oE "version=0x[0-9a-f]+" | sort -u | tr "\n" " "; }
ngget() { # LOG PORT [extra args]
    local log=$1 port=$2; shift 2
    timeout 20 $CLI 127.0.0.1 "$port" "https://127.0.0.1:$port/" --exit-on-all-streams-close \
        --no-quic-dump --available-versions v1,v2 -v v1 "$@" > "$log" 2>&1 || { tail -20 "$log"; exit 1; }
}
echo "== ngtcp2 client (v1, lists v2) -> only-h3 server preferring v2"
ngget ng-cli-1.log 9401
grep -q "hello h3" ng-cli-1.log || { echo "FAIL: no response"; tail -20 ng-cli-1.log; exit 1; }
v=$(hs_versions ng-cli-1.log); echo "handshake packets: $v"
[ "$v" = "version=0x$V2 " ] || { echo "FAIL: not moved to v2"; exit 1; }
grep -q "the negotiated version is 0x$V2" ng-cli-*.log
echo "== ngtcp2 client (v1, lists v2) -> only-h3 server preferring v2, 0-RTT"
ngget ng-cli-0.log 9401 --session-file=sess --tp-file=tp --wait-for-ticket
ngget ng-cli-0rtt.log 9401 --session-file=sess --tp-file=tp
grep -q "hello h3" ng-cli-0rtt.log || { echo "FAIL: no 0-RTT response"; exit 1; }
grep -q "type=0RTT" ng-cli-0rtt.log || { echo "FAIL: no 0-RTT sent"; exit 1; }
! grep -q "Early data was rejected" ng-cli-0rtt.log || { echo "FAIL: 0-RTT rejected"; exit 1; }
grep -q "early request" h3-prefer.log || { echo "FAIL: no early request on only-h3"; exit 1; }
# ngtcp2 sent its 0-RTT packets in v1, as RFC 9369 section 4.1 requires.
! grep -E "pkt tx .*type=0RTT" ng-cli-0rtt.log | grep -qv "version=0x00000001" || { echo "FAIL: 0-RTT not in v1"; exit 1; }
v=$(hs_versions ng-cli-0rtt.log); echo "handshake packets: $v"
[ "$v" = "version=0x$V2 " ] || { echo "FAIL: not moved to v2"; exit 1; }
grep -q "the negotiated version is 0x$V2" ng-cli-*.log
echo "== ngtcp2 client (v1, lists v2) -> only-h3 server without a preference: stays v1"
ngget ng-cli-plain.log 9403
v=$(hs_versions ng-cli-plain.log); echo "handshake packets: $v"
[ "$v" = "version=0x00000001 " ] || { echo "FAIL: moved off v1"; exit 1; }
echo "== only-quic client (v1) -> ngtcp2 server preferring v2"
$RQ client 127.0.0.1:9411 alpn h3 handshake-only expect-v2
echo "== only-quic client (v2) -> ngtcp2 server preferring v1"
$RQ client 127.0.0.1:9413 alpn h3 handshake-only v2 expect-v1
echo "ngtcp2 compatible version negotiation interop: all passed"
'
