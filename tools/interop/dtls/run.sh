#!/usr/bin/env bash
# akio-dtls interop, both directions each:
#   - OpenSSL `s_client -dtls1_2` / `s_server -dtls1_2` (openssl.sh) inside the rust:1 Docker
#     image, with `-use_srtp` and `-keymatexport` compared byte for byte; LOCAL_OPENSSL=1 uses
#     the host's openssl instead.
#   - pion/dtls v3 (Go; pion/main.go): every SRTP profile, ECDSA and RSA suites, keying
#     material compared; RFC 9146 connection IDs and PSK suites both ways.
#   - DTLS 1.3, CIDs, PSKs, resumption, KeyUpdate, version negotiation against OpenSSL 4.1 and
#     wolfSSL 5.8 (dtls13.sh) in the image built from ./Dockerfile (built on first use;
#     SKIP_DTLS13=1 skips it; DTLS_INTEROP_IMAGE names the image, default akio-dtls-interop:
#     rebuild it after the Dockerfile changes).
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
IMAGE=${DTLS_INTEROP_IMAGE:-akio-dtls-interop}
W=$(mktemp -d)
PIDS=""
trap 'kill $PIDS 2>/dev/null || true; rm -rf "$W"' EXIT

echo "== OpenSSL"
if [ "${LOCAL_OPENSSL:-0}" = 1 ]; then
  cargo build -q --release -p akio-dtls --example dtls-interop --manifest-path "$ROOT/Cargo.toml"
  "$ROOT/tools/interop/dtls/openssl.sh" "$ROOT/target/release/examples/dtls-interop" "$W/openssl"
else
  docker run --rm -v "$ROOT":/w -w /w -v flash-cargo-reg:/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR=/tmp/t rust:1 bash -c \
    'cargo build -q --release -p akio-dtls --example dtls-interop &&
     tools/interop/dtls/openssl.sh /tmp/t/release/examples/dtls-interop /tmp/openssl'
fi

echo "== pion/dtls"
cargo build -q --release -p akio-dtls --example dtls-interop --manifest-path "$ROOT/Cargo.toml"
RS=$ROOT/target/release/examples/dtls-interop
(cd "$ROOT/tools/interop/dtls/pion" && GOFLAGS=-mod=mod go build -o "$W/pion" .)
GO=$W/pion
cd "$W"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ec.key -out ec.pem \
  -days 30 -subj /CN=pion-ec 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa.key -out rsa.pem -days 30 \
  -subj /CN=pion-rsa 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout akio.key \
  -out akio.pem -days 30 -subj /CN=akio 2>/dev/null
fp() { echo "sha-256 $(openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2)"; }
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; cat "$f"; done; exit 1; }
port=25430
same_material() {
  local a b
  a=$(sed -n 's/^SRTP_MATERIAL //p' "$1")
  b=$(sed -n 's/^SRTP_MATERIAL //p' "$2")
  [ -n "$a" ] && [ "$a" = "$b" ]
}
suite_of() { sed -n 's/^CONNECTED suite=\([^ ]*\).*/\1/p' "$1"; }

for profile in SRTP_AEAD_AES_128_GCM SRTP_AEAD_AES_256_GCM SRTP_AES128_CM_SHA1_80 SRTP_AES128_CM_SHA1_32; do
  for kind in ec rsa; do
    suite=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    [ "$kind" = rsa ] && suite=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    [ "$profile" = SRTP_AES128_CM_SHA1_32 ] && [ "$kind" = ec ] &&
      suite=TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    name=$profile-$kind
    # pion server, akio-dtls client.
    port=$((port + 1))
    "$GO" server "127.0.0.1:$port" "$kind.pem" "$kind.key" "$profile" "$suite" >"ps-$name.log" 2>&1 &
    PIDS="$PIDS $!"
    sleep 0.5
    "$RS" client "127.0.0.1:$port" --cert akio.pem --key akio.key --srtp "$profile" \
      --fingerprint "$(fp "$kind.pem")" --message "hello from akio-dtls" >"oc-$name.log" 2>&1 ||
      fail "$name: akio-dtls client"
    sleep 0.3
    same_material "oc-$name.log" "ps-$name.log" || fail "$name: keying material differs"
    grep -q "^RECV hello from akio-dtls" "oc-$name.log" || fail "$name: no echo"
    grep -q "peer=$(fp akio.pem)" "ps-$name.log" || fail "$name: pion saw another certificate"
    echo "ok   pion server <- akio-dtls client: $name ($(suite_of "oc-$name.log"))"
    # akio-dtls server, pion client.
    port=$((port + 1))
    "$RS" server "127.0.0.1:$port" --cert "$kind.pem" --key "$kind.key" --srtp "$profile" \
      --suite "$suite" --fingerprint "$(fp akio.pem)" >"os-$name.log" 2>&1 &
    PIDS="$PIDS $!"
    sleep 0.5
    "$GO" client "127.0.0.1:$port" akio.pem akio.key "$profile" >"pc-$name.log" 2>&1 ||
      fail "$name: pion client"
    sleep 0.3
    same_material "os-$name.log" "pc-$name.log" || fail "$name: keying material differs"
    grep -q "^RECV hello from pion" "pc-$name.log" || fail "$name: no echo at pion"
    grep -q "^RECV hello from pion" "os-$name.log" || fail "$name: no data at akio-dtls"
    echo "ok   pion client -> akio-dtls server: $name ($(suite_of "os-$name.log"))"
  done
done
# Connection IDs (RFC 9146) and PSK suites.
port=$((port + 1))
"$GO" cid-server "127.0.0.1:$port" 8 >ps-cid.log 2>&1 &
PIDS="$PIDS $!"
sleep 0.5
"$RS" client "127.0.0.1:$port" --cid 4 >oc-cid.log 2>&1 || fail "cid: akio-dtls client"
grep -q "local_cid=[0-9A-F]\{8\} peer_cid=[0-9A-F]\{16\}" oc-cid.log || fail "cid: not negotiated"
grep -q "^RECV hello from akio-dtls" oc-cid.log || fail "cid: no echo"
echo "ok   pion cid-server <- akio-dtls --cid 4: CIDs both ways"
port=$((port + 1))
"$RS" server "127.0.0.1:$port" --cid 6 --no-client-cert >os-cid.log 2>&1 &
PIDS="$PIDS $!"
sleep 0.5
"$GO" cid-client "127.0.0.1:$port" 0 >pc-cid.log 2>&1 || fail "cid: pion client"
sleep 0.3
grep -q "local_cid=[0-9A-F]\{12\} peer_cid=$" os-cid.log || fail "cid: pion did not send our CID"
grep -q "^RECV hello from pion" pc-cid.log || fail "cid: no echo at pion"
echo "ok   pion cid-client (send-only) -> akio-dtls --cid 6"
PSK=00112233445566778899aabbccddeeff
for suite in TLS_PSK_WITH_AES_128_GCM_SHA256 TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256; do
  port=$((port + 1))
  "$GO" psk-server "127.0.0.1:$port" akio-psk "$PSK" "$suite" >"ps-$suite.log" 2>&1 &
  PIDS="$PIDS $!"
  sleep 0.5
  "$RS" client "127.0.0.1:$port" --psk "akio-psk:$PSK" >"oc-$suite.log" 2>&1 || fail "$suite: client"
  [ "$(suite_of "oc-$suite.log")" = "$suite" ] || fail "$suite: got $(suite_of "oc-$suite.log")"
  grep -q "^RECV hello from akio-dtls" "oc-$suite.log" || fail "$suite: no echo"
  port=$((port + 1))
  "$RS" server "127.0.0.1:$port" --psk "akio-psk:$PSK" >"os-$suite.log" 2>&1 &
  PIDS="$PIDS $!"
  sleep 0.5
  "$GO" psk-client "127.0.0.1:$port" akio-psk "$PSK" "$suite" >"pc-$suite.log" 2>&1 || fail "$suite: pion client"
  sleep 0.3
  grep -q "psk=akio-psk" "os-$suite.log" || fail "$suite: no PSK at akio-dtls"
  echo "ok   pion <-> akio-dtls PSK both ways: $suite"
done

if [ "${SKIP_DTLS13:-0}" != 1 ]; then
  echo "== DTLS 1.3 / CID / PSK / resumption (OpenSSL 4.1, wolfSSL 5.8)"
  docker image inspect "$IMAGE" >/dev/null 2>&1 ||
    docker build -t "$IMAGE" "$ROOT/tools/interop/dtls"
  docker run --rm -v "$ROOT":/w -w /w -v flash-cargo-reg:/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR=/tmp/t "$IMAGE" bash -c \
    'cargo build -q --release -p akio-dtls --example dtls-interop &&
     tools/interop/dtls/dtls13.sh /tmp/t/release/examples/dtls-interop /tmp/dtls13'
fi
echo "dtls interop: all passed"
