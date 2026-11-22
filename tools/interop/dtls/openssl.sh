#!/usr/bin/env bash
# akio-dtls <-> OpenSSL `s_client -dtls1_2` / `s_server -dtls1_2`, both directions, with
# `-use_srtp` and `-keymatexport` (the EXTRACTOR-dtls_srtp keys must match byte for byte) and
# mutual authentication pinned by fingerprint.
#   openssl.sh <dtls-interop binary> <work dir>
# run.sh calls it inside the rust:1 Docker image (OpenSSL 3.x); it also runs on a host with
# OpenSSL >= 3.
set -eu
BIN=$1
W=$2
mkdir -p "$W"
cd "$W"
PIDS=""
trap 'kill $PIDS 2>/dev/null || true' EXIT
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; cat "$f"; done; exit 1; }

openssl version
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ec.key \
  -out ec.pem -days 30 -subj /CN=openssl-ec 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa.key -out rsa.pem -days 30 \
  -subj /CN=openssl-rsa 2>/dev/null
# Our own identity as PEM, so both sides can pin each other's fingerprint.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout akio.key \
  -out akio.pem -days 30 -subj /CN=akio 2>/dev/null
fp() { echo "sha-256 $(openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2)"; }
openssl_material() { grep -A3 'Keying material exporter' "$1" | sed -n 's/.*Keying material: *//p' | head -1; }

port=24430
# OpenSSL server, akio-dtls client.
server_case() { # name, cert, key, srtp profile(openssl), material length, extra client args...
  local name=$1 cert=$2 key=$3 srtp=$4 len=$5
  shift 5
  port=$((port + 1))
  openssl s_server -dtls1_2 -accept "127.0.0.1:$port" -cert "$cert" -key "$key" \
    -use_srtp "$srtp" -keymatexport EXTRACTOR-dtls_srtp -keymatexportlen "$len" \
    -Verify 1 -CAfile akio.pem -verify_return_error -naccept 1 >"s-$name.log" 2>&1 < <(sleep 8) &
  PIDS="$PIDS $!"
  sleep 0.5
  "$BIN" client "127.0.0.1:$port" --cert akio.pem --key akio.key --srtp "$srtp" \
    --fingerprint "$(fp "$cert")" --oneway "$@" >"c-$name.log" 2>&1 || fail "$name: client"
  sleep 0.3
  local ours theirs
  ours=$(sed -n 's/^SRTP_MATERIAL //p' "c-$name.log")
  theirs=$(openssl_material "s-$name.log")
  [ -n "$ours" ] && [ "$ours" = "$theirs" ] || fail "$name: keying material '$ours' vs '$theirs'"
  grep -q "^hello from akio-dtls" "s-$name.log" || fail "$name: s_server did not receive the data"
  echo "ok   openssl s_server <- akio-dtls client: $name ($(sed -n 's/^CONNECTED suite=\([^ ]*\).*/\1/p' "c-$name.log"))"
}

# akio-dtls server, OpenSSL client.
client_case() { # name, srtp profile, material length, extra s_client args...
  local name=$1 srtp=$2 len=$3
  shift 3
  port=$((port + 1))
  "$BIN" server "127.0.0.1:$port" --cert akio.pem --key akio.key --srtp "$srtp" \
    --fingerprint "$(fp ec.pem)" >"S-$name.log" 2>&1 &
  local spid=$!
  PIDS="$PIDS $spid"
  sleep 0.5
  (echo "hello from openssl"; sleep 2) | openssl s_client -dtls1_2 -connect "127.0.0.1:$port" \
    -cert ec.pem -key ec.key -use_srtp "$srtp" -keymatexport EXTRACTOR-dtls_srtp \
    -keymatexportlen "$len" -CAfile akio.pem -verify_return_error "$@" >"C-$name.log" 2>&1 || true
  kill "$spid" 2>/dev/null || true
  local ours theirs
  ours=$(sed -n 's/^SRTP_MATERIAL //p' "S-$name.log")
  theirs=$(openssl_material "C-$name.log")
  [ -n "$ours" ] && [ "$ours" = "$theirs" ] || fail "$name: keying material '$ours' vs '$theirs'"
  grep -q "^RECV hello from openssl" "S-$name.log" || fail "$name: no data from s_client"
  grep -q "^hello from openssl" "C-$name.log" || fail "$name: no echo at s_client"
  echo "ok   openssl s_client -> akio-dtls server: $name ($(sed -n 's/^CONNECTED suite=\([^ ]*\).*/\1/p' "S-$name.log"))"
}

server_case ecdsa-aes128gcm ec.pem ec.key SRTP_AES128_CM_SHA1_80 60
server_case ecdsa-aead-gcm ec.pem ec.key SRTP_AEAD_AES_128_GCM 56
server_case ecdsa-aes256gcm ec.pem ec.key SRTP_AEAD_AES_256_GCM 88 \
  --suite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
server_case ecdsa-chacha ec.pem ec.key SRTP_AES128_CM_SHA1_32 60 \
  --suite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
server_case rsa-aes128gcm rsa.pem rsa.key SRTP_AES128_CM_SHA1_80 60
server_case rsa-chacha-mtu300 rsa.pem rsa.key SRTP_AEAD_AES_128_GCM 56 \
  --suite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 --mtu 300

client_case default SRTP_AES128_CM_SHA1_80 60
client_case aead-gcm SRTP_AEAD_AES_128_GCM 56
client_case aes256-sha384 SRTP_AEAD_AES_256_GCM 88 -cipher ECDHE-ECDSA-AES256-GCM-SHA384
client_case chacha SRTP_AES128_CM_SHA1_80 60 -cipher ECDHE-ECDSA-CHACHA20-POLY1305
client_case mtu300 SRTP_AES128_CM_SHA1_80 60 -mtu 300

# Negative: a pinned fingerprint that does not match makes our client fail.
port=$((port + 1))
openssl s_server -dtls1_2 -accept "127.0.0.1:$port" -cert ec.pem -key ec.key -naccept 1 \
  >s-badfp.log 2>&1 < <(sleep 8) &
PIDS="$PIDS $!"
sleep 0.5
if "$BIN" client "127.0.0.1:$port" --fingerprint "$(fp rsa.pem)" >c-badfp.log 2>&1; then
  fail "wrong fingerprint accepted"
fi
grep -q "fingerprint mismatch" c-badfp.log || fail "wrong fingerprint: unexpected error"
echo "ok   wrong fingerprint rejected (openssl server)"
echo "openssl interop: all passed"
