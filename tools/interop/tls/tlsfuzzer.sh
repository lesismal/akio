#!/usr/bin/env bash
# tlsfuzzer (https://github.com/tlsfuzzer/tlsfuzzer) against only-tls's server: protocol
# conformance scripts for TLS 1.3 and 1.2, run in Docker (needs network for the clone and pip):
#
#   docker run --rm -v "$PWD":/w -w /w -v flash-cargo-reg:/usr/local/cargo/registry \
#     -e CARGO_TARGET_DIR=/tmp/t rust:1 tools/interop/tls/tlsfuzzer.sh [script.py ...]
#
# The server is `tls-interop server --http-server` (one small HTTP response per request head, as
# tlsfuzzer expects) with an RSA-2048 certificate and a stapled OCSP response; a second one on
# port 4434 asks for a client certificate (the client certificate compression script), a third
# on 4435 answers 240 bytes (the record_size_limit script checks how they are cut).
# TLS 1.2 scripts get `-d` ((EC)DHE instead of the RSA key exchange only-tls does not offer)
# and, where they take it, `-C` with an ECDHE + AES-GCM suite (their default is a CBC one).
set -u
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT=${OUT:-/tmp/tlsfuzzer-run}
mkdir -p "$OUT"
TARGET=${CARGO_TARGET_DIR:-$ROOT/target}
(cd "$ROOT" && cargo build -q --release -p only-tls --example tls-interop) || exit 1
BIN=$TARGET/release/examples/tls-interop
cd "$OUT" || exit 1
if [ ! -d tlsfuzzer ]; then
    git clone -q --depth 1 https://github.com/tlsfuzzer/tlsfuzzer || exit 1
fi
python3 -m venv venv >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq python3-venv >/dev/null && python3 -m venv venv; }
# tlsfuzzer master follows tlslite-ng master.
./venv/bin/pip install -q ecdsa "git+https://github.com/tlsfuzzer/tlslite-ng" >/dev/null 2>&1 || exit 1
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 30 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1
# An OCSP response for the (self-signed) certificate, signed by itself.
printf 'V\t491231235959Z\t\t%s\tunknown\t/CN=localhost\n' \
    "$(openssl x509 -in cert.pem -noout -serial | cut -d= -f2)" > index.txt
openssl ocsp -issuer cert.pem -cert cert.pem -reqout ocsp-req.der -no_nonce >/dev/null 2>&1
openssl ocsp -index index.txt -CA cert.pem -rsigner cert.pem -rkey key.pem -reqin ocsp-req.der \
    -respout ocsp.der -ndays 1 >/dev/null 2>&1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout client-key.pem \
    -out client.pem -days 30 -subj "/CN=client" -addext "basicConstraints=critical,CA:FALSE" \
    -addext "extendedKeyUsage=clientAuth" >/dev/null 2>&1

"$BIN" server 127.0.0.1:4433 --count 1000000 --http-server --cert cert.pem --key key.pem \
    --ocsp-file ocsp.der > server.log 2>&1 &
SP=$!
"$BIN" server 127.0.0.1:4434 --count 1000000 --http-server --cert cert.pem --key key.pem \
    --ca client.pem --tls13 > server-auth.log 2>&1 &
SP2=$!
"$BIN" server 127.0.0.1:4435 --count 1000000 --http-server --http-body 200 --cert cert.pem \
    --key key.pem > server-big.log 2>&1 &
SP3=$!
trap 'kill $SP $SP2 $SP3 2>/dev/null' EXIT
sleep 1

# script | extra arguments | probes known to fail (the run passes when exactly these fail)
#
# Left out, because they test what only-tls deliberately does not do: CBC suites (the default of
# most TLS 1.2 scripts that take no -C), RSA key exchange, FFDHE groups, x448, RSA-PSS keys,
# external PSKs, psk_ke, SSLv2 hellos, a server that requests certificates, non-TLS 1.3 servers.
SCRIPTS=(
    "test-tls13-conversation.py||0"
    "test-tls13-hrr.py||0"
    "test-tls13-keyupdate.py||0"
    # The client's Finished padded to 192 KiB: refused as an over-long handshake message
    # (decode_error) instead of being read to the end.
    "test-tls13-finished.py||1"
    "test-tls13-ccs.py||0"
    "test-tls13-multiple-ccs-messages.py||0"
    "test-tls13-record-padding.py||0"
    "test-tls13-zero-length-data.py||0"
    "test-tls13-empty-alert.py||0"
    "test-tls13-unencrypted-alert.py||0"
    "test-tls13-legacy-version.py||0"
    "test-tls13-shuffled-extentions.py||0"
    "test-tls13-large-number-of-extensions.py||0"
    "test-tls13-invalid-ciphers.py||0"
    "test-tls13-nociphers.py||0"
    "test-tls13-signature-algorithms.py||0"
    "test-tls13-rsa-signatures.py||0"
    "test-tls13-pkcs-signature.py||0"
    "test-tls13-count-tickets.py|-t 2|0"
    # Early data sent after a HelloRetryRequest (a client bug) is not skipped; the other probe
    # falls back to a CBC TLS 1.2 suite.
    "test-tls13-0rtt-garbage.py|-d|2"
    "test-conversation.py|-d -C TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|0"
    "test-renegotiation-disabled.py|-d -C TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|0"
    "test-truncating-of-client-hello.py|-d -C TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|0"
    "test-fuzzed-ciphertext.py|-d -C TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|0"
    "test-record-layer-fragmentation.py|-d -C TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|0"
    "test-zero-length-data.py|-d -C TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|0"
    "test-ccs.py|-d -C TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|0"
    "test-no-mlkem-in-old-tls.py|-d -C TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|0"
    "test-invalid-content-type.py|-d -C TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|0"
    "test-version-numbers.py|-d -C TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|0"
    "test-invalid-compression-methods.py|-d -C TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|0"
    "test-ecdhe-rsa-key-exchange-with-bad-messages.py|-C TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|0"
    # With -C the AES-256 probe sends an empty cipher list (decode_error, correctly).
    "test-aes-gcm-nonces.py|-d -C TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|2"
    # record_size_limit: the 21 probes of TLS 1.0, 1.1 and 1.2 use the RSA key exchange and CBC
    # suites (sanity twice, sizes sent / accepted, PRFs, too large record, renegotiation,
    # resumption); the TLS 1.3 probes and the TLS 1.2 extension-parsing ones run.
    "test-record-size-limit.py|-p 4435 --reply-AD-size 240 -M|21"
    # Certificate compression (zlib), server certificates and (second server) client ones. The
    # TLS 1.2 probe offers CBC suites only (its --tls1.2-cipher option is not registered).
    # Compressed client certificates are fuzzed up to 131,000 bytes: longer messages exceed the
    # handshake message limit and get decode_error instead of the bad_certificate expected.
    # test-ocsp-stapling.py offers CBC suites only: OCSP stapling is covered by run.sh against
    # OpenSSL, Go and GnuTLS.
    "test-tls13-certificate-compression.py|-d -M --algorithms zlib|1"
    "test-tls13-client-certificate-compression.py|-p 4434 -c ../client.pem -k ../client-key.pem --algorithms zlib --fuzz-package-limit 131000|0"
)
if [ "$#" -gt 0 ]; then
    # Only the named scripts, keeping their arguments from the list above.
    ALL=("${SCRIPTS[@]}")
    SCRIPTS=()
    for s in "$@"; do
        found="$s|"
        for e in "${ALL[@]}"; do [ "${e%%|*}" = "$s" ] && found=$e; done
        [ "$found" = "$s|" ] && found="$s||0"
        SCRIPTS+=("$found")
    done
fi
pass=0
fail=0
for entry in "${SCRIPTS[@]}"; do
    s=${entry%%|*}
    rest=${entry#*|}
    args=${rest%|*}
    known=${rest##*|}
    [ -f "tlsfuzzer/scripts/$s" ] || { echo "SKIP $s (not in this tlsfuzzer)"; continue; }
    # shellcheck disable=SC2086
    (cd tlsfuzzer && PYTHONPATH=. timeout 600 ../venv/bin/python "scripts/$s" -h 127.0.0.1 -p 4433 $args) \
        > "$OUT/$s.log" 2>&1
    r=$?
    sum=$(grep -E "^(PASS|FAIL|SKIP|TOTAL)" "$OUT/$s.log" | tr '\n' ' ')
    nfail=$(grep -E "^FAIL: " "$OUT/$s.log" | awk '{print $2}')
    if [ $r -eq 0 ] || { [ -n "$nfail" ] && [ "$nfail" -eq "$known" ] && [ "$known" -gt 0 ]; }; then
        pass=$((pass + 1))
        echo "PASS $s  $sum"
    else
        fail=$((fail + 1))
        echo "FAIL $s (exit $r)  $sum"
        grep -E "^[a-zA-Z0-9_ ()=,.-]+\.\.\.$|^Error|^AssertionError|failed" "$OUT/$s.log" | head -8 | sed 's/^/    /'
    fi
done
echo "== tlsfuzzer: $pass scripts passed, $fail failed (logs in $OUT)"
