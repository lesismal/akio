#!/usr/bin/env bash
# akio-tls <-> OpenSSL (s_server / s_client) and Go crypto/tls, both directions:
# TLS 1.3 and 1.2, every implemented cipher suite and group (X448 and Ed448 with OpenSSL only:
# Go has neither), RSA / RSA-PSS-key (rsa_pss_pss_*, OpenSSL only: Go cannot parse the keys) /
# ECDSA P-256 / P-384 / P-521 / Ed25519 / Ed448 certificates, client authentication (also with
# P-521 and RSA-PSS-key client certificates, and the client's OCSP response of ADR-049: akio
# both ways, and OpenSSL, which neither asks for nor sends one, around it), resumption (tickets and session IDs),
# HelloRetryRequest, ALPN, SNI, KeyUpdate, early data (0-RTT, OpenSSL only: Go has none),
# OCSP stapling (OpenSSL, Go, GnuTLS; akio's client validating it, and CRLs, against OpenSSL),
# certificate compression (RFC 8879 zlib, brotli and zstd: OpenSSL 3.2+ built with them, e.g.
# Debian's for zlib and zstd; skipped otherwise) and record_size_limit (RFC 8449: GnuTLS when
# gnutls-cli is installed; OpenSSL and Go have none, so their cases check it is not applied, and
# OpenSSL's max_fragment_length offer is ignored).
#
#   tools/interop/tls/run.sh              # needs openssl (3.x+) and go on PATH
#   OUT=/tmp/x tools/interop/tls/run.sh   # where PKI, logs and binaries go
#   AKIO_INTEROP_KTLS=require tools/interop/tls/run.sh   # akio's side on kernel TLS after the
#       handshake (Linux with the `tls` module, 6.14+; ktls feature, docs/BENCHMARKS.md)
#
# Linux Docker (Debian's OpenSSL 3 and the Go toolchain from the image are fetched on demand):
#   docker run --rm -v "$PWD":/w -w /w -v akio-cargo-reg:/usr/local/cargo/registry \
#     -e CARGO_TARGET_DIR=/tmp/t rust:1 bash -c 'apt-get update -qq && \
#     apt-get install -y -qq golang-go openssl gnutls-bin >/dev/null && tools/interop/tls/run.sh'
set -u
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT=${OUT:-$(mktemp -d)}
mkdir -p "$OUT/pki"
TARGET=${CARGO_TARGET_DIR:-$ROOT/target}
KTLS_FEATURE=()
[ -n "${AKIO_INTEROP_KTLS:-}" ] && KTLS_FEATURE=(--features ktls)
(cd "$ROOT" && cargo build -q --release -p akio-tls --example tls-interop ${KTLS_FEATURE[@]+"${KTLS_FEATURE[@]}"} &&
    cargo build -q --release -p akio-http --example http-bench) || exit 1
AKIO=$TARGET/release/examples/tls-interop
HTTP=$TARGET/release/examples/http-bench
(cd "$ROOT/tools/interop/tls/go" && go build -o "$OUT/tlsgo" .) || exit 1
GO=$OUT/tlsgo
P=$OUT/pki
PORT=${PORT:-19443}

# ---- PKI: a CA, server leaves of every key type, a client leaf ----
cd "$P" || exit 1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem \
    -days 30 -subj "/CN=akio interop CA" >/dev/null 2>&1
leaf() { # name keygen-args san
    local n=$1
    shift
    openssl genpkey "$@" -out "$n.key" >/dev/null 2>&1
    openssl req -new -key "$n.key" -out "$n.csr" -subj "/CN=$n" >/dev/null 2>&1
    printf 'subjectAltName=DNS:localhost,DNS:alt.test,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n' > "$n.ext"
    openssl x509 -req -in "$n.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 \
        -extfile "$n.ext" -out "$n.pem" >/dev/null 2>&1
}
leaf rsa -algorithm RSA -pkeyopt rsa_keygen_bits:2048
leaf p256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256
leaf p384 -algorithm EC -pkeyopt ec_paramgen_curve:P-384
leaf ed25519 -algorithm ED25519
leaf ed448 -algorithm ED448
leaf client -algorithm EC -pkeyopt ec_paramgen_curve:P-256
leaf p521 -algorithm EC -pkeyopt ec_paramgen_curve:P-521
leaf pss -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha256 \
    -pkeyopt rsa_pss_keygen_mgf1_md:sha256 -pkeyopt rsa_pss_keygen_saltlen:32
leaf client_p521 -algorithm EC -pkeyopt ec_paramgen_curve:P-521
leaf client_pss -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048
# An OCSP response for the P-256 leaf, signed by the CA (status good, valid for a day).
printf 'V\t491231235959Z\t\t%s\tunknown\t/CN=p256\n' \
    "$(openssl x509 -in p256.pem -noout -serial | cut -d= -f2)" > index.txt
openssl ocsp -issuer ca.pem -cert p256.pem -reqout ocsp-req.der -no_nonce >/dev/null 2>&1
openssl ocsp -index index.txt -CA ca.pem -rsigner ca.pem -rkey ca.key -reqin ocsp-req.der \
    -respout ocsp.der -ndays 1 >/dev/null 2>&1
# The same leaf revoked: an OCSP response and a CRL saying so, and a CRL listing nothing.
printf 'R\t491231235959Z\t%s,keyCompromise\t%s\tunknown\t/CN=p256\n' "$(date -u +%y%m%d%H%M%SZ)" \
    "$(openssl x509 -in p256.pem -noout -serial | cut -d= -f2)" > index-revoked.txt
openssl ocsp -index index-revoked.txt -CA ca.pem -rsigner ca.pem -rkey ca.key -reqin ocsp-req.der \
    -respout ocsp-revoked.der -ndays 1 >/dev/null 2>&1
: > index-empty.txt
for db in revoked empty; do
    printf '[ca]\ndefault_ca = c\n[c]\ndatabase = index-%s.txt\ncrlnumber = crlnumber\ndefault_md = sha256\ndefault_crl_days = 1\n' \
        "$db" > "crl-$db.cnf"
    echo 01 > crlnumber
    openssl ca -config "crl-$db.cnf" -gencrl -cert ca.pem -keyfile ca.key -out "crl-$db.pem" >/dev/null 2>&1
done
# OCSP responses for the P-256 client leaf (good, revoked), for its OCSP in client authentication.
printf 'V\t491231235959Z\t\t%s\tunknown\t/CN=client\n' \
    "$(openssl x509 -in client.pem -noout -serial | cut -d= -f2)" > index-client.txt
printf 'R\t491231235959Z\t%s,keyCompromise\t%s\tunknown\t/CN=client\n' "$(date -u +%y%m%d%H%M%SZ)" \
    "$(openssl x509 -in client.pem -noout -serial | cut -d= -f2)" > index-client-revoked.txt
openssl ocsp -issuer ca.pem -cert client.pem -reqout ocsp-client-req.der -no_nonce >/dev/null 2>&1
for st in "" -revoked; do
    openssl ocsp -index "index-client$st.txt" -CA ca.pem -rsigner ca.pem -rkey ca.key \
        -reqin ocsp-client-req.der -respout "ocsp-client$st.der" -ndays 1 >/dev/null 2>&1
done
cd "$OUT" || exit 1

pass=0
fail=0
failed=()
ok() {
    pass=$((pass + 1))
    echo "PASS $1"
}
ko() {
    fail=$((fail + 1))
    failed+=("$1")
    echo "FAIL $1"
    [ -n "${2:-}" ] && sed 's/^/    /' "$2" | tail -15
}
wait_port() {
    for _ in $(seq 1 50); do
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}
next_port() { PORT=$((PORT + 1)); }

# ---- akio client -> openssl s_server ----
s_server_case() { # name "s_server args" "akio client args" [expect-resume]
    local name=$1 sargs=$2 cargs=$3
    next_port
    # shellcheck disable=SC2086
    openssl s_server -accept "$PORT" -www -CAfile "$P/ca.pem" $sargs > "$OUT/srv.log" 2>&1 &
    local sp=$!
    wait_port "$PORT"
    # shellcheck disable=SC2086
    if "$AKIO" client "127.0.0.1:$PORT" localhost --ca "$P/ca.pem" --http $cargs > "$OUT/cli.log" 2>&1; then
        ok "akio client -> openssl: $name ($(grep -m1 'client\[0\]' "$OUT/cli.log" | cut -d' ' -f2-3))"
    else
        ko "akio client -> openssl: $name" "$OUT/cli.log"
    fi
    kill $sp 2>/dev/null
    wait $sp 2>/dev/null
}

# The akio client must fail, saying `pattern`.
s_server_fail_case() { # name "s_server args" "akio client args" pattern
    local name=$1 sargs=$2 cargs=$3 pat=$4
    next_port
    # shellcheck disable=SC2086
    openssl s_server -accept "$PORT" -www -CAfile "$P/ca.pem" $sargs > "$OUT/srv.log" 2>&1 &
    local sp=$!
    wait_port "$PORT"
    # shellcheck disable=SC2086
    if "$AKIO" client "127.0.0.1:$PORT" localhost --ca "$P/ca.pem" --http $cargs > "$OUT/cli.log" 2>&1; then
        ko "akio client -> openssl: $name (handshake succeeded)" "$OUT/cli.log"
    elif grep -q "$pat" "$OUT/cli.log"; then
        ok "akio client -> openssl: $name (refused: $pat)"
    else
        ko "akio client -> openssl: $name (no \"$pat\")" "$OUT/cli.log"
    fi
    kill $sp 2>/dev/null
    wait $sp 2>/dev/null
}

# ---- openssl s_client -> akio server ----
s_client_case() { # name "akio server args" "s_client args" grep-pattern [stdin]
    local name=$1 sargs=$2 cargs=$3 pat=$4 input=${5:-"hello akio"}
    next_port
    # shellcheck disable=SC2086
    "$AKIO" server "127.0.0.1:$PORT" --count 4 $sargs > "$OUT/srv.log" 2>&1 &
    local sp=$!
    wait_port "$PORT"
    # shellcheck disable=SC2086
    # One line at a time: s_client treats a whole read starting with K as the command.
    (printf '%b\n' "$input" | while IFS= read -r l; do
        printf '%s\n' "$l"
        sleep 0.3
    done; sleep 1) | timeout 10 openssl s_client -connect "127.0.0.1:$PORT" \
        -servername localhost -CAfile "$P/ca.pem" -verify_return_error $cargs > "$OUT/cli.log" 2>&1
    if grep -q "$pat" "$OUT/cli.log" && grep -q "Verify return code: 0" "$OUT/cli.log"; then
        ok "openssl -> akio server: $name ($(grep -m1 '^server:' "$OUT/srv.log" | cut -d' ' -f2-3))"
    else
        ko "openssl -> akio server: $name" "$OUT/cli.log"
    fi
    kill $sp 2>/dev/null
    wait $sp 2>/dev/null
}

# ---- Go both ways ----
go_server_case() { # name "go server args" "akio client args"
    local name=$1 sargs=$2 cargs=$3
    next_port
    # shellcheck disable=SC2086
    "$GO" server -addr "127.0.0.1:$PORT" -count 4 $sargs > "$OUT/srv.log" 2>&1 &
    local sp=$!
    wait_port "$PORT"
    # shellcheck disable=SC2086
    if "$AKIO" client "127.0.0.1:$PORT" localhost --ca "$P/ca.pem" $cargs > "$OUT/cli.log" 2>&1; then
        ok "akio client -> go: $name ($(grep -m1 'client\[0\]' "$OUT/cli.log" | cut -d' ' -f2-3))"
    else
        ko "akio client -> go: $name" "$OUT/cli.log"
        sed 's/^/    srv: /' "$OUT/srv.log" | tail -5
    fi
    kill $sp 2>/dev/null
    wait $sp 2>/dev/null
}
go_client_case() { # name "akio server args" "go client args"
    local name=$1 sargs=$2 cargs=$3
    next_port
    # shellcheck disable=SC2086
    "$AKIO" server "127.0.0.1:$PORT" --count 4 $sargs > "$OUT/srv.log" 2>&1 &
    local sp=$!
    wait_port "$PORT"
    # shellcheck disable=SC2086
    if "$GO" client -addr "127.0.0.1:$PORT" -name localhost -ca "$P/ca.pem" $cargs > "$OUT/cli.log" 2>&1; then
        ok "go -> akio server: $name ($(grep -m1 'client\[0\]' "$OUT/cli.log" | cut -d' ' -f2-3))"
    else
        ko "go -> akio server: $name" "$OUT/cli.log"
        sed 's/^/    srv: /' "$OUT/srv.log" | tail -5
    fi
    kill $sp 2>/dev/null
    wait $sp 2>/dev/null
}

S="--cert $P/p256.pem --key $P/p256.key"
echo "== OpenSSL $(openssl version | cut -d' ' -f2), $(go version | cut -d' ' -f3)"

# TLS 1.3 suites and groups.
for cs in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
    s_server_case "1.3 $cs" "-cert $P/p256.pem -key $P/p256.key -tls1_3 -ciphersuites $cs" ""
    s_client_case "1.3 $cs" "$S" "-tls1_3 -ciphersuites $cs" "hello akio"
done
for g in X25519 P-256 P-384 X448 P-521; do
    s_server_case "1.3 group $g" "-cert $P/p256.pem -key $P/p256.key -tls1_3 -groups $g" ""
    s_client_case "1.3 group $g" "$S" "-tls1_3 -groups $g" "hello akio"
done
# Certificate types, both versions.
for k in rsa p256 p384 p521 pss ed25519 ed448; do
    s_server_case "1.3 $k cert" "-cert $P/$k.pem -key $P/$k.key -tls1_3" ""
    s_client_case "1.3 $k cert" "--cert $P/$k.pem --key $P/$k.key" "-tls1_3" "hello akio"
done
# TLS 1.2 suites (ECDSA suites with P-256 / Ed25519, RSA suites with RSA).
for cs in ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305; do
    s_server_case "1.2 $cs" "-cert $P/p256.pem -key $P/p256.key -tls1_2 -cipher $cs" ""
    s_client_case "1.2 $cs" "$S" "-tls1_2 -cipher $cs" "hello akio"
done
for cs in ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-CHACHA20-POLY1305; do
    s_server_case "1.2 $cs" "-cert $P/rsa.pem -key $P/rsa.key -tls1_2 -cipher $cs" ""
    s_client_case "1.2 $cs" "--cert $P/rsa.pem --key $P/rsa.key" "-tls1_2 -cipher $cs" "hello akio"
done
s_server_case "1.2 ed25519 cert" "-cert $P/ed25519.pem -key $P/ed25519.key -tls1_2" ""
s_client_case "1.2 ed25519 cert" "--cert $P/ed25519.pem --key $P/ed25519.key" "-tls1_2" "hello akio"
s_server_case "1.2 ed448 cert" "-cert $P/ed448.pem -key $P/ed448.key -tls1_2" ""
s_client_case "1.2 ed448 cert" "--cert $P/ed448.pem --key $P/ed448.key" "-tls1_2" "hello akio"
s_server_case "1.2 p384 cert" "-cert $P/p384.pem -key $P/p384.key -tls1_2" ""
s_server_case "1.2 p521 cert" "-cert $P/p521.pem -key $P/p521.key -tls1_2" ""
s_client_case "1.2 p521 cert" "--cert $P/p521.pem --key $P/p521.key" "-tls1_2" "hello akio"
s_server_case "1.2 pss cert (rsa_pss_pss_sha256)" "-cert $P/pss.pem -key $P/pss.key -tls1_2" ""
s_client_case "1.2 pss cert (rsa_pss_pss_sha256)" "--cert $P/pss.pem --key $P/pss.key" "-tls1_2" \
    "hello akio"
for g in X25519 P-256 P-384 X448 P-521; do
    s_server_case "1.2 group $g" "-cert $P/p256.pem -key $P/p256.key -tls1_2 -groups $g" ""
done
# HelloRetryRequest: the server wants P-384, the client sends X25519 first.
s_server_case "1.3 HelloRetryRequest" "-cert $P/p256.pem -key $P/p256.key -tls1_3 -groups P-384" ""
s_client_case "1.3 HelloRetryRequest (forced)" "$S --hrr" "-tls1_3" "hello akio"
# Client authentication.
s_server_case "1.3 client auth" "-cert $P/p256.pem -key $P/p256.key -tls1_3 -Verify 1" \
    "--cert $P/client.pem --key $P/client.key"
s_server_case "1.2 client auth" "-cert $P/rsa.pem -key $P/rsa.key -tls1_2 -Verify 1" \
    "--cert $P/client.pem --key $P/client.key --tls12"
s_client_case "1.3 client auth" "$S --ca $P/ca.pem --require" \
    "-tls1_3 -cert $P/client.pem -key $P/client.key" "hello akio"
s_client_case "1.2 client auth" "$S --ca $P/ca.pem --require" \
    "-tls1_2 -cert $P/client.pem -key $P/client.key" "hello akio"
for k in client_p521 client_pss; do
    for v in 1.3 1.2; do
        sv="-tls${v/./_}"
        s_server_case "$v client auth ($k)" "-cert $P/p256.pem -key $P/p256.key $sv -Verify 1" \
            "--cert $P/$k.pem --key $P/$k.key"
        s_client_case "$v client auth ($k)" "$S --ca $P/ca.pem --require" \
            "$sv -cert $P/$k.pem -key $P/$k.key" "hello akio"
    done
done
# The client's OCSP response in client authentication (ADR-049). OpenSSL neither asks for one
# nor sends one: its client ignores the status_request of our CertificateRequest (soft fail
# passes, hard fail refuses it), and our client staples nothing when not asked.
s_client_case "1.3 client auth, client OCSP soft-fail (none sent)" \
    "$S --ca $P/ca.pem --require --client-ocsp-policy soft" \
    "-tls1_3 -cert $P/client.pem -key $P/client.key" "hello akio"
s_server_case "1.3 client auth, client OCSP not asked" \
    "-cert $P/p256.pem -key $P/p256.key -tls1_3 -Verify 1" \
    "--cert $P/client.pem --key $P/client.key --client-ocsp-file $P/ocsp-client.der"
next_port
"$AKIO" server "127.0.0.1:$PORT" --count 2 $S --ca "$P/ca.pem" --require --client-ocsp-policy hard \
    > "$OUT/srv.log" 2>&1 &
sp=$!
wait_port "$PORT"
(echo a; sleep 0.5) | timeout 10 openssl s_client -connect "127.0.0.1:$PORT" -servername localhost \
    -CAfile "$P/ca.pem" -tls1_3 -cert "$P/client.pem" -key "$P/client.key" > "$OUT/cli.log" 2>&1
sleep 0.3
if grep -q "no stapled OCSP response" "$OUT/srv.log"; then
    ok "openssl -> akio server: 1.3 client OCSP hard-fail refuses a client without one"
else
    ko "openssl -> akio server: 1.3 client OCSP hard-fail" "$OUT/srv.log"
fi
kill $sp 2>/dev/null
wait $sp 2>/dev/null
# akio both ways over TCP: good, revoked, missing (hard fail).
akio_client_ocsp_case() { # name server-policy "client args" expect(ok|pattern)
    local name=$1 pol=$2 cargs=$3 want=$4
    next_port
    # shellcheck disable=SC2086
    "$AKIO" server "127.0.0.1:$PORT" --count 2 $S --ca "$P/ca.pem" --require \
        --client-ocsp-policy "$pol" > "$OUT/srv.log" 2>&1 &
    local sp=$!
    wait_port "$PORT"
    # shellcheck disable=SC2086
    "$AKIO" client "127.0.0.1:$PORT" localhost --ca "$P/ca.pem" --cert "$P/client.pem" \
        --key "$P/client.key" $cargs > "$OUT/cli.log" 2>&1
    local rc=$?
    sleep 0.3
    if [ "$want" = ok ] && [ $rc = 0 ] && grep -q "^server: .*ocsp=[1-9]" "$OUT/srv.log"; then
        ok "akio client -> akio server: $name ($(grep -m1 -o 'ocsp=[0-9]*' "$OUT/srv.log"))"
    elif [ "$want" != ok ] && [ $rc != 0 ] && grep -q "$want" "$OUT/srv.log"; then
        ok "akio client -> akio server: $name (refused: $want)"
    else
        ko "akio client -> akio server: $name" "$OUT/srv.log"
    fi
    kill $sp 2>/dev/null
    wait $sp 2>/dev/null
}
akio_client_ocsp_case "1.3 client OCSP hard-fail, good" hard "--client-ocsp-file $P/ocsp-client.der" ok
akio_client_ocsp_case "1.3 client OCSP soft-fail, revoked" soft \
    "--client-ocsp-file $P/ocsp-client-revoked.der" "revoked"
akio_client_ocsp_case "1.3 client OCSP hard-fail, none" hard "" "no stapled OCSP response"
# Resumption: tickets in 1.3, tickets and session IDs in 1.2.
s_server_case "1.3 resumption" "-cert $P/p256.pem -key $P/p256.key -tls1_3" "--count 3 --expect-resume"
s_server_case "1.2 resumption (ticket)" "-cert $P/p256.pem -key $P/p256.key -tls1_2" \
    "--count 3 --expect-resume"
s_server_case "1.2 resumption (session id)" "-cert $P/p256.pem -key $P/p256.key -tls1_2 -no_ticket" \
    "--count 3 --expect-resume"
for v in tls1_3 tls1_2; do
    for t in "--tickets" ""; do
        next_port
        # shellcheck disable=SC2086
        "$AKIO" server "127.0.0.1:$PORT" --count 4 $S $t > "$OUT/srv.log" 2>&1 &
        sp=$!
        wait_port "$PORT"
        rm -f "$OUT/sess"
        (echo a; sleep 0.5) | timeout 10 openssl s_client -connect "127.0.0.1:$PORT" -servername localhost \
            -CAfile "$P/ca.pem" -"$v" -sess_out "$OUT/sess" > "$OUT/cli.log" 2>&1
        (echo b; sleep 0.5) | timeout 10 openssl s_client -connect "127.0.0.1:$PORT" -servername localhost \
            -CAfile "$P/ca.pem" -"$v" -sess_in "$OUT/sess" > "$OUT/cli2.log" 2>&1
        if grep -q "^Reused" "$OUT/cli2.log"; then
            ok "openssl -> akio server: $v resumption ${t:-(cache)}"
        else
            ko "openssl -> akio server: $v resumption ${t:-(cache)}" "$OUT/cli2.log"
        fi
        kill $sp 2>/dev/null
        wait $sp 2>/dev/null
    done
done
# Early data (0-RTT): akio's client sends its line before the handshake when it resumes.
# s_server runs without -www: OpenSSL 3.0 refuses -early_data with -www/-WWW/-HTTP/-rev
# (later releases allow it), so the client sends, closes and reads to s_server's close, and
# s_server's log shows what it did with the early data of the second and third connections.
s_server_early_case() { # name "s_server args" "akio client args" s_server-log-line
    local name=$1 sargs=$2 cargs=$3 want=$4
    next_port
    # s_server stops at EOF on stdin: keep it open for the length of the case.
    # shellcheck disable=SC2086
    sleep 15 | openssl s_server -accept "$PORT" -CAfile "$P/ca.pem" -tls1_3 -early_data $sargs \
        > "$OUT/srv.log" 2>&1 &
    local sp=$!
    wait_port "$PORT"
    # shellcheck disable=SC2086
    if "$AKIO" client "127.0.0.1:$PORT" localhost --ca "$P/ca.pem" --count 3 --early-data \
        --no-reply $cargs > "$OUT/cli.log" 2>&1 && [ "$(grep -c "^$want" "$OUT/srv.log")" = 2 ] &&
        grep -q "hello from akio-tls 1" "$OUT/srv.log" && grep -q "hello from akio-tls 2" "$OUT/srv.log"; then
        ok "akio client -> openssl: $name ($(grep -m1 'client\[1\]' "$OUT/cli.log" | cut -d' ' -f2-3))"
    else
        ko "akio client -> openssl: $name" "$OUT/cli.log"
        grep -v '^[A-Za-z0-9+/=]*$' "$OUT/srv.log" | sed 's/^/    srv: /' | tail -8
    fi
    kill $sp 2>/dev/null
    wait $sp 2>/dev/null
}
s_server_early_case "1.3 early data" "-cert $P/p256.pem -key $P/p256.key" \
    "--expect-resume --expect-early accepted" "Early data received"
# A HelloRetryRequest (the server wants P-384) rejects it: sent again after the handshake.
# (OpenSSL's anti-replay uses each ticket once, already for the first ClientHello, so the
# second one is a full handshake.)
s_server_early_case "1.3 early data rejected (HRR)" "-cert $P/p256.pem -key $P/p256.key -groups P-384" \
    "--expect-early rejected" "Early data was rejected"
for t in "" "--hrr"; do
    next_port
    # shellcheck disable=SC2086
    "$AKIO" server "127.0.0.1:$PORT" --count 4 $S --tickets --early-data $t > "$OUT/srv.log" 2>&1 &
    sp=$!
    wait_port "$PORT"
    rm -f "$OUT/sess"
    printf 'early hello\n' > "$OUT/early.txt"
    (echo a; sleep 0.5) | timeout 10 openssl s_client -connect "127.0.0.1:$PORT" -servername localhost \
        -CAfile "$P/ca.pem" -tls1_3 -sess_out "$OUT/sess" > "$OUT/cli.log" 2>&1
    sleep 0.5 | timeout 10 openssl s_client -connect "127.0.0.1:$PORT" -servername localhost \
        -CAfile "$P/ca.pem" -tls1_3 -sess_in "$OUT/sess" -early_data "$OUT/early.txt" > "$OUT/cli2.log" 2>&1
    if [ -z "$t" ] && grep -q "^Early data was accepted" "$OUT/cli2.log" &&
        grep -q "^early hello" "$OUT/cli2.log" && grep -q "early=Accepted/12" "$OUT/srv.log"; then
        ok "openssl -> akio server: 1.3 early data accepted"
    elif [ -n "$t" ] && grep -q "^Early data was rejected" "$OUT/cli2.log" &&
        grep -q "early=Rejected/0" "$OUT/srv.log"; then
        ok "openssl -> akio server: 1.3 early data rejected (HRR)"
    else
        ko "openssl -> akio server: 1.3 early data ${t:-accepted}" "$OUT/cli2.log"
        sed 's/^/    srv: /' "$OUT/srv.log" | tail -5
    fi
    kill $sp 2>/dev/null
    wait $sp 2>/dev/null
done
# ALPN and SNI.
s_server_case "1.3 ALPN" "-cert $P/p256.pem -key $P/p256.key -alpn h2,http/1.1" "--alpn http/1.1,h2"
s_client_case "1.3 ALPN" "$S --alpn h2,http/1.1" "-alpn http/1.1" "ALPN protocol: http/1.1"
s_client_case "1.2 ALPN" "$S --alpn h2,http/1.1" "-tls1_2 -alpn h2" "ALPN protocol: h2"
# KeyUpdate: openssl asks for one back ("K"); our client updates its keys before every record.
s_client_case "1.3 KeyUpdate requested by openssl" "$S" "-tls1_3" "after update" "K\nafter update"
s_server_case "1.3 KeyUpdate sent by akio" "-cert $P/p256.pem -key $P/p256.key -tls1_3" "--key-update"
# Bulk.
s_server_case "1.3 64 KiB request" "-cert $P/p256.pem -key $P/p256.key -tls1_3" "--bytes 65536"

# OCSP stapling: s_client checks the response (-ocsp_check_leaf verifies it where OpenSSL has it;
# OpenSSL fails that check in TLS 1.2 against its own s_server too), akio's client checks it is
# the configured one.
OCSP_CHECK=""
openssl s_client -help 2>&1 | grep -q -- -ocsp_check_leaf && OCSP_CHECK="-ocsp_check_leaf"
s_server_case "1.3 OCSP stapling" "-cert $P/p256.pem -key $P/p256.key -tls1_3 -status_file $P/ocsp.der" \
    "--expect-ocsp $P/ocsp.der"
s_server_case "1.2 OCSP stapling" "-cert $P/p256.pem -key $P/p256.key -tls1_2 -status_file $P/ocsp.der" \
    "--expect-ocsp $P/ocsp.der"
# Revocation checks of akio's client: stapled OCSP under each policy, CRLs.
for v in 1.3 1.2; do
    sv="-tls${v/./_}"
    s_server_case "$v OCSP hard-fail, good response" \
        "-cert $P/p256.pem -key $P/p256.key $sv -status_file $P/ocsp.der" "--ocsp-policy hard"
    s_server_fail_case "$v OCSP soft-fail, revoked response" \
        "-cert $P/p256.pem -key $P/p256.key $sv -status_file $P/ocsp-revoked.der" \
        "--ocsp-policy soft" "revoked"
    s_server_fail_case "$v OCSP hard-fail, no response" "-cert $P/p256.pem -key $P/p256.key $sv" \
        "--ocsp-policy hard" "no stapled OCSP response"
    s_server_case "$v OCSP soft-fail, no response" "-cert $P/p256.pem -key $P/p256.key $sv" \
        "--ocsp-policy soft"
    s_server_fail_case "$v CRL, revoked" "-cert $P/p256.pem -key $P/p256.key $sv" \
        "--crl $P/crl-revoked.pem" "revoked"
    s_server_case "$v CRL hard-fail, not revoked" "-cert $P/p256.pem -key $P/p256.key $sv" \
        "--crl $P/crl-empty.pem --crl-policy hard"
done
s_client_case "1.3 OCSP stapling" "$S --ocsp-file $P/ocsp.der" "-tls1_3 -status $OCSP_CHECK" \
    "Cert Status: good"
s_client_case "1.2 OCSP stapling" "$S --ocsp-file $P/ocsp.der" "-tls1_2 -status" "Cert Status: good"
# Certificate compression, both ways, server and client certificates, one algorithm at a time
# (akio's side takes only that one): zlib, brotli and zstd where OpenSSL (3.2+) was built with
# them (Debian's has zlib and zstd; brotli needs `enable-brotli`, e.g. the image of
# tools/interop/tls/certcomp.Dockerfile). Then OpenSSL's client offering all it has, akio's
# server picking the smallest.
for alg in zlib brotli zstd; do
    flag=$(printf '%s' "$alg" | tr '[:lower:]' '[:upper:]')
    if ! openssl version -a | grep -q -- "-D$flag"; then
        echo "SKIP $alg certificate compression with OpenSSL (built without $alg)"
        continue
    fi
    s_client_case "1.3 compressed certificate ($alg)" "$S --cert-comp $alg" "-tls1_3 -trace" \
        "Compression type=$alg"
    s_client_case "1.3 compressed client certificate ($alg)" \
        "$S --ca $P/ca.pem --require --cert-comp $alg" \
        "-tls1_3 -cert $P/client.pem -key $P/client.key" "hello akio"
    if grep -q "cert_comp_alg=$alg" "$OUT/srv.log"; then :; else
        ko "openssl -> akio server: client certificate was not compressed with $alg" "$OUT/srv.log"
    fi
    s_server_case "1.3 compressed certificate ($alg)" \
        "-cert $P/p256.pem -key $P/p256.key -tls1_3 -cert_comp -Verify 1" \
        "--cert $P/client.pem --key $P/client.key --cert-comp $alg"
    if grep -q "cert_comp_alg=$alg" "$OUT/cli.log"; then :; else
        ko "akio client -> openssl: certificate was not compressed with $alg" "$OUT/cli.log"
    fi
done
if openssl version -a | grep -q -- '-DZLIB'; then
    s_client_case "1.3 compressed certificate (smallest offered)" "$S" "-tls1_3 -trace" \
        "CompressedCertificate"
fi
# record_size_limit: OpenSSL has none, so nothing is applied (our 512 is not enforced on its
# 16 KiB records); its max_fragment_length offer (RFC 6066, not implemented) is ignored, and
# records it caps itself with -max_send_frag are read as any others.
s_server_case "1.3 record_size_limit not negotiated" "-cert $P/p256.pem -key $P/p256.key -tls1_3" \
    "--record-limit 512 --expect-record-limit 0 --bytes 65536"
s_server_case "1.2 small records (-max_send_frag 512)" \
    "-cert $P/p256.pem -key $P/p256.key -tls1_2 -max_send_frag 512" "--record-limit 512 --bytes 65536"
s_client_case "1.3 max_fragment_length offered (ignored)" "$S --record-limit 512" \
    "-tls1_3 -maxfraglen 512" "hello akio"
s_client_case "1.2 max_fragment_length offered (ignored)" "$S" "-tls1_2 -maxfraglen 1024" "hello akio"

# GnuTLS: record_size_limit both ways (it counts the TLS 1.3 content type: --recordsize=512 is
# 513 on the wire), OCSP stapling both ways. akio's client sends 5000 bytes, cut to GnuTLS's
# limit; gnutls-cli sends one record per line read and drops the rest of a longer line (it does
# not retry a partial gnutls_record_send), so it sends lines of 500 bytes.
if command -v gnutls-cli >/dev/null; then
    for v in 1.3 1.2; do
        want=512
        [ "$v" = 1.3 ] && want=513
        prio="NORMAL:-VERS-ALL:+VERS-TLS$v"
        next_port
        # --count 2: wait_port's probe is the first connection.
        "$AKIO" server "127.0.0.1:$PORT" --count 2 $S --record-limit 1000 --ocsp-file "$P/ocsp.der" \
            > "$OUT/srv.log" 2>&1 &
        sp=$!
        wait_port "$PORT"
        rm -f "$OUT/got-ocsp.der"
        (for i in 1 2 3 4 5; do printf 'hello gnutls %d %0484d\n' "$i" 0; sleep 0.2; done; sleep 0.5) |
            timeout 10 gnutls-cli --x509cafile "$P/ca.pem" -p "$PORT" localhost --recordsize=512 \
                --priority "$prio" --save-ocsp="$OUT/got-ocsp.der" > "$OUT/cli.log" 2>&1
        if grep -q "rsl=1000/$want" "$OUT/srv.log" &&
            [ "$(grep -c -E '^hello gnutls [1-5] 0{484}$' "$OUT/cli.log")" = 5 ] &&
            cmp -s "$OUT/got-ocsp.der" "$P/ocsp.der"; then
            ok "gnutls -> akio server: $v record_size_limit + OCSP ($(grep -o 'rsl=[0-9/]*' "$OUT/srv.log"))"
        else
            ko "gnutls -> akio server: $v record_size_limit + OCSP" "$OUT/cli.log"
            sed 's/^/    srv: /' "$OUT/srv.log" | tail -3
        fi
        kill $sp 2>/dev/null
        wait $sp 2>/dev/null
        next_port
        timeout 15 gnutls-serv --echo -p "$PORT" --x509certfile "$P/p256.pem" --x509keyfile "$P/p256.key" \
            --recordsize=512 --ocsp-response="$P/ocsp.der" --priority "$prio" > "$OUT/srv.log" 2>&1 &
        sp=$!
        wait_port "$PORT"
        if "$AKIO" client "127.0.0.1:$PORT" localhost --ca "$P/ca.pem" --record-limit 1000 \
            --expect-record-limit "$want" --expect-ocsp "$P/ocsp.der" --bytes 5000 > "$OUT/cli.log" 2>&1; then
            ok "akio client -> gnutls: $v record_size_limit + OCSP ($(grep -m1 -o 'rsl=[0-9/]*' "$OUT/cli.log"))"
        else
            ko "akio client -> gnutls: $v record_size_limit + OCSP" "$OUT/cli.log"
        fi
        kill $sp 2>/dev/null
        wait $sp 2>/dev/null
    done
else
    echo "SKIP GnuTLS cases (no gnutls-cli)"
fi

# Go crypto/tls.
for k in rsa p256 p384 p521 ed25519; do
    go_server_case "1.3 $k cert" "-cert $P/$k.pem -key $P/$k.key" ""
    go_server_case "1.2 $k cert" "-cert $P/$k.pem -key $P/$k.key -tls12" "--tls12"
    go_client_case "1.3 $k cert" "--cert $P/$k.pem --key $P/$k.key" ""
    go_client_case "1.2 $k cert" "--cert $P/$k.pem --key $P/$k.key" "-tls12"
done
for s in 0x1301 0x1302 0x1303; do
    go_client_case "1.3 suite $s" "$S --suites $s" ""
done
for s in 0xc02b 0xc02c 0xcca9; do
    go_server_case "1.2 suite $s" "-cert $P/p256.pem -key $P/p256.key -suite $s" "--tls12"
    go_client_case "1.2 suite $s" "$S" "-tls12 -suite $s"
done
for c in 29 23 24 25; do
    go_client_case "1.3 curve $c" "$S" "-curve $c"
    go_server_case "1.3 curve $c" "-cert $P/p256.pem -key $P/p256.key -curve $c" ""
done
go_server_case "1.3 resumption" "-cert $P/p256.pem -key $P/p256.key" "--count 3 --expect-resume"
go_server_case "1.2 resumption" "-cert $P/p256.pem -key $P/p256.key -tls12" "--count 3 --expect-resume --tls12"
go_client_case "1.3 resumption (tickets)" "$S --tickets" "-count 3 -expect-resume"
go_client_case "1.3 resumption (cache)" "$S" "-count 3 -expect-resume"
go_client_case "1.2 resumption (tickets)" "$S --tickets" "-count 3 -expect-resume -tls12"
go_server_case "1.3 client auth" "-cert $P/p256.pem -key $P/p256.key -ca $P/ca.pem -require" \
    "--cert $P/client.pem --key $P/client.key"
go_server_case "1.2 client auth" "-cert $P/p256.pem -key $P/p256.key -ca $P/ca.pem -require -tls12" \
    "--cert $P/client.pem --key $P/client.key --tls12"
go_client_case "1.3 client auth" "$S --ca $P/ca.pem --require" "-cert $P/client.pem -key $P/client.key"
go_client_case "1.2 client auth" "$S --ca $P/ca.pem --require" "-cert $P/client.pem -key $P/client.key -tls12"
go_server_case "1.3 ALPN" "-cert $P/p256.pem -key $P/p256.key -alpn h2" "--alpn h2"
go_client_case "1.3 ALPN" "$S --alpn h2" "-alpn h2"
go_server_case "1.3 HelloRetryRequest" "-cert $P/p256.pem -key $P/p256.key -curve 24" ""
go_client_case "1.3 HelloRetryRequest (forced)" "$S --hrr" ""
go_server_case "1.3 KeyUpdate sent by akio" "-cert $P/p256.pem -key $P/p256.key" "--key-update --bytes 300000"
go_client_case "1.3 many records" "$S" "-key-update"
# OCSP stapling both ways (Go's client always asks); Go has no record_size_limit, so ours is not
# applied, and no certificate compression.
go_server_case "1.3 OCSP stapling" "-cert $P/p256.pem -key $P/p256.key -ocsp $P/ocsp.der" \
    "--expect-ocsp $P/ocsp.der"
go_server_case "1.2 OCSP stapling" "-cert $P/p256.pem -key $P/p256.key -ocsp $P/ocsp.der -tls12" \
    "--tls12 --expect-ocsp $P/ocsp.der"
go_client_case "1.3 OCSP stapling" "$S --ocsp-file $P/ocsp.der" "-expect-ocsp $P/ocsp.der"
go_client_case "1.2 OCSP stapling" "$S --ocsp-file $P/ocsp.der" "-expect-ocsp $P/ocsp.der -tls12"
go_server_case "1.3 record_size_limit not negotiated" "-cert $P/p256.pem -key $P/p256.key" \
    "--record-limit 512 --expect-record-limit 0 --bytes 40000"
go_client_case "1.2 record_size_limit not negotiated" "$S --record-limit 512" "-tls12 -key-update"

# curl against akio-http over TLS (HTTP/1.1 and HTTP/2 by ALPN).
if command -v curl >/dev/null; then
    next_port
    "$HTTP" "127.0.0.1:$PORT" 2 epoll tls > "$OUT/http.log" 2>&1 &
    hp=$!
    wait_port "$PORT"
    for v in --http1.1 --http2; do
        for t in 1.2 1.3; do
            r=$(curl -sSk "$v" "--tlsv$t" --tls-max "$t" -w ' %{http_version} %{http_code}' \
                "https://127.0.0.1:$PORT/plaintext" 2>&1)
            case "$r" in
            "Hello, World! "*" 200") ok "curl $v TLS $t -> akio-http ($r)" ;;
            *"not found built-in"* | *"option"*) echo "SKIP curl $v TLS $t (not in this curl build)" ;;
            *) ko "curl $v TLS $t -> akio-http" && echo "    $r" ;;
            esac
        done
    done
    kill $hp 2>/dev/null
    wait $hp 2>/dev/null
fi

echo
echo "== $pass passed, $fail failed (logs and PKI in $OUT)"
for f in "${failed[@]+"${failed[@]}"}"; do
    echo "   failed: $f"
done
[ "$fail" -eq 0 ]
