#!/usr/bin/env bash
# only-tls <-> OpenSSL (s_server / s_client) and Go crypto/tls, both directions:
# TLS 1.3 and 1.2, every implemented cipher suite and group, RSA / ECDSA P-256 / P-384 /
# Ed25519 certificates, client authentication, resumption (tickets and session IDs),
# HelloRetryRequest, ALPN, SNI, KeyUpdate.
#
#   tools/interop/tls/run.sh              # needs openssl (3.x+) and go on PATH
#   OUT=/tmp/x tools/interop/tls/run.sh   # where PKI, logs and binaries go
#   ONLY_INTEROP_KTLS=require tools/interop/tls/run.sh   # only's side on kernel TLS after the
#       handshake (Linux with the `tls` module, 6.14+; experimental-ktls feature, docs/BENCHMARKS.md)
#
# Linux Docker (Debian's OpenSSL 3 and the Go toolchain from the image are fetched on demand):
#   docker run --rm -v "$PWD":/w -w /w -v flash-cargo-reg:/usr/local/cargo/registry \
#     -e CARGO_TARGET_DIR=/tmp/t rust:1 bash -c 'apt-get update -qq && \
#     apt-get install -y -qq golang-go openssl >/dev/null && tools/interop/tls/run.sh'
set -u
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT=${OUT:-$(mktemp -d)}
mkdir -p "$OUT/pki"
TARGET=${CARGO_TARGET_DIR:-$ROOT/target}
KTLS_FEATURE=()
[ -n "${ONLY_INTEROP_KTLS:-}" ] && KTLS_FEATURE=(--features experimental-ktls)
(cd "$ROOT" && cargo build -q --release -p only-tls --example tls-interop ${KTLS_FEATURE[@]+"${KTLS_FEATURE[@]}"} &&
    cargo build -q --release -p only-http --example http-bench) || exit 1
ONLY=$TARGET/release/examples/tls-interop
HTTP=$TARGET/release/examples/http-bench
(cd "$ROOT/tools/interop/tls/go" && go build -o "$OUT/tlsgo" .) || exit 1
GO=$OUT/tlsgo
P=$OUT/pki
PORT=${PORT:-19443}

# ---- PKI: a CA, server leaves of every key type, a client leaf ----
cd "$P" || exit 1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem \
    -days 30 -subj "/CN=only interop CA" >/dev/null 2>&1
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
leaf client -algorithm EC -pkeyopt ec_paramgen_curve:P-256
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

# ---- only client -> openssl s_server ----
s_server_case() { # name "s_server args" "only client args" [expect-resume]
    local name=$1 sargs=$2 cargs=$3
    next_port
    # shellcheck disable=SC2086
    openssl s_server -accept "$PORT" -www -CAfile "$P/ca.pem" $sargs > "$OUT/srv.log" 2>&1 &
    local sp=$!
    wait_port "$PORT"
    # shellcheck disable=SC2086
    if "$ONLY" client "127.0.0.1:$PORT" localhost --ca "$P/ca.pem" --http $cargs > "$OUT/cli.log" 2>&1; then
        ok "only client -> openssl: $name ($(grep -m1 'client\[0\]' "$OUT/cli.log" | cut -d' ' -f2-3))"
    else
        ko "only client -> openssl: $name" "$OUT/cli.log"
    fi
    kill $sp 2>/dev/null
    wait $sp 2>/dev/null
}

# ---- openssl s_client -> only server ----
s_client_case() { # name "only server args" "s_client args" grep-pattern [stdin]
    local name=$1 sargs=$2 cargs=$3 pat=$4 input=${5:-"hello only"}
    next_port
    # shellcheck disable=SC2086
    "$ONLY" server "127.0.0.1:$PORT" --count 4 $sargs > "$OUT/srv.log" 2>&1 &
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
        ok "openssl -> only server: $name ($(grep -m1 '^server:' "$OUT/srv.log" | cut -d' ' -f2-3))"
    else
        ko "openssl -> only server: $name" "$OUT/cli.log"
    fi
    kill $sp 2>/dev/null
    wait $sp 2>/dev/null
}

# ---- Go both ways ----
go_server_case() { # name "go server args" "only client args"
    local name=$1 sargs=$2 cargs=$3
    next_port
    # shellcheck disable=SC2086
    "$GO" server -addr "127.0.0.1:$PORT" -count 4 $sargs > "$OUT/srv.log" 2>&1 &
    local sp=$!
    wait_port "$PORT"
    # shellcheck disable=SC2086
    if "$ONLY" client "127.0.0.1:$PORT" localhost --ca "$P/ca.pem" $cargs > "$OUT/cli.log" 2>&1; then
        ok "only client -> go: $name ($(grep -m1 'client\[0\]' "$OUT/cli.log" | cut -d' ' -f2-3))"
    else
        ko "only client -> go: $name" "$OUT/cli.log"
        sed 's/^/    srv: /' "$OUT/srv.log" | tail -5
    fi
    kill $sp 2>/dev/null
    wait $sp 2>/dev/null
}
go_client_case() { # name "only server args" "go client args"
    local name=$1 sargs=$2 cargs=$3
    next_port
    # shellcheck disable=SC2086
    "$ONLY" server "127.0.0.1:$PORT" --count 4 $sargs > "$OUT/srv.log" 2>&1 &
    local sp=$!
    wait_port "$PORT"
    # shellcheck disable=SC2086
    if "$GO" client -addr "127.0.0.1:$PORT" -name localhost -ca "$P/ca.pem" $cargs > "$OUT/cli.log" 2>&1; then
        ok "go -> only server: $name ($(grep -m1 'client\[0\]' "$OUT/cli.log" | cut -d' ' -f2-3))"
    else
        ko "go -> only server: $name" "$OUT/cli.log"
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
    s_client_case "1.3 $cs" "$S" "-tls1_3 -ciphersuites $cs" "hello only"
done
for g in X25519 P-256 P-384; do
    s_server_case "1.3 group $g" "-cert $P/p256.pem -key $P/p256.key -tls1_3 -groups $g" ""
    s_client_case "1.3 group $g" "$S" "-tls1_3 -groups $g" "hello only"
done
# Certificate types, both versions.
for k in rsa p256 p384 ed25519; do
    s_server_case "1.3 $k cert" "-cert $P/$k.pem -key $P/$k.key -tls1_3" ""
    s_client_case "1.3 $k cert" "--cert $P/$k.pem --key $P/$k.key" "-tls1_3" "hello only"
done
# TLS 1.2 suites (ECDSA suites with P-256 / Ed25519, RSA suites with RSA).
for cs in ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305; do
    s_server_case "1.2 $cs" "-cert $P/p256.pem -key $P/p256.key -tls1_2 -cipher $cs" ""
    s_client_case "1.2 $cs" "$S" "-tls1_2 -cipher $cs" "hello only"
done
for cs in ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-CHACHA20-POLY1305; do
    s_server_case "1.2 $cs" "-cert $P/rsa.pem -key $P/rsa.key -tls1_2 -cipher $cs" ""
    s_client_case "1.2 $cs" "--cert $P/rsa.pem --key $P/rsa.key" "-tls1_2 -cipher $cs" "hello only"
done
s_server_case "1.2 ed25519 cert" "-cert $P/ed25519.pem -key $P/ed25519.key -tls1_2" ""
s_client_case "1.2 ed25519 cert" "--cert $P/ed25519.pem --key $P/ed25519.key" "-tls1_2" "hello only"
s_server_case "1.2 p384 cert" "-cert $P/p384.pem -key $P/p384.key -tls1_2" ""
for g in X25519 P-256 P-384; do
    s_server_case "1.2 group $g" "-cert $P/p256.pem -key $P/p256.key -tls1_2 -groups $g" ""
done
# HelloRetryRequest: the server wants P-384, the client sends X25519 first.
s_server_case "1.3 HelloRetryRequest" "-cert $P/p256.pem -key $P/p256.key -tls1_3 -groups P-384" ""
s_client_case "1.3 HelloRetryRequest (forced)" "$S --hrr" "-tls1_3" "hello only"
# Client authentication.
s_server_case "1.3 client auth" "-cert $P/p256.pem -key $P/p256.key -tls1_3 -Verify 1" \
    "--cert $P/client.pem --key $P/client.key"
s_server_case "1.2 client auth" "-cert $P/rsa.pem -key $P/rsa.key -tls1_2 -Verify 1" \
    "--cert $P/client.pem --key $P/client.key --tls12"
s_client_case "1.3 client auth" "$S --ca $P/ca.pem --require" \
    "-tls1_3 -cert $P/client.pem -key $P/client.key" "hello only"
s_client_case "1.2 client auth" "$S --ca $P/ca.pem --require" \
    "-tls1_2 -cert $P/client.pem -key $P/client.key" "hello only"
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
        "$ONLY" server "127.0.0.1:$PORT" --count 4 $S $t > "$OUT/srv.log" 2>&1 &
        sp=$!
        wait_port "$PORT"
        rm -f "$OUT/sess"
        (echo a; sleep 0.5) | timeout 10 openssl s_client -connect "127.0.0.1:$PORT" -servername localhost \
            -CAfile "$P/ca.pem" -"$v" -sess_out "$OUT/sess" > "$OUT/cli.log" 2>&1
        (echo b; sleep 0.5) | timeout 10 openssl s_client -connect "127.0.0.1:$PORT" -servername localhost \
            -CAfile "$P/ca.pem" -"$v" -sess_in "$OUT/sess" > "$OUT/cli2.log" 2>&1
        if grep -q "^Reused" "$OUT/cli2.log"; then
            ok "openssl -> only server: $v resumption ${t:-(cache)}"
        else
            ko "openssl -> only server: $v resumption ${t:-(cache)}" "$OUT/cli2.log"
        fi
        kill $sp 2>/dev/null
        wait $sp 2>/dev/null
    done
done
# ALPN and SNI.
s_server_case "1.3 ALPN" "-cert $P/p256.pem -key $P/p256.key -alpn h2,http/1.1" "--alpn http/1.1,h2"
s_client_case "1.3 ALPN" "$S --alpn h2,http/1.1" "-alpn http/1.1" "ALPN protocol: http/1.1"
s_client_case "1.2 ALPN" "$S --alpn h2,http/1.1" "-tls1_2 -alpn h2" "ALPN protocol: h2"
# KeyUpdate: openssl asks for one back ("K"); our client updates its keys before every record.
s_client_case "1.3 KeyUpdate requested by openssl" "$S" "-tls1_3" "after update" "K\nafter update"
s_server_case "1.3 KeyUpdate sent by only" "-cert $P/p256.pem -key $P/p256.key -tls1_3" "--key-update"
# Bulk.
s_server_case "1.3 64 KiB request" "-cert $P/p256.pem -key $P/p256.key -tls1_3" "--bytes 65536"

# Go crypto/tls.
for k in rsa p256 p384 ed25519; do
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
for c in 29 23 24; do
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
go_server_case "1.3 KeyUpdate sent by only" "-cert $P/p256.pem -key $P/p256.key" "--key-update --bytes 300000"
go_client_case "1.3 many records" "$S" "-key-update"

# curl against only-http over TLS (HTTP/1.1 and HTTP/2 by ALPN).
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
            "Hello, World! "*" 200") ok "curl $v TLS $t -> only-http ($r)" ;;
            *"not found built-in"* | *"option"*) echo "SKIP curl $v TLS $t (not in this curl build)" ;;
            *) ko "curl $v TLS $t -> only-http" && echo "    $r" ;;
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
