#!/usr/bin/env bash
# only-socks GSS-API (RFC 1961, ADR-071) against MIT Kerberos, in one Debian container: a KDC
# for realm ONLY.TEST on 127.0.0.1, the proxy's service principal rcmd/proxy.only.test in a
# keytab, a user alice with a ticket.
#   only <-> only    only-socks' client and server (socks-gss-interop), the GSS-API
#                    mechanism being MIT krb5 through the test-only shim gss_shim.py
#                    (python3-gssapi): protection none, integrity and confidentiality, a 1 MiB
#                    echo; a server requiring integrity upgrading a client that asks for none.
#   gss_client.py    an independent RFC 1961 client (python3-gssapi), checked against Dante,
#                    then against only-socks' server, each level.
#   only -> Dante    our client against Dante with `socksmethod: gssapi` (the reference
#                    server; Debian's source package rebuilt --with-gssapi, as the packaged
#                    one has no GSS-API), each protection level.
# Not curl: Debian 12's curl 7.88 resets `allow_gssapi` when its SOCKS state machine resumes
# after a partial read (lib/socks.c), so its --socks5-gssapi fails against any server, Dante
# included ("per-message authentication is not supported").
#
#   tools/interop/socks/gssapi.sh
set -u
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
if [ ! -f /.dockerenv ] && [ "${SOCKS_INTEROP_INSIDE:-}" != 1 ]; then
  exec docker run --rm --hostname proxy.only.test -v "$ROOT":/w -w /w \
    -v only-cargo-reg:/usr/local/cargo/registry \
    -v only-socks-gss-target:/tmp/t -e CARGO_TARGET_DIR=/tmp/t -e SOCKS_INTEROP_INSIDE=1 -e GSS_DEBUG \
    rust:1-bookworm bash tools/interop/socks/gssapi.sh "$@"
fi

if ! command -v krb5kdc >/dev/null || ! python3 -c 'import gssapi' 2>/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources
  { apt-get update -qq && apt-get install -y -qq krb5-kdc krb5-admin-server krb5-user \
      python3-gssapi curl dpkg-dev libkrb5-dev bison flex; } >/dev/null 2>&1 ||
    { echo "apt-get failed"; exit 1; }
fi
# Debian's (and Alpine's) Dante is built without GSS-API: rebuild Debian's source package with
# it, once (kept in the target volume).
SOCKD=${CARGO_TARGET_DIR:-/tmp}/dante-gssapi/sockd
if [ ! -x "$SOCKD" ]; then
  echo "building Dante with GSS-API..."
  D=$(mktemp -d)
  (cd "$D" && apt-get source -qq dante >/dev/null 2>&1 && cd dante-*/ &&
    cp /usr/share/misc/config.guess /usr/share/misc/config.sub . &&
    touch aclocal.m4 && sleep 1 && touch configure &&
    find . -name Makefile.in -exec touch {} + && find . -name '*.h.in' -exec touch {} + &&
    ./configure --with-gssapi --without-pam --without-libwrap --without-bsdauth \
      --without-upnp --without-ldap >/dev/null 2>&1 && make -j8 >/dev/null 2>&1 &&
    mkdir -p "$(dirname "$SOCKD")" && cp sockd/sockd "$SOCKD") || { echo "Dante build failed"; exit 1; }
  rm -rf "$D"
fi
cargo build -q -p only-socks --example socks-gss-interop || exit 1
EX=${CARGO_TARGET_DIR:-$ROOT/target}/debug/examples/socks-gss-interop
export ONLY_GSS_SHIM=$ROOT/tools/interop/socks/gss_shim.py
W=$(mktemp -d)
chmod 755 "$W" # Dante reads the keytab as nobody
PIDS=""
trap 'kill $PIDS 2>/dev/null; rm -rf "$W"' EXIT
pass=0
fail=0

check() { # name, command...
  local name=$1
  shift
  if "$@" >"$W/out" 2>&1; then
    pass=$((pass + 1))
    echo "  ok  $name"
  else
    fail=$((fail + 1))
    echo "FAIL  $name"
    sed 's/^/      /' "$W/out" | tail -20
  fi
}

# ---- Kerberos ------------------------------------------------------------------------------
# Docker maps the container's host name to its own address; the servers listen on 127.0.0.1.
{ echo "127.0.0.1 proxy.only.test"; grep -v proxy.only.test /etc/hosts; } >"$W/hosts"
cat "$W/hosts" >/etc/hosts
cat >/etc/krb5.conf <<CONF
[libdefaults]
  default_realm = ONLY.TEST
  dns_lookup_kdc = false
  dns_lookup_realm = false
  rdns = false
  dns_canonicalize_hostname = false
[realms]
  ONLY.TEST = {
    kdc = 127.0.0.1
    admin_server = 127.0.0.1
  }
[domain_realm]
  proxy.only.test = ONLY.TEST
CONF
rm -rf /var/lib/krb5kdc/principal*
kdb5_util create -s -r ONLY.TEST -P master-pw >/dev/null 2>&1 || { echo "kdb5_util failed"; exit 1; }
krb5kdc || { echo "krb5kdc failed"; exit 1; }
kadmin.local -q "addprinc -randkey rcmd/proxy.only.test" >/dev/null 2>&1
kadmin.local -q "ktadd -k $W/proxy.keytab rcmd/proxy.only.test" >/dev/null 2>&1
chmod 644 "$W/proxy.keytab"
kadmin.local -q "addprinc -pw alice-pw alice" >/dev/null 2>&1
echo alice-pw | kinit alice >/dev/null || { echo "kinit failed"; exit 1; }
export KRB5_KTNAME=$W/proxy.keytab
echo "kerberos: $(klist | grep 'Default principal')"

# ---- servers -------------------------------------------------------------------------------
"$EX" server 127.0.0.1:1090 none >"$W/only-none.log" 2>&1 & PIDS="$PIDS $!"
"$EX" server 127.0.0.1:1091 integrity >"$W/only-integrity.log" 2>&1 & PIDS="$PIDS $!"
cat >"$W/danted.conf" <<CONF
logoutput: $W/danted.log
internal: 127.0.0.1 port = 1092
external: 127.0.0.1
clientmethod: none
socksmethod: gssapi
user.privileged: root
user.unprivileged: nobody
client pass {
  from: 0.0.0.0/0 to: 0.0.0.0/0
  gssapi.keytab: $W/proxy.keytab
  gssapi.servicename: rcmd
  gssapi.enctype: clear integrity confidentiality
}
socks pass {
  from: 0.0.0.0/0 to: 0.0.0.0/0
  command: connect
  gssapi.enctype: clear integrity confidentiality
}
CONF
"$SOCKD" -f "$W/danted.conf" -D >/dev/null 2>&1 || echo "Dante did not start"
sleep 1

SVC=rcmd@proxy.only.test
# ---- only <-> only, only -> Dante ----------------------------------------------------------
for p in none integrity confidentiality; do
  check "only client -> only server, protection $p" "$EX" client 127.0.0.1:1090 $SVC $p
  check "only client -> Dante, protection $p" "$EX" client 127.0.0.1:1092 $SVC $p
done
check "only client (none) -> only server requiring integrity: upgraded" \
  "$EX" client 127.0.0.1:1091 $SVC none
# ---- an independent client: gss_client.py (python3-gssapi), on Dante first ---------------------
for l in 0 1 2; do
  check "gss_client.py -> Dante, level $l" python3 tools/interop/socks/gss_client.py 1092 $SVC $l
  check "gss_client.py -> only server, level $l" python3 tools/interop/socks/gss_client.py 1090 $SVC $l
done
check "gss_client.py (level 0) -> only server requiring integrity: granted 1" \
  python3 tools/interop/socks/gss_client.py 1091 $SVC 0 1
check "the server saw the Kerberos principal" grep -q 'Some("alice@ONLY.TEST")' "$W/only-none.log"

if [ -n "${GSS_DEBUG:-}" ]; then
  grep -v "debug:" "$W/danted.log" | cut -c1-500 | tail -30
fi
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
