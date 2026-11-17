#!/usr/bin/env bash
# only-socks <-> SOCKS clients, in one Linux container (Debian, everything on 127.0.0.1):
#   curl          --socks5, --socks5-hostname, --socks4, --socks4a and socks5://user:pass@
#                 (CONNECT regressions), a 4 MiB download checked by hash;
#   PySocks       (python3-socks) UDP ASSOCIATE: echo through the relay, a name destination;
#   clients.py    hand-written BIND and UDP ASSOCIATE edge cases (declared port, fragments),
#                 and against only-socks: UDP fragment reassembly and SOCKS4 BIND;
#   only-socks' own client (socks-client-interop): SOCKS5 CONNECT / BIND / UDP ASSOCIATE,
#                 SOCKS4 and 4a CONNECT / BIND, blocking and on the engine, with and without
#                 username/password.
# Every client also runs against Dante (danted), the reference server, so a failure points
# at only-socks rather than at the test (and our client is checked against a server that is
# not ours). Needs Docker; runs `rust:1-bookworm` (Debian 12: 13
# has neither Dante nor PySocks) and installs
# curl, python3-socks and dante-server in it.
#
#   tools/interop/socks/run.sh
set -u
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
if [ ! -f /.dockerenv ] && [ "${SOCKS_INTEROP_INSIDE:-}" != 1 ]; then
  exec docker run --rm -v "$ROOT":/w -w /w -v only-cargo-reg:/usr/local/cargo/registry \
    -v only-socks-interop-target:/tmp/t -e CARGO_TARGET_DIR=/tmp/t -e SOCKS_INTEROP_INSIDE=1 \
    rust:1-bookworm bash tools/interop/socks/run.sh "$@"
fi

if ! command -v curl >/dev/null || ! command -v danted >/dev/null || ! python3 -c 'import socks' 2>/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  { apt-get update -qq && apt-get install -y -qq curl python3-socks dante-server; } >/dev/null 2>&1 || { echo "apt-get failed"; exit 1; }
fi
cargo build -q --release -p only-socks --example socks-interop --example socks-client-interop || exit 1
SRV=${CARGO_TARGET_DIR:-$ROOT/target}/release/examples/socks-interop
CLI=${CARGO_TARGET_DIR:-$ROOT/target}/release/examples/socks-client-interop
W=$(mktemp -d)
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

# A file to fetch, served over HTTP.
mkdir -p "$W/www"
head -c $((4 << 20)) /dev/urandom >"$W/www/blob"
WANT=$(sha256sum <"$W/www/blob" | cut -d' ' -f1)
(cd "$W/www" && exec python3 -m http.server 8000 --bind 127.0.0.1) >/dev/null 2>&1 &
PIDS="$PIDS $!"

"$SRV" 127.0.0.1:1080 >/dev/null & PIDS="$PIDS $!"
"$SRV" 127.0.0.1:1082 alice:s3cret >/dev/null & PIDS="$PIDS $!"
cat >"$W/danted.conf" <<CONF
logoutput: $W/danted.log
internal: 127.0.0.1 port = 1081
external: 127.0.0.1
clientmethod: none
socksmethod: none
user.privileged: root
user.unprivileged: nobody
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 command: bind connect udpassociate bindreply udpreply }
CONF
danted -f "$W/danted.conf" -D >/dev/null 2>&1 || true
sleep 1

fetch() { # curl proxy options...
  [ "$(curl -sS --max-time 20 "$@" http://localhost:8000/blob | sha256sum | cut -d' ' -f1)" = "$WANT" ]
}

for p in "only 1080" "dante 1081"; do
  set -- $p
  echo "== $1 (127.0.0.1:$2)"
  check "curl --socks5 (CONNECT, IPv4)" fetch --socks5 127.0.0.1:$2
  check "curl --socks5-hostname (CONNECT, name)" fetch --socks5-hostname 127.0.0.1:$2
  if [ "$1" = only ]; then # SOCKS4 is checked against only-socks alone
    check "curl --socks4" fetch --socks4 127.0.0.1:$2
    check "curl --socks4a" fetch --socks4a 127.0.0.1:$2
  fi
  if [ "$1" = only ]; then
    check "PySocks UDP + BIND + raw UDP + fragments + SOCKS4 BIND (clients.py)" \
      python3 "$ROOT/tools/interop/socks/clients.py" 127.0.0.1 $2 --fragments --socks4-bind
  else
    check "PySocks UDP + BIND + raw UDP (clients.py)" python3 "$ROOT/tools/interop/socks/clients.py" 127.0.0.1 $2
  fi
  if [ "$1" = only ]; then
    check "only-socks client: SOCKS5/4/4a CONNECT, BIND, UDP (socks-client-interop)" "$CLI" 127.0.0.1:$2
  else # Dante 1.4 refuses SOCKS4a host names (curl --socks4a too)
    check "only-socks client: SOCKS5/4/4a CONNECT, BIND, UDP (socks-client-interop)" \
      "$CLI" 127.0.0.1:$2 --no-socks4a-names
  fi
done
echo "== only with username/password (127.0.0.1:1082)"
check "curl socks5://user:pass@" fetch -x socks5://alice:s3cret@127.0.0.1:1082
check "curl socks5h://user:pass@" fetch -x socks5h://alice:s3cret@127.0.0.1:1082
check "curl wrong password refused" bash -c '! curl -sS --max-time 5 -x socks5://alice:nope@127.0.0.1:1082 http://localhost:8000/blob -o /dev/null'
check "clients.py with authentication" python3 "$ROOT/tools/interop/socks/clients.py" 127.0.0.1 1082 alice s3cret --fragments
check "only-socks client with authentication" "$CLI" 127.0.0.1:1082 alice:s3cret --no-socks4

echo "socks interop: $pass passed, $fail failed"
[ "$fail" = 0 ]
