#!/usr/bin/env bash
# only-bittorrent <-> mainstream clients, in one Linux container (Debian, all on 127.0.0.1):
#   aria2 1.37        leeching from only (plain, MSE required, magnet) and seeding to only
#                     (UDP tracker; plain and MSE);
#   libtorrent 2.0    (python3-libtorrent) leeching from only over uTP+RC4 and TCP, and by
#                     magnet; seeding to only over uTP+RC4, TCP, and by magnet; and the DHT:
#                     a only DHT node bootstraps libtorrent, only finds libtorrent's seed by
#                     DHT + magnet, and libtorrent finds only's seed the same way.
# Trackers are only's own (HTTP and UDP). Needs Docker; runs `rust:1` (Debian trixie) and
# installs aria2 and python3-libtorrent in it.
#
#   tools/interop/bittorrent/run.sh            # everything
#   tools/interop/bittorrent/run.sh aria2 lt   # some suites (aria2, lt, dht)
set -u
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
if [ ! -f /.dockerenv ] && [ "${BT_INTEROP_INSIDE:-}" != 1 ]; then
  exec docker run --rm -v "$ROOT":/w -w /w -v only-cargo-reg:/usr/local/cargo/registry \
    -v only-bt-interop-target:/tmp/t -e CARGO_TARGET_DIR=/tmp/t -e BT_INTEROP_INSIDE=1 rust:1 bash tools/interop/bittorrent/run.sh "$@"
fi

SUITES=${*:-aria2 lt dht}
if ! command -v aria2c >/dev/null || ! python3 -c 'import libtorrent' 2>/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  { apt-get update -qq && apt-get install -y -qq aria2 python3-libtorrent; } >/dev/null 2>&1 || exit 1
fi
cargo build -q --release -p only-bittorrent --example bt-interop || exit 1
BT=${CARGO_TARGET_DIR:-$ROOT/target}/release/examples/bt-interop
LT="python3 $ROOT/tools/interop/bittorrent/lt.py"
W=$(mktemp -d)
PIDS=""
trap 'kill $PIDS 2>/dev/null; rm -rf "$W"' EXIT
pass=0
fail=0
FAILED=""

bg() { # variable, command...: starts the command in the background, its pid in the variable
  local v=$1
  shift
  "$@" >"$W/log.$v" 2>&1 &
  eval "$v=$!"
  PIDS="$PIDS $!"
}
stop() { kill "$@" 2>/dev/null; wait "$@" 2>/dev/null; }
check() { # name, data dir, file
  if cmp -s "$W/src/data.bin" "$2/data.bin"; then
    echo "PASS $1"; pass=$((pass + 1))
  else
    echo "FAIL $1"; fail=$((fail + 1)); FAILED="$FAILED|$1"
  fi
}
run() { # name, data dir, command...
  local name=$1 dir=$2
  shift 2
  if timeout 90 "$@" >"$W/out" 2>&1; then
    grep -E "complete|peer" "$W/out" | tail -3 | sed 's/^/    /'
    check "$name" "$dir"
  else
    echo "FAIL $name (exit $?)"; tail -15 "$W/out" | sed 's/^/    /'
    fail=$((fail + 1)); FAILED="$FAILED|$name"
  fi
}
expect() { # name, pattern: the last output must contain it
  if grep -qE "$2" "$W/out"; then echo "PASS $1"; pass=$((pass + 1)); else
    echo "FAIL $1 (no '$2')"; fail=$((fail + 1)); FAILED="$FAILED|$1"; fi
}

mkdir -p "$W/src"
head -c $((20 * 1024 * 1024 + 12345)) /dev/urandom >"$W/src/data.bin"
TR=127.0.0.1:7000
$BT make "$W/src/data.bin" "$W/http.torrent" "http://$TR/announce" >/dev/null
$BT make "$W/src/data.bin" "$W/udp.torrent" "udp://$TR/announce" >/dev/null
IH=$($BT make "$W/src/data.bin" "$W/bare.torrent" -)
bg TRACKER $BT tracker $TR
sleep 0.5

case " $SUITES " in *" aria2 "*)
  echo "== aria2 $(aria2c --version | head -1 | awk '{print $3}')"
  bg SEED $BT seed "$W/http.torrent" "$W/src" 127.0.0.1:7100 --no-dht
  sleep 1
  A="aria2c -q --seed-time=0 --enable-dht=false --enable-dht6=false --bt-enable-lpd=false --enable-peer-exchange=false --allow-overwrite=true"
  run "aria2 leeches from only (TCP, HTTP tracker)" "$W/a1" $A --listen-port=7201 --dir="$W/a1" "$W/http.torrent"
  run "aria2 leeches from only (MSE required)" "$W/a2" $A --listen-port=7202 --bt-require-crypto=true --bt-min-crypto-level=arc4 --dir="$W/a2" "$W/http.torrent"
  run "aria2 leeches from only by magnet (metadata from only)" "$W/a3" $A --listen-port=7203 --dir="$W/a3" "magnet:?xt=urn:btih:$IH&tr=http://$TR/announce"
  stop $SEED
  # aria2 speaks UDP trackers only with its DHT on (it shares the DHT socket); nothing to bootstrap.
  bg ASEED aria2c --seed-ratio=0.0 -V --enable-dht=true --dht-listen-port=7205 --bt-enable-lpd=false --listen-port=7204 --dir="$W/src" "$W/udp.torrent"
  sleep 3
  run "only leeches from aria2 (TCP, UDP tracker)" "$W/f1" $BT leech "$W/udp.torrent" "$W/f1" 127.0.0.1:7101 --no-dht --no-utp --mse off --expect-tcp
  run "only leeches from aria2 (MSE required)" "$W/f2" $BT leech "$W/udp.torrent" "$W/f2" 127.0.0.1:7102 --no-dht --no-utp --mse require --expect-encrypted
  stop $ASEED
  ;;
esac

case " $SUITES " in *" lt "*)
  echo "== libtorrent $(python3 -c 'import libtorrent; print(libtorrent.__version__)')"
  bg SEED $BT seed "$W/bare.torrent" "$W/src" 127.0.0.1:7110 --no-dht
  sleep 1
  run "libtorrent leeches from only (uTP only, RC4 forced)" "$W/l1" $LT leech "$W/bare.torrent" "$W/l1" 7301 --peer 127.0.0.1:7110 --utp-only --enc forced
  expect "  ... and the connection was uTP with RC4" "utp=True rc4=True"
  run "libtorrent leeches from only (TCP only, plaintext)" "$W/l2" $LT leech "$W/bare.torrent" "$W/l2" 7302 --peer 127.0.0.1:7110 --tcp-only --enc disabled
  expect "  ... and the connection was TCP in plaintext" "utp=False rc4=False"
  run "libtorrent leeches from only by magnet (metadata from only)" "$W/l3" $LT leech "magnet:?xt=urn:btih:$IH" "$W/l3" 7303 --peer 127.0.0.1:7110
  stop $SEED
  bg LSEED $LT seed "$W/bare.torrent" "$W/src" 7310 --enc forced
  bg LSEED2 $LT seed "$W/bare.torrent" "$W/src" 7311 --enc disabled --tcp-only
  sleep 2
  run "only leeches from libtorrent (uTP, MSE required)" "$W/f3" $BT leech "$W/bare.torrent" "$W/f3" 127.0.0.1:7111 --peer 127.0.0.1:7310 --no-dht --mse require --expect-utp --expect-encrypted
  run "only leeches from libtorrent (TCP, plaintext)" "$W/f4" $BT leech "$W/bare.torrent" "$W/f4" 127.0.0.1:7112 --peer 127.0.0.1:7311 --no-dht --no-utp --mse off --expect-tcp
  run "only leeches from libtorrent by magnet (metadata from libtorrent)" "$W/f5" $BT leech "magnet:?xt=urn:btih:$IH" "$W/f5" 127.0.0.1:7113 --peer 127.0.0.1:7310 --no-dht
  stop $LSEED $LSEED2
  ;;
esac

case " $SUITES " in *" dht "*)
  echo "== DHT (only node as the bootstrap node, libtorrent and only peers)"
  bg ROUTER $BT dht 127.0.0.1:7400
  sleep 1
  bg LSEED $LT seed "$W/bare.torrent" "$W/src" 7410 --dht 127.0.0.1:7400
  sleep 8
  run "only finds libtorrent's seed by DHT (magnet, no tracker, no peer)" "$W/f6" $BT leech "magnet:?xt=urn:btih:$IH" "$W/f6" 127.0.0.1:7411 --bootstrap 127.0.0.1:7400
  stop $LSEED
  bg FSEED $BT seed "$W/bare.torrent" "$W/src" 127.0.0.1:7412 --bootstrap 127.0.0.1:7400
  sleep 4
  run "libtorrent finds only's seed by DHT (magnet, no tracker, no peer)" "$W/l4" $LT leech "magnet:?xt=urn:btih:$IH" "$W/l4" 7413 --dht 127.0.0.1:7400
  stop $FSEED $ROUTER
  ;;
esac

stop $TRACKER
echo "bittorrent interop: $pass passed, $fail failed"
[ "$fail" = 0 ] || { echo "failed:$FAILED" | tr '|' '\n  '; exit 1; }
