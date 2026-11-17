#!/usr/bin/env bash
# only-bittorrent <-> mainstream clients, in one Linux container (Debian, all on 127.0.0.1):
#   aria2 1.37        leeching from only (plain, MSE required, magnet) and seeding to only
#                     (UDP tracker; plain and MSE);
#   libtorrent 2.0    (python3-libtorrent) leeching from only over uTP+RC4 and TCP, and by
#                     magnet; seeding to only over uTP+RC4, TCP, and by magnet; and the DHT:
#                     a only DHT node bootstraps libtorrent, only finds libtorrent's seed by
#                     DHT + magnet, and libtorrent finds only's seed the same way.
#   v2 (BEP 52)       v2-only and hybrid multi-file torrents made by only and by libtorrent,
#                     each side leeching from the other by .torrent and by magnet link (a v2
#                     magnet makes the leecher fetch the piece layers with hash requests);
#                     aria2 (no v2 support) leeching a hybrid torrent from only and seeding one.
#   webseed (BEP 19)  only downloads v1, hybrid and v2 torrents from nginx alone (no peer), and
#                     libtorrent downloads only's hybrid torrent from the same web seed.
#   lsd (BEP 14)      two containers on a Docker bridge network, no tracker, DHT or peer
#                     address: libtorrent finds only's seed by LSD, and only finds libtorrent's.
# Trackers are only's own (HTTP and UDP). Needs Docker; runs the image of ./Dockerfile
# (`rust:1`, Debian trixie, with aria2, python3-libtorrent and nginx), built on first use.
#
#   tools/interop/bittorrent/run.sh            # everything
#   tools/interop/bittorrent/run.sh aria2 lt   # some suites (aria2, lt, dht, v2, webseed, lsd)
set -u
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
IMAGE=only-bt-interop:latest
if [ ! -f /.dockerenv ] && [ "${BT_INTEROP_INSIDE:-}" != 1 ]; then
  docker image inspect $IMAGE >/dev/null 2>&1 || docker build -q -t $IMAGE "$ROOT/tools/interop/bittorrent" >/dev/null || exit 1
  ALL=${*:-aria2 lt dht v2 webseed lsd}
  INSIDE=$(echo " $ALL " | sed 's/ lsd / /')
  rc=0
  if [ -n "$(echo $INSIDE)" ]; then
    docker run --rm -v "$ROOT":/w -w /w -v only-cargo-reg:/usr/local/cargo/registry \
      -v only-bt-interop-target:/tmp/t -e CARGO_TARGET_DIR=/tmp/t -e BT_INTEROP_INSIDE=1 $IMAGE \
      bash tools/interop/bittorrent/run.sh $INSIDE || rc=1
  fi
  case " $ALL " in *" lsd "*) bash "$ROOT/tools/interop/bittorrent/lsd.sh" || rc=1 ;; esac
  exit $rc
fi

SUITES=${*:-aria2 lt dht v2 webseed}
if ! command -v aria2c >/dev/null || ! python3 -c 'import libtorrent' 2>/dev/null || ! command -v nginx >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  { apt-get update -qq && apt-get install -y -qq aria2 python3-libtorrent nginx; } >/dev/null 2>&1 || exit 1
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
checkdir() { # name, data dir: the tree must match the source tree
  # Padding files (BEP 47) that v1-only clients write are not part of the data.
  if diff -r -x .pad "$W/src/tree" "$2/tree" >/dev/null 2>&1; then
    echo "PASS $1"; pass=$((pass + 1))
  else
    echo "FAIL $1"; fail=$((fail + 1)); FAILED="$FAILED|$1"
  fi
}
rund() { # name, data dir, command...: like run, comparing the tree
  local name=$1 dir=$2
  shift 2
  if timeout 90 "$@" >"$W/out" 2>&1; then
    grep -E "complete|peer" "$W/out" | tail -3 | sed 's/^/    /'
    checkdir "$name" "$dir"
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

# A multi-file tree with odd sizes and an empty file: v2 aligns files to pieces (padding).
mkdir -p "$W/src/tree/sub"
head -c $((3 * 1024 * 1024 + 4321)) /dev/urandom >"$W/src/tree/big.bin"
: >"$W/src/tree/empty"
head -c 5000 /dev/urandom >"$W/src/tree/sub/small.txt"
head -c 700001 /dev/urandom >"$W/src/tree/sub/mid.bin"

case " $SUITES " in *" v2 "*)
  echo "== v2 and hybrid torrents (BEP 52): libtorrent $(python3 -c 'import libtorrent; print(libtorrent.__version__)'), aria2"
  for kind in v2 hybrid; do
    $BT make "$W/src/tree" "$W/o-$kind.torrent" "http://$TR/announce" 65536 $kind >/dev/null
    $LT make "$W/src/tree" "$W/l-$kind.torrent" $kind 65536 >/dev/null
  done
  bg S2 $BT seed "$W/o-v2.torrent" "$W/src" 127.0.0.1:7500 --no-dht
  bg SH $BT seed "$W/o-hybrid.torrent" "$W/src" 127.0.0.1:7501 --no-dht
  sleep 1
  rund "libtorrent leeches a v2 torrent made by only from only" "$W/v1" $LT leech "$W/o-v2.torrent" "$W/v1" 7510 --peer 127.0.0.1:7500
  rund "libtorrent leeches a hybrid torrent made by only from only" "$W/v2" $LT leech "$W/o-hybrid.torrent" "$W/v2" 7511 --peer 127.0.0.1:7501
  rund "libtorrent leeches by v2 magnet from only (piece layers from only)" "$W/v3" $LT leech "$($BT magnet "$W/o-v2.torrent")" "$W/v3" 7512 --peer 127.0.0.1:7500
  rund "libtorrent leeches by hybrid magnet from only" "$W/v4" $LT leech "$($BT magnet "$W/o-hybrid.torrent")" "$W/v4" 7513 --peer 127.0.0.1:7501
  A="aria2c -q --seed-time=0 --enable-dht=false --enable-dht6=false --bt-enable-lpd=false --enable-peer-exchange=false --allow-overwrite=true"
  rund "aria2 leeches a hybrid torrent made by only from only (its v1 part)" "$W/v5" $A --listen-port=7514 --dir="$W/v5" "$W/o-hybrid.torrent"
  stop $S2 $SH
  bg L2 $LT seed "$W/l-v2.torrent" "$W/src" 7520
  bg LH $LT seed "$W/l-hybrid.torrent" "$W/src" 7521
  sleep 2
  rund "only leeches a v2 torrent made by libtorrent from libtorrent" "$W/v6" $BT leech "$W/l-v2.torrent" "$W/v6" 127.0.0.1:7530 --peer 127.0.0.1:7520 --no-dht
  rund "only leeches a hybrid torrent made by libtorrent from libtorrent" "$W/v7" $BT leech "$W/l-hybrid.torrent" "$W/v7" 127.0.0.1:7531 --peer 127.0.0.1:7521 --no-dht
  rund "only leeches by v2 magnet from libtorrent (piece layers by hash requests)" "$W/v8" $BT leech "$($LT magnet "$W/l-v2.torrent")" "$W/v8" 127.0.0.1:7532 --peer 127.0.0.1:7520 --no-dht
  rund "only leeches by hybrid magnet from libtorrent" "$W/v9" $BT leech "$($LT magnet "$W/l-hybrid.torrent")" "$W/v9" 127.0.0.1:7533 --peer 127.0.0.1:7521 --no-dht
  stop $L2 $LH
  # aria2 knows nothing of BEP 47: it seeds padding files as files, so they must exist.
  cp -r "$W/src" "$W/asrc"
  python3 - "$W/l-hybrid.torrent" "$W/asrc" <<'PY'
import os, sys, libtorrent as lt
info = lt.bdecode(open(sys.argv[1], "rb").read())[b"info"]
for f in info[b"files"]:
    if b"p" in f.get(b"attr", b""):
        p = os.path.join(sys.argv[2], info[b"name"].decode(), *[c.decode() for c in f[b"path"]])
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "wb").write(bytes(f[b"length"]))
PY
  bg AS aria2c --seed-ratio=0.0 -V --enable-dht=false --bt-enable-lpd=false --listen-port=7540 --dir="$W/asrc" "$W/l-hybrid.torrent"
  sleep 3
  rund "only leeches a hybrid torrent (made by libtorrent) from aria2" "$W/v10" $BT leech "$W/l-hybrid.torrent" "$W/v10" 127.0.0.1:7541 --peer 127.0.0.1:7540 --no-dht
  stop $AS
  ;;
esac

case " $SUITES " in *" webseed "*)
  echo "== web seeds (BEP 19) from nginx $(nginx -v 2>&1 | sed 's/.*\///')"
  mkdir -p "$W/www" && cp -r "$W/src/tree" "$W/src/data.bin" "$W/www/"
  chmod 755 "$W" && chmod -R a+rX "$W/www" # nginx's workers run as www-data
  cat >"$W/nginx.conf" <<NGINX
daemon off;
pid $W/nginx.pid;
error_log $W/nginx.err;
events {}
http { access_log off; server { listen 127.0.0.1:7600; root $W/www; } }
NGINX
  bg NGINX nginx -c "$W/nginx.conf"
  sleep 1
  $BT make "$W/src/data.bin" "$W/ws-single.torrent" - 262144 v1 --web-seed "http://127.0.0.1:7600/data.bin" >/dev/null
  run "only downloads a single-file v1 torrent from a web seed alone" "$W/w0" $BT leech "$W/ws-single.torrent" "$W/w0" 127.0.0.1:7610 --no-dht
  for kind in v1 hybrid v2; do
    $BT make "$W/src/tree" "$W/ws-$kind.torrent" - 65536 $kind --web-seed "http://127.0.0.1:7600/" >/dev/null
    rund "only downloads a $kind torrent from a web seed alone" "$W/w-$kind" $BT leech "$W/ws-$kind.torrent" "$W/w-$kind" 127.0.0.1:7611 --no-dht
  done
  rund "libtorrent downloads only's hybrid torrent from the same web seed" "$W/w-lt" $LT leech "$W/ws-hybrid.torrent" "$W/w-lt" 7612
  stop $NGINX
  ;;
esac

stop $TRACKER
echo "bittorrent interop: $pass passed, $fail failed"
[ "$fail" = 0 ] || { echo "failed:$FAILED" | tr '|' '\n  '; exit 1; }
