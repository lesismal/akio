#!/usr/bin/env bash
# Local Service Discovery (BEP 14) between only and libtorrent 2.0, in two containers on a
# Docker bridge network: neither side knows a tracker, a DHT node or the other's address.
#   1. only seeds (LSD on), libtorrent leeches (LSD on): libtorrent hears only's announcement.
#   2. libtorrent seeds, only leeches: only hears libtorrent's announcement.
# Run by tools/interop/bittorrent/run.sh (suite `lsd`), or on its own.
set -u
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
IMAGE=akio-bt-interop:latest
NET=akio-bt-lsd
VOL=akio-bt-lsd-data
docker image inspect $IMAGE >/dev/null 2>&1 || docker build -q -t $IMAGE "$ROOT/tools/interop/bittorrent" >/dev/null || exit 1
docker network rm $NET >/dev/null 2>&1
docker network create $NET >/dev/null || exit 1
docker volume rm $VOL >/dev/null 2>&1
RUN="docker run --rm --network $NET -v $ROOT:/w -w /w -v akio-cargo-reg:/usr/local/cargo/registry -v akio-bt-interop-target:/tmp/t -e CARGO_TARGET_DIR=/tmp/t -v $VOL:/d $IMAGE"
BT=/tmp/t/release/examples/bt-interop
LT="python3 /w/tools/interop/bittorrent/lt.py"
cleanup() { docker rm -f akio-bt-lsd-a akio-bt-lsd-b >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; docker volume rm $VOL >/dev/null 2>&1; }
trap cleanup EXIT
echo "== LSD (BEP 14) on a Docker network"
$RUN bash -c "cargo build -q --release -p akio-bittorrent --example bt-interop && mkdir -p /d/src && head -c 3000000 /dev/urandom >/d/src/lsd.bin && $BT make /d/src/lsd.bin /d/lsd.torrent - >/dev/null" || exit 1
pass=0
fail=0
case1() { # seed-side command, leech-side command, name
  docker run -d --name akio-bt-lsd-a --network $NET -v "$ROOT":/w -w /w -v akio-bt-interop-target:/tmp/t -v $VOL:/d $IMAGE bash -c "$1" >/dev/null
  sleep 2
  if docker run --rm --name akio-bt-lsd-b --network $NET -v "$ROOT":/w -w /w -v akio-bt-interop-target:/tmp/t -v $VOL:/d $IMAGE bash -c "$2" >/tmp/akio-bt-lsd.out 2>&1; then
    echo "PASS $3"; pass=$((pass + 1))
  else
    echo "FAIL $3"; tail -15 /tmp/akio-bt-lsd.out | sed 's/^/    /'; docker logs akio-bt-lsd-a 2>&1 | tail -8 | sed 's/^/    a: /'
    fail=$((fail + 1))
  fi
  docker rm -f akio-bt-lsd-a >/dev/null 2>&1
}
case1 "$BT seed /d/lsd.torrent /d/src 0.0.0.0:7700 --no-dht --lsd" \
  "timeout 120 $LT leech /d/lsd.torrent /tmp/l 7701 --lsd --listen-ip 0.0.0.0 --timeout 110 && cmp /d/src/lsd.bin /tmp/l/lsd.bin" \
  "libtorrent finds only's seed by LSD (Docker network)"
case1 "$LT seed /d/lsd.torrent /d/src 7710 --lsd --listen-ip 0.0.0.0" \
  "timeout 120 $BT leech /d/lsd.torrent /tmp/l 0.0.0.0:7711 --no-dht --lsd --timeout 110 && cmp /d/src/lsd.bin /tmp/l/lsd.bin" \
  "only finds libtorrent's seed by LSD (Docker network)"
echo "bittorrent lsd interop: $pass passed, $fail failed"
[ "$fail" = 0 ]
