#!/usr/bin/env bash
# only-ice <-> libnice with one stream of two components (RTP and RTCP without rtcp-mux) over
# loopback UDP, in one Linux container (Debian 12, libnice 0.1.21): libnice controlling with
# aggressive and with regular nomination, libnice controlled, libnice lite, and only-ice lite
# (crates/only-ice/tests/libnice.rs). The peer (tools/interop/ice/nicepeer.c) is built against
# Debian's libnice-dev. pion/ice, the other interop peer (crates/only-ice/tests/pion.rs), has
# only component 1. Needs Docker.
#
#   tools/interop/ice/run.sh   # ICE_INTEROP_TARGET=/abs/dir: target dir (default: a volume)
set -u
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
if [ ! -f /.dockerenv ] && [ "${ICE_INTEROP_INSIDE:-}" != 1 ]; then
  exec docker run --rm -v "$ROOT":/w -w /w -v only-cargo-reg:/usr/local/cargo/registry \
    -v "${ICE_INTEROP_TARGET:-only-ice-interop-target}":/tmp/t -e CARGO_TARGET_DIR=/tmp/t -e ICE_INTEROP_INSIDE=1 \
    rust:1-bookworm bash tools/interop/ice/run.sh "$@"
fi

if ! pkg-config --exists nice 2>/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  { apt-get update -qq && apt-get install -y -qq libnice-dev pkg-config; } >/dev/null 2>&1 || { echo "apt-get failed"; exit 1; }
fi
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
# shellcheck disable=SC2046
cc -O1 -Wall -Wextra -o "$W/nicepeer" "$ROOT/tools/interop/ice/nicepeer.c" $(pkg-config --cflags --libs nice) || exit 1
echo "libnice $(pkg-config --modversion nice)"
ONLY_ICE_NICE_PEER="$W/nicepeer" cargo test -q -p only-ice --test libnice -- --ignored --test-threads 1 "$@"
