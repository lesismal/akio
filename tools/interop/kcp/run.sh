#!/usr/bin/env bash
# flash-kcp <-> kcp-go (xtaci/kcp-go v5, as kcptun), both directions, for several crypts, with
# and without FEC, directly and through a relay dropping every 7th datagram. Needs Go.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT" && cargo build -q --release -p flash-kcp --example kcp-interop
RS=$ROOT/target/release/examples/kcp-interop
cd "$ROOT/tools/interop/kcp" && GOFLAGS=-mod=mod go build -o /tmp/kcp-go .
GO=/tmp/kcp-go
PIDS=""
trap 'kill $PIDS 2>/dev/null || true' EXIT
port=9300
for c in "plain 0 0" "none 0 0" "xor 0 0" "aes 10 3" "aes-128 0 0" "aes-128-gcm 4 2"; do
  set -- $c
  gs=$port; rs=$((port + 1)); gr=$((port + 2)); rr=$((port + 3)); port=$((port + 4))
  $GO server 127.0.0.1:$gs "$@" > /dev/null & PIDS="$PIDS $!"
  $RS server 127.0.0.1:$rs "$@" > /dev/null & PIDS="$PIDS $!"
  sleep 0.5
  echo "== $c"
  echo -n "flash client -> kcp-go server: "; $RS client 127.0.0.1:$gs "$@"
  echo -n "kcp-go client -> flash server: "; $GO client 127.0.0.1:$rs "$@"
  if [ "$2" != 0 ]; then
    $GO relay 127.0.0.1:$gr 127.0.0.1:$gs 7 > /dev/null & PIDS="$PIDS $!"
    $GO relay 127.0.0.1:$rr 127.0.0.1:$rs 7 > /dev/null & PIDS="$PIDS $!"
    sleep 0.3
    echo -n "  lossy, flash client -> kcp-go server: "; $RS client 127.0.0.1:$gr "$@"
    echo -n "  lossy, kcp-go client -> flash server: "; $GO client 127.0.0.1:$rr "$@"
  fi
done
echo "kcp interop: all passed"
