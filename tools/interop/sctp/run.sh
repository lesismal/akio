#!/usr/bin/env bash
# only-sctp (examples/udp_peer.rs) <-> pion/sctp v1.12.0 + pion/datachannel over plain UDP:
# both roles, with pion's RFC 8260 interleaving on (I-DATA / I-FORWARD-TSN negotiated) and off
# (DATA / FORWARD TSN), without loss and with every 10th packet dropped each way (at every 4th,
# 25 %, pion often needs longer than the Rust side's 60 s limit, with DATA as with I-DATA). Needs Go.
# RS / GO: prebuilt binaries (skips the builds).
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
if [ -z "${RS:-}" ]; then
  (cd "$ROOT" && cargo build -q --release -p only-sctp --example udp_peer)
  RS=$ROOT/target/release/examples/udp_peer
fi
if [ -z "${GO:-}" ]; then
  (cd "$ROOT/tools/interop/sctp" && GOFLAGS=-mod=mod go build -o /tmp/only-sctp-pion .)
  GO=/tmp/only-sctp-pion
fi
PIDS=""
trap 'kill $PIDS 2>/dev/null || true' EXIT
R=127.0.0.1:6100
P=127.0.0.1:6101
for interleave in 1 0; do
  for loss in 0 10; do
    for rust in connect accept; do
      pion=accept
      [ "$rust" = accept ] && pion=connect
      echo "== rust $rust, pion $pion, pion interleaving $interleave, drop every ${loss}th packet"
      # The passive side starts first: a connected UDP socket fails on ICMP unreachable.
      if [ "$rust" = connect ]; then
        $GO "$pion" "$P" "$R" "$loss" "$interleave" >/tmp/only-sctp-pion.log 2>&1 & GP=$!
        PIDS="$PIDS $GP"
        sleep 0.3
        $RS "$rust" "$R" "$P" "$loss" | tail -4
      else
        ($RS "$rust" "$R" "$P" "$loss" >/tmp/only-sctp-rust.log 2>&1; echo $? >>/tmp/only-sctp-rust.log) & RP=$!
        sleep 0.3
        $GO "$pion" "$P" "$R" "$loss" "$interleave" >/tmp/only-sctp-pion.log 2>&1 & GP=$!
        PIDS="$PIDS $GP"
        wait $RP
        tail -5 /tmp/only-sctp-rust.log
        [ "$(tail -1 /tmp/only-sctp-rust.log)" = 0 ]
      fi
      grep "pion: established" /tmp/only-sctp-pion.log
      want=true
      [ "$interleave" = 0 ] && want=false
      grep -q "interleaving=$want" /tmp/only-sctp-pion.log
      kill $GP 2>/dev/null || true
      wait $GP 2>/dev/null || true
    done
  done
done
echo "sctp interop: all passed"
