#!/usr/bin/env bash
# AF_XDP vs AF_PACKET under the userspace stack (only-dpdk), same-run A/B on one veth pair
# (ADR-063). The stack serves UDP/TCP echo on one end (root namespace); kernel clients in a
# network namespace on the other end measure UDP and TCP request/response rates (64 B), TCP
# connections per second and single-connection TCP echo throughput. The links alternate within
# each round (and swap order every round). Linux, root. Run it on a quiet host:
#
#   /root/only-bench/quiet.sh run tools/bench/afxdp.sh
#
#   SECS (5) seconds per measurement, RUNS (5) rounds, THREADS (4) client threads,
#   SRV_CPU (2) the stack's I/O thread, CLI_CPUS (4-7) the clients, LINKS (af_packet af_xdp).
#
# Both links run with TSO/GSO/GRO off on the pair, so each moves one MTU-sized frame per
# segment (an AF_XDP chunk holds one frame; AF_PACKET would otherwise see 64 KiB aggregates).
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
T=${CARGO_TARGET_DIR:-$ROOT/target}
export CARGO_TARGET_DIR=$T
SECS=${SECS:-5}
RUNS=${RUNS:-5}
THREADS=${THREADS:-4}
SRV_CPU=${SRV_CPU:-2}
CLI_CPUS=${CLI_CPUS:-4-7}
LINKS=${LINKS:-af_packet af_xdp}
NS=onlyxab
cargo build -q --release -p only-dpdk --example link-bench || exit 1
BIN=$T/release/examples/link-bench

cleanup() { ip netns del "$NS" 2>/dev/null; ip link del flxab0 2>/dev/null; true; }
trap cleanup EXIT
cleanup
ip netns add "$NS"
ip link add flxab0 type veth peer name flxab1
ip link set flxab1 netns "$NS"
ip -n "$NS" addr add 10.66.0.1/24 dev flxab1
ip -n "$NS" link set lo up
ip -n "$NS" link set flxab1 up
ip link set flxab0 up
ethtool -K flxab0 tso off gso off gro off >/dev/null
ip netns exec "$NS" ethtool -K flxab1 tso off gso off gro off >/dev/null
# Connection churn from one client namespace: reuse TIME_WAIT ports (this namespace only).
ip netns exec "$NS" sysctl -qw net.ipv4.tcp_tw_reuse=1 net.ipv4.ip_local_port_range="1024 65000"

echo "# $(uname -sr), $(nproc) CPUs; ${SECS}s x $RUNS rounds, $THREADS client threads; stack on CPU $SRV_CPU"
for r in $(seq "$RUNS"); do
  order=$LINKS
  [ $((r % 2)) -eq 0 ] && order=$(echo "$LINKS" | awk '{for(i=NF;i>0;i--) printf "%s ", $i}')
  for link in $order; do
    # The stack's MAC differs per link (AF_XDP takes the interface's): forget the old one.
    ip -n "$NS" neigh flush dev flxab1
    fifo=$(mktemp -u)
    mkfifo "$fifo"
    taskset -c "$SRV_CPU" "$BIN" serve "$link" flxab0 10.66.0.2 <"$fifo" >"$fifo.out" 2>"$fifo.err" &
    pid=$!
    exec 7>"$fifo"
    for _ in $(seq 100); do grep -q ready "$fifo.out" 2>/dev/null && break; sleep 0.1; done
    res=$(ip netns exec "$NS" taskset -c "$CLI_CPUS" "$BIN" client 10.66.0.2 "$SECS" "$THREADS" 2>&1 | tail -1)
    exec 7>&-
    wait "$pid"
    info=$(grep -o 'Some(.*)' "$fifo.err" 2>/dev/null | head -1)
    echo "round=$r link=$link $res ${info}"
    rm -f "$fifo" "$fifo.out" "$fifo.err"
    # Let TIME_WAIT and the XDP detach settle.
    sleep 1
  done
done
