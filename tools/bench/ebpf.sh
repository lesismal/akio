#!/usr/bin/env bash
# eBPF acceleration benchmark (Linux, root): SO_REUSEPORT steering on/off, the SOCKS tunnel
# relayed in userspace vs spliced with the sockmap relay, and the XDP rate limiter's drop rate.
# Every case alternates within each round (same-run A/B). Run it on a quiet host, e.g.
#
#   /root/akio-bench/quiet.sh run tools/bench/ebpf.sh
#
#   SECS (5) seconds per measurement, RUNS (3) rounds, SRV_CPUS (0-3) / CLI_CPUS (4-7,12-15),
#   ONLY (steer,socks,xdp) the sections to run.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
T=${CARGO_TARGET_DIR:-$ROOT/target}
export CARGO_TARGET_DIR=$T
SECS=${SECS:-5}
RUNS=${RUNS:-3}
SRV_CPUS=${SRV_CPUS:-0-3}
CLI_CPUS=${CLI_CPUS:-4-7,12-15}
ONLY=${ONLY:-steer,socks,xdp}
want() { case ",$ONLY," in *",$1,"*) return 0 ;; esac; return 1; }
cargo build -q --release -p echo-bench || exit 1
cargo build -q --release -p akio --example bench-server -p akio-socks --example ebpf-bench || exit 1
E=$T/release/examples
echo "# $(uname -sr), $(nproc) CPUs; ${SECS}s x $RUNS rounds"

# 1. Steering: echo, 4 I/O threads on $SRV_CPUS, 256 connections x 64 B from 8 client threads.
PORT=19401
want steer && for r in $(seq "$RUNS"); do
  for mode in none cpu cpu-pin hash; do
    AKIO_ACCEL=$mode taskset -c "$SRV_CPUS" "$E/bench-server" tcp "127.0.0.1:$PORT" 4 epoll >/dev/null 2>&1 &
    pid=$!
    sleep 1
    taskset -c "$CLI_CPUS" "$T/release/echo-bench" "127.0.0.1:$PORT" 256 64 1 8 tcp >/dev/null 2>&1
    v=$(taskset -c "$CLI_CPUS" "$T/release/echo-bench" "127.0.0.1:$PORT" 256 64 "$SECS" 8 tcp 2>/dev/null |
      awk '{for(i=2;i<=NF;i++) if($i=="req/s") print $(i-1)}' | head -1)
    kill "$pid"; wait "$pid" 2>/dev/null
    echo "steer round=$r mode=$mode req/s=${v:-FAILED}"
  done
done

# 2. SOCKS5 upload through the proxy (2 I/O threads), 8 tunnels.
want socks && for r in $(seq "$RUNS"); do
  for mode in userspace sockmap; do
    echo "socks round=$r $("$E/ebpf-bench" socks "$mode" "$SECS" 8 epoll 2>&1 | tail -1)"
  done
done

# 3. XDP: UDP flood over a veth pair between two network namespaces; the receiver either has
#    no XDP program (datagrams reach a socket that reads them) or the rate limiter (every
#    packet counted, 1/s per source: nearly all dropped) in native and generic mode.
want xdp || exit 0
ip netns del xbench-a 2>/dev/null; ip netns del xbench-b 2>/dev/null
ip netns add xbench-a && ip netns add xbench-b
ip link add va netns xbench-a type veth peer name vb netns xbench-b
ip -n xbench-a addr add 10.77.0.1/24 dev va
ip -n xbench-b addr add 10.77.0.2/24 dev vb
for n in xbench-a xbench-b; do ip -n $n link set lo up; done
ip -n xbench-a link set va up
ip -n xbench-b link set vb up
for r in $(seq "$RUNS"); do
  for mode in none native generic; do
    if [ $mode = none ]; then
      ip netns exec xbench-b taskset -c 2 "$E/ebpf-bench" sink 10.77.0.2:9000 "$((SECS + 1))" >/tmp/xbench-rx &
    else
      ip netns exec xbench-b "$E/ebpf-bench" xdp vb "$SECS" $mode >/tmp/xbench-rx 2>/dev/null &
    fi
    rx=$!
    sleep 0.5
    tx=$(ip netns exec xbench-a taskset -c "$CLI_CPUS" "$E/ebpf-bench" flood 10.77.0.2:9000 "$SECS" 4)
    wait $rx
    echo "xdp round=$r mode=$mode $tx; $(cat /tmp/xbench-rx)"
  done
done
ip netns del xbench-a; ip netns del xbench-b
