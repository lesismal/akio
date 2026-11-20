#!/usr/bin/env bash
# Kernel TLS evaluation (docs/BENCHMARKS.md, "Kernel TLS (kTLS) evaluation"): HTTP/1.1 over TLS
# with only-tls's own record layer (`user`) against the kernel's (`ktls`, `sendfile` for the
# file case), same server, same handshake, interleaved rounds. Needs Linux with the `tls` module
# (6.14+ for TLS 1.3), h2load, root for VETH=1.
#
#   cargo build --release -p only-tls --example ktls-bench --features ktls
#   tools/bench/ktls.sh                  # loopback
#   VETH=1 tools/bench/ktls.sh           # client in a network namespace behind a veth pair, MTU 1500
#
# Prints TSV: case mode round req/s throughput server-cpu-s cpu-ns-per-byte user-s sys-s requests.
# Knobs: SRV_CPUS (0-3), CLI_CPUS (4-7,12-15), SECS (8), RUNS (3), PORT (7900), FILE (a 10 MB
# random file is made if missing), CASES (name:path:connections:extra-args, `_` for spaces).
set -u
B=${CARGO_TARGET_DIR:-target}/release/examples/ktls-bench
FILE=${FILE:-/tmp/only-ktls-file.bin}
SECS=${SECS:-8}
RUNS=${RUNS:-3}
SRV=${SRV_CPUS:-0-3}
CLI=${CLI_CPUS:-4-7,12-15}
PORT=${PORT:-7900}
HZ=$(getconf CLK_TCK)
ADDR=127.0.0.1
NS=()
cases=${CASES:-"1k:1024:64: 16k:16384:64: 256k:262144:32: file:file:16: chacha16k:16384:64:--suite_0x1303 tls12_16k:16384:64:--tls12"}
[ -f "$FILE" ] || head -c 10000000 /dev/urandom > "$FILE"
if [ -n "${VETH:-}" ]; then
  ns=onlyktls
  ip netns del $ns 2>/dev/null
  ip netns add $ns
  ip link add vokt0 type veth peer name vokt1
  ip link set vokt1 netns $ns
  ip addr add 10.77.0.1/24 dev vokt0
  ip link set vokt0 mtu 1500 up
  ip netns exec $ns ip addr add 10.77.0.2/24 dev vokt1
  ip netns exec $ns ip link set vokt1 mtu 1500 up
  ip netns exec $ns ip link set lo up
  trap 'ip netns del '$ns' 2>/dev/null; ip link del vokt0 2>/dev/null' EXIT
  ADDR=10.77.0.1
  NS=(ip netns exec $ns)
fi
for r in $(seq 1 "$RUNS"); do
  for c in $cases; do
    IFS=: read -r name path conns extra <<<"$c"
    extra=${extra//_/ }
    for mode in user ktls; do
      PORT=$((PORT + 1))
      # shellcheck disable=SC2086
      taskset -c "$SRV" "$B" "$ADDR:$PORT" $mode --file "$FILE" $extra 2>/dev/null &
      pid=$!
      sleep 0.4
      ${NS[@]+"${NS[@]}"} taskset -c "$CLI" h2load --h1 -c "$conns" -t 8 -D 2 "https://$ADDR:$PORT/$path" >/dev/null 2>&1
      read -r u0 s0 < <(awk '{print $14, $15}' /proc/$pid/stat)
      out=$(${NS[@]+"${NS[@]}"} taskset -c "$CLI" h2load --h1 -c "$conns" -t 8 -D "$SECS" "https://$ADDR:$PORT/$path" 2>&1)
      read -r u1 s1 < <(awk '{print $14, $15}' /proc/$pid/stat)
      kill $pid
      wait $pid 2>/dev/null
      rps=$(sed -n 's/^finished in .*, \([0-9.]*\) req\/s, .*/\1/p' <<<"$out")
      bw=$(sed -n 's/^finished in .*, [0-9.]* req\/s, \([0-9.]*[KMG]B\/s\).*/\1/p' <<<"$out")
      bytes=$(sed -n 's/^traffic: .*(\([0-9]*\)) total.*/\1/p' <<<"$out")
      ok=$(sed -n 's/^requests: .* \([0-9]*\) succeeded.*/\1/p' <<<"$out")
      cpu=$(awk -v a=$((u1 - u0 + s1 - s0)) -v hz="$HZ" 'BEGIN{printf "%.2f", a/hz}')
      usr=$(awk -v a=$((u1 - u0)) -v hz="$HZ" 'BEGIN{printf "%.2f", a/hz}')
      sys=$(awk -v a=$((s1 - s0)) -v hz="$HZ" 'BEGIN{printf "%.2f", a/hz}')
      nspb=$(awk -v c="$cpu" -v b="${bytes:-1}" 'BEGIN{printf "%.3f", c*1e9/b}')
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$mode" "$r" "$rps" "$bw" "$cpu" "$nspb" "$usr" "$sys" "$ok"
    done
  done
done
