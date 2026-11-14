# Kernel bypass (DPDK)

> **Experimental.** `Backend::Dpdk` and the `only::dpdk` module are outside the semver promise
> ([docs/api-stability.md](https://github.com/lesismal/only/blob/main/docs/api-stability.md))
> and may change in any release.

`Backend::Dpdk` runs a listener on a **userspace TCP/IP stack** instead of the kernel's: `only`
I/O threads poll a network device directly, run `only`'s own TCP/IP stack (Ethernet, ARP, IPv4,
ICMP, UDP, TCP; safe Rust with `#![forbid(unsafe_code)]` and no dependencies) and hand data to the
same `Handler`s as every other backend. UDP listeners still get
one datagram per `on_data`, TCP listeners a byte stream; `Conn::send`, backpressure, `dial`,
`dial_udp`, idle timeouts, telemetry and graceful shutdown work as usual, so protocol crates such
as `only-kcp` run unchanged.

The device under the stack is one of:

| `Device` | Needs | Use |
|---|---|---|
| `Dpdk(EalConfig)` | Linux, feature `dpdk-pmd`, libdpdk (found with `pkg-config`) | production: a NIC bound to DPDK (vfio-pci), or a DPDK virtual device (`net_tap`, `net_af_packet`, `net_ring`, ...) |
| `Tap(name)` | Linux, `CAP_NET_ADMIN`, `/dev/net/tun` | development and tests: the kernel is the peer on the other side of the TAP |
| `AfPacket(ifname)` | Linux, `CAP_NET_RAW` | the stack on an existing interface the kernel does not use (a veth end, a spare NIC) |
| `Memory(MemoryPort)` | nothing | two stacks in one process (`MemoryWire::new()`), any platform: tests and examples |

## Enabling it

```toml
[dependencies]
only = { version = "1", features = ["dpdk"] }       # TAP, AF_PACKET, memory wire
# only = { version = "1", features = ["dpdk-pmd"] } # + DPDK ports (links libdpdk)
```

`dpdk-pmd` compiles a small C shim against the installed DPDK (`pkg-config --cflags --libs
libdpdk`, DPDK 21.11 or newer). Without libdpdk the crate still builds and `Device::Dpdk` fails
at `build` with `Unsupported`; set `ONLY_DPDK_REQUIRE=1` to make a missing libdpdk a build error.
On Debian/Ubuntu: `apt-get install dpdk-dev libdpdk-dev pkg-config`.

## A server

```rust,ignore
{{#include ../../../crates/only-dpdk/examples/guide-dpdk.rs:server}}
```

- `DpdkConfig::new(device, address)` gives the stack its IPv4 address; `prefix_len` (default 24)
  and `gateway` route the rest. The listener address must be that address or `0.0.0.0`; port 0
  picks a free port.
- Every listener whose config names the **same device** shares one stack: one IP address, one set
  of I/O threads. Each listener is still its own group, with its own acceptor, config, metrics
  and shutdown. `Listener::threads` does not apply: the device's queue count decides the threads.

A DPDK port instead of the memory wire:

```rust,ignore
{{#include ../../../crates/only-dpdk/examples/guide-dpdk.rs:dpdk}}
```

The EAL is initialised once per process, from the `args` of the first DPDK stack. On a real NIC:
reserve hugepages (`echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages`), bind the
NIC to `vfio-pci` (`dpdk-devbind.py -b vfio-pci 0000:03:00.0`), and pass e.g.
`["-l", "2-3", "-a", "0000:03:00.0"]` with `port = "0"` and `queues = 2`. The example's
`--no-huge --no-shconf --no-pci --vdev=net_tap0,...` runs without hugepages or a NIC.

## A client

```rust,ignore
{{#include ../../../crates/only-dpdk/examples/guide-dpdk.rs:client}}
```

`Engine::dial` runs on the engine's last listener and `dial_udp` on its last UDP listener, so a
client engine has a listener on the device. Dials are spread over the queues; each queue picks
local ports with `port % queues == queue`, and a reply the NIC's RSS puts on another queue is
handed to the dialing one. A dialed UDP connection whose peer answers with ICMP "port
unreachable" is closed with `ConnectionRefused`, as on the kernel backends.

## `DpdkConfig`

| Field | Default | Meaning |
|---|---|---|
| `device` | (required) | the link layer, see above |
| `address` | (required) | the stack's IPv4 address |
| `prefix_len` | 24 | local subnet |
| `gateway` | none | next hop for addresses outside the subnet |
| `mac` | port MAC (DPDK) / derived from `address` | Ethernet address |
| `mtu` | 1500 | IP MTU (TCP MSS = `mtu - 40`); larger UDP datagrams are fragmented, fragments are reassembled |
| `tcp_buffer` | 64 KiB | receive and send buffer per TCP connection (bounds the window; window scaling above 64 KiB) |
| `udp_buffer` | 1 MiB | datagrams queued per UDP port before the I/O thread delivers them |
| `tcp_backlog` | 64 | handshakes in progress per TCP listener and queue |
| `syn_cookies` | true | answer SYNs with stateless SYN cookies once the backlog is full |
| `congestion` | `Congestion::Cubic` | TCP congestion control: CUBIC (RFC 9438) or NewReno |
| `tcp_keepalive` | none | idle time before TCP keepalive probes (9 probes, every `min(keepalive, 75 s)`) |
| `busy_poll` | false | never sleep (DPDK style, one core per queue at 100%); otherwise sleep up to 1 ms when idle |

`EalConfig`: `args` (EAL arguments), `port` (index or device name), `queues` (rx/tx queue pairs =
I/O threads, default 1), `descriptors` (per queue, default 1024), `mbufs` (pool size, default
8191).

## How it works

- **One stack per device, one thread per queue.** Each queue has its own stack instance (ARP
  cache, connection table, timer heap), owned by one I/O thread. An iteration runs posted
  commands, feeds a burst of received frames to the stack (`rte_eth_rx_burst`, read in place from
  the mbufs), acts on the events it reports (accepted and connected connections, readable data,
  freed send space, closes, datagrams), moves what handlers queued into the stack's send buffers,
  lets the stack send (due timers, data, one ACK per burst instead of one per segment; frames are
  built directly in freshly allocated mbufs) and transmits the burst (`rte_eth_tx_burst`).
- **No per-iteration scans.** Work comes from events and from a timer heap with one entry per
  connection (re-armed lazily), so an idle connection costs nothing per iteration.
- **Several queues**: the port is configured for RSS on the IP/UDP/TCP 4-tuple, so one flow stays
  on one queue and thread. ARP frames are copied to every queue, so each stack knows its
  neighbours; dialed connections' frames that land on another queue are handed over.
- **Connections** are `only` connections without a kernel socket: `Conn::send` only queues (from
  any thread) and wakes the owning thread, which moves the bytes into the stack after each
  callback. Handlers run corked, so what one callback sends enters the stack once.
- **Threads** are registered with the EAL (`rte_thread_register`) so mempool caches apply. With
  `busy_poll = false` an idle thread sleeps up to 1 ms (woken early by cross-thread sends on DPDK
  and memory devices).

## The TCP/IP stack

`crates/only-dpdk/src/net/` (replacing smoltcp, DEV-PLAN "no third-party dependencies"):

- **Ethernet II, ARP** (RFC 826): a neighbour cache with a 60 s reachability timeout and unicast
  refresh, and a queue of packets waiting for resolution, so the first SYN or datagram to a new
  neighbour goes out as soon as the reply arrives (the smoltcp version dropped it, costing a 1 s
  SYN retransmission on every first connection).
- **IPv4**: header checksums, fragmentation of large datagrams, reassembly with limits (64
  datagrams, 1 MiB, 30 s), gateway routing.
- **ICMP**: echo replies; port / protocol unreachable for closed ports (rate limited); received
  unreachables end dialed UDP connections and handshakes, "fragmentation needed" lowers the MSS.
- **TCP** (RFC 9293): the full state machine with simultaneous open and close, TIME-WAIT (and
  reuse by a new SYN or dial), RST rules with RFC 5961 challenge ACKs; RTT estimation and RTO
  (RFC 6298, 200 ms floor, exponential backoff); SACK (RFC 2018) with a scoreboard and RFC 6675
  style loss recovery, NewReno fast recovery (RFC 6582) without SACK; CUBIC (RFC 9438) or NewReno;
  window scaling and timestamps with PAWS (RFC 7323); MSS option; delayed ACKs (40 ms, every
  second segment, quick ACKs at connection start); Nagle off; zero-window probing; keepalive; a
  listen backlog with SYN cookies (window scale and SACK carried in the timestamp).
- Checksums are computed in software (no offloads); received checksums are verified except on
  AF_PACKET, where frames from the local kernel carry partial ones.

Why its own stack: one instance per queue with no global state fits `only`'s thread-per-core model
without locks, the whole stack is safe Rust, and it can do what the data path needs (ACK
coalescing per burst, event-driven connections, a timer heap) without patching a dependency.
F-Stack (FreeBSD's stack on DPDK) and Seastar's stack are faster and more complete, but bring a
C/C++ runtime with its own threading model and a large amount of `unsafe` FFI on the data path.

## Limits (as of this release)

- IPv4 only (no IPv6 / neighbour discovery), no checksum, TSO or LRO offloads (checksums are
  computed in software), no pacing, no ECN, no TCP Fast Open, no path-MTU probing beyond ICMP
  "fragmentation needed".
- Idle timeouts are checked by a scan every 50 ms (not per iteration).
- `Config::write_timeout` and `Accel` do not apply; `send_file` is read through memory.
- No benchmark yet against epoll/io_uring on real NICs; the memory-wire A/B against the former
  smoltcp-based stack is in docs/BENCHMARKS.md.

## Testing

Unit tests cover each layer with crafted frames (checksums, options, ARP queueing, reassembly
limits, RTO, NewReno and CUBIC), and `src/net/sim.rs` runs two stacks over a simulated link in
virtual time (delay, a bandwidth-limited drop-tail queue, random loss, reordering): bulk transfer,
window scaling on a long fat pipe, SACK repairing a burst loss within one round trip, NewReno
without SACK, 10% loss both ways, RTO, zero window, keepalive, closes, SYN cookies, 2000
connections, 300 connections echoing through cookies and loss. `tests/memory.rs` runs everywhere:
UDP and TCP echo between two stacks, bulk TCP with flow control, orderly close, KCP over the
stack. `tools/dpdk/test.sh` builds the Docker image in `tools/dpdk/` (Debian's DPDK 24.11) and
runs `tests/kernel_peer.rs` with `--cap-add NET_ADMIN --device /dev/net/tun` against the Linux
kernel's own sockets: UDP (fragmented datagrams included) and TCP echo over DPDK's `net_tap` PMD
(one and two queues), a TAP device and AF_PACKET on a veth pair, dials from the stack to the
kernel (TCP on every queue, UDP, ICMP port unreachable), ping, `tc netem` loss / delay /
reordering (the kernel's SACK counters must move), a 4 MiB window over a 20 ms RTT, and 500
concurrent connections. The fuzz targets `dpdk_ethernet`, `dpdk_arp`, `dpdk_ipv4`, `dpdk_tcp`,
`dpdk_udp`, `dpdk_icmp` and `dpdk_stack` (a whole stack fed frames) live in `fuzz/`; their
corpora replay in `cargo test`. CI runs `tools/dpdk/test.sh` as the heavy `dpdk` job.
