# Kernel bypass (DPDK)

> **Experimental.** `Backend::Dpdk` and the `flash::dpdk` module are outside the semver promise
> ([docs/api-stability.md](https://github.com/lesismal/flash/blob/main/docs/api-stability.md))
> and may change in any release.

`Backend::Dpdk` runs a listener on a **userspace TCP/IP stack** instead of the kernel's: flash
I/O threads poll a network device directly, run [smoltcp](https://docs.rs/smoltcp) for ARP, IPv4,
UDP and TCP, and hand data to the same `Handler`s as every other backend. UDP listeners still get
one datagram per `on_data`, TCP listeners a byte stream; `Conn::send`, backpressure, `dial`,
`dial_udp`, idle timeouts, telemetry and graceful shutdown work as usual, so protocol crates such
as `flash-kcp` run unchanged.

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
flash = { version = "1", features = ["dpdk"] }       # TAP, AF_PACKET, memory wire
# flash = { version = "1", features = ["dpdk-pmd"] } # + DPDK ports (links libdpdk)
```

`dpdk-pmd` compiles a small C shim against the installed DPDK (`pkg-config --cflags --libs
libdpdk`, DPDK 21.11 or newer). Without libdpdk the crate still builds and `Device::Dpdk` fails
at `build` with `Unsupported`; set `FLASH_DPDK_REQUIRE=1` to make a missing libdpdk a build error.
On Debian/Ubuntu: `apt-get install dpdk-dev libdpdk-dev pkg-config`.

## A server

```rust,ignore
{{#include ../../../crates/flash-dpdk/examples/guide-dpdk.rs:server}}
```

- `DpdkConfig::new(device, address)` gives the stack its IPv4 address; `prefix_len` (default 24)
  and `gateway` route the rest. The listener address must be that address or `0.0.0.0`; port 0
  picks a free port.
- Every listener whose config names the **same device** shares one stack: one IP address, one set
  of I/O threads. Each listener is still its own group, with its own acceptor, config, metrics
  and shutdown. `Listener::threads` does not apply: the device's queue count decides the threads.

A DPDK port instead of the memory wire:

```rust,ignore
{{#include ../../../crates/flash-dpdk/examples/guide-dpdk.rs:dpdk}}
```

The EAL is initialised once per process, from the `args` of the first DPDK stack. On a real NIC:
reserve hugepages (`echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages`), bind the
NIC to `vfio-pci` (`dpdk-devbind.py -b vfio-pci 0000:03:00.0`), and pass e.g.
`["-l", "2-3", "-a", "0000:03:00.0"]` with `port = "0"` and `queues = 2`. The example's
`--no-huge --no-shconf --no-pci --vdev=net_tap0,...` runs without hugepages or a NIC.

## A client

```rust,ignore
{{#include ../../../crates/flash-dpdk/examples/guide-dpdk.rs:client}}
```

`Engine::dial` runs on the engine's last listener and `dial_udp` on its last UDP listener, so a
client engine has a listener on the device. Dialing is single-queue only: with several queues the
NIC's RSS, not the dialing thread, decides where the replies land.

## `DpdkConfig`

| Field | Default | Meaning |
|---|---|---|
| `device` | (required) | the link layer, see above |
| `address` | (required) | the stack's IPv4 address |
| `prefix_len` | 24 | local subnet |
| `gateway` | none | next hop for addresses outside the subnet |
| `mac` | port MAC (DPDK) / derived from `address` | Ethernet address |
| `mtu` | 1500 | IP MTU; also the largest UDP datagram is `mtu - 28` (no IP fragmentation) |
| `tcp_buffer` | 64 KiB | receive and send buffer per TCP connection (bounds the window) |
| `udp_buffer` | 1 MiB | receive and send buffer per UDP socket |
| `tcp_backlog` | 64 | handshakes in progress per TCP listener and queue |
| `busy_poll` | false | never sleep (DPDK style, one core per queue at 100%); otherwise sleep up to 1 ms when idle |

`EalConfig`: `args` (EAL arguments), `port` (index or device name), `queues` (rx/tx queue pairs =
I/O threads, default 1), `descriptors` (per queue, default 1024), `mbufs` (pool size, default
8191).

## How it works

- **One stack per device, one thread per queue.** Each queue has its own smoltcp `Interface` and
  socket set, owned by one I/O thread. An iteration runs posted commands, polls the device (an
  `rte_eth_rx_burst` of up to 32 frames, read in place from the mbufs), lets smoltcp process them,
  hands new data to handlers, moves what they queued into smoltcp's socket buffers, polls again
  for egress (frames are built directly in freshly allocated mbufs) and transmits the burst
  (`rte_eth_tx_burst`).
- **Several queues**: the port is configured for RSS on the IP/UDP/TCP 4-tuple, so one flow stays
  on one queue and thread. ARP frames are copied to every queue, so each stack knows its
  neighbours.
- **Connections** are flash connections without a kernel socket: `Conn::send` only queues (from
  any thread) and wakes the owning thread, which moves the bytes into the stack after each
  callback. Handlers run corked, so what one callback sends enters the stack once.
- **Threads** are registered with the EAL (`rte_thread_register`) so mempool caches apply. With
  `busy_poll = false` an idle thread sleeps up to 1 ms (woken early by cross-thread sends on DPDK
  and memory devices).

Why smoltcp: it is a maintained, memory-safe Rust stack with no global state, so one instance per
queue fits flash's thread-per-core model without locks. F-Stack (FreeBSD's stack on DPDK) and
Seastar's stack are faster and more complete, but bring a C/C++ runtime with its own threading
model and would put a large amount of `unsafe` FFI on the data path.

## Limits (as of this release)

- IPv4 only (no IPv6 / neighbour discovery), no IP fragmentation, no checksum or TSO offloads
  (checksums are computed in software).
- smoltcp's TCP has no SACK and, by default, no congestion control; fine on a LAN, not tuned for
  lossy long-distance paths. TCP connections are re-examined on every iteration that saw traffic,
  which is linear in the number of connections on the thread.
- `Config::write_timeout` and `Accel` do not apply; `send_file` is read through memory; ICMP
  errors are not reported to dialed UDP connections.
- No benchmark yet against epoll/io_uring on real NICs.

## Testing

`crates/flash-dpdk/tests/memory.rs` runs everywhere: UDP and TCP echo between two stacks, bulk TCP
with flow control, orderly close, KCP over the stack. `tools/dpdk/test.sh` builds the Docker image
in `tools/dpdk/` (Debian's DPDK 24.11) and runs `tests/kernel_peer.rs` with `--cap-add NET_ADMIN
--device /dev/net/tun`: the Linux kernel's own sockets exchange UDP datagrams and 2 MiB of TCP
with flash over DPDK's `net_tap` PMD (one and two queues), over smoltcp's TAP device and over
an AF_PACKET socket on a veth pair. CI runs
the same as the heavy `dpdk` job.
