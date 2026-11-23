# ADR-096: TUN devices on I/O threads, in a crate of their own

English | [简体中文](096-tun-devices.zh-CN.md)

Status: accepted (2026-11-23)

## Context

fit's VPN track ([fit decision 026](https://github.com/lesismal/fit/blob/main/docs/decisions/026-vpn.md),
fib request A51) and akit, its Rust counterpart (akit request A8), run a TUN interface on each
node: every IP packet of the overlay is read from the device and written to it. A TUN device is
a descriptor that is neither a socket the engine accepted nor one it dialed: `/dev/net/tun` on
Linux (a character device), a `PF_SYSTEM` kernel-control socket on macOS (`utun`). Each read
returns one packet and each write takes one, and both can be non-blocking, so the device fits
on a readiness poller. Without engine support an application reads it on a thread of its own,
blocking in `read`, against rule 1, and hands every packet across threads. fib has no TUN
package yet; fit's design names the system calls (`IFF_TUN | IFF_NO_PI`, utun with its 4-byte
family header) and wants the descriptor on the poller.

## Decision

1. **The system calls live in `akio-sys` (`tun` module)**, the only crate where raw syscalls
   may be: `tun_open(name, multi_queue)` (`open("/dev/net/tun")`, `TUNSETIFF` with
   `IFF_TUN | IFF_NO_PI`, plus `IFF_MULTI_QUEUE` for one descriptor per queue; non-blocking,
   close-on-exec), `tun_is_multi_queue` (`TUNGETIFF`), `utun_open(unit)` / `utun_name` (macOS:
   `CTLIOCGINFO` for `com.apple.net.utun_control`, `connect` with a `sockaddr_ctl`,
   `UTUN_OPT_IFNAME`), `read_packet` / `write_packet` (one packet per call; on macOS the family
   header is skipped on reads and prepended with a two-iovec `writev`, so the packet is never
   copied), `tun_gone` (the error means the device is gone), and the interface settings a TUN
   needs, as ioctls on a datagram socket: `if_mtu` / `if_set_mtu`, `if_is_up` / `if_set_up`,
   `if_index`, `if_add_addr` / `if_del_addr` (Linux: one IPv4 address with `SIOCSIFADDR` and
   `SIOCSIFNETMASK`, IPv6 addresses through `struct in6_ifreq`; macOS: `SIOCAIFADDR` /
   `SIOCAIFADDR_IN6`, point-to-point with the address as its own destination). No netlink:
   ioctls cover the name, MTU, addresses and flags; routes beyond the connected prefix are the
   application's (fit sets them with rtnetlink and a routing socket), and can be added later.
   Every structure handed to the kernel is a byte array of the C layout's size and alignment,
   asserted at compile time and filled in safe code; the `unsafe` is only the calls
   (docs/unsafe-review.md).
2. **A new crate, `akio-tun`** (`#![forbid(unsafe_code)]`, on `akio-core` and `akio-sys`), not
   part of `akio-core` or `akio`: TUN is platform-specific, needs privileges, and only VPN-like
   applications want it; `akio-core` stays a library of connections and traits with no device
   code, and the backends stay untouched. `akio` exposes it behind the cargo feature `tun`:
   `akio::tun` and `Engine::serve_tun`. This follows `akio-dpdk`, which also runs its own loops
   over `ConnInner::new_virtual` connections.
3. **One queue, one I/O thread, one connection.** `TunDevice::create(&TunConfig)` opens the
   interface with all its queues and applies MTU, addresses and the up flag (control-plane
   system calls, for a control thread or the pool). `TunServer::start(device, acceptor, cfg)`, or
   `Engine::serve_tun(device, acceptor)` with the engine's pool, telemetry and live settings,
   gives each queue a thread with its own epoll / kqueue poller and one
   `ConnInner::new_virtual(datagram)` connection served by the acceptor's ordinary `Handler`:
   - **reads**: on readiness up to 64 packets are read into the thread's 64 KiB buffer and each
     is handed to `on_data` as a borrowed `&[u8]`; then what the callbacks queued is written;
   - **writes**: `Conn::send` (or `TunWriter`, a cloneable `Send + Sync` handle on all queues
     that picks the queue by a hash of the packet's addresses, keeping a flow in order) only
     queues and wakes the thread when the queue was empty; the thread writes one packet per
     `write` until the queue is empty or the device answers `EAGAIN` (write interest until it
     drains). The queue is bounded by `Config::max_queued_bytes` (past it `send` fails with
     `Overloaded`: the packet is the caller's to drop, as IP allows), `on_drain` fires when it
     empties, and `hold_reads` pauses the device's reads (rules 7 and 8);
   - **own backpressure**: reads pause while the queue of packets to write is at
     `write_high_watermark` and resume at a quarter of it, unless the connection is relayed;
   - **errors**: a read error, or a write error that `tun_gone` recognises (`EBADFD` once the
     interface was deleted underneath), closes the connection with that error; any other write
     error drops the packet (a network drops what it cannot carry). While reads are off (held,
     backpressured) the poller cannot report a deleted device: its wake-up carries `EPOLLIN`,
     which epoll filters out of an empty interest set. The loop then wakes once a second and
     probes with a zero-length write, which fails with `EBADFD` on a deleted device and `EINVAL`
     on a live one, taking no packet;
   - **shutdown**: `on_shutdown`, reads stop, the queue is written up to `shutdown_timeout`, then
     `on_close(None)` and the descriptor closes; the last queue's close destroys the interface.
   The connection has no addresses (`0.0.0.0:0`), appears in the connection table and metrics as
   backend `tun`, and its slow callbacks are reported like any other.
4. **The readiness loop on every backend.** An engine on io_uring still serves TUN devices with
   epoll (kqueue on macOS), as it serves UDP listeners (architecture §4.4). A TUN is not a
   socket, so io_uring's multishot receive does not apply; a read per packet costs one system
   call either way until `IORING_OP_READ_MULTISHOT` (Linux 6.7) with provided buffers, which would
   need a new kind of slot in the io_uring loops. Revisit with a benchmark if TUN throughput
   becomes the bottleneck.
5. **Batching, where the kernel allows it.** A TUN takes and gives one packet per system call
   (`readv` only scatters one packet; there is no `recvmmsg` for a character device). What is
   batched: up to 64 reads per wake-up with their replies written after them; sends from other
   threads that arrive while a wake-up is pending are written in one pass; and with
   `TunConfig::queues(n)` (`IFF_MULTI_QUEUE`) the kernel spreads flows over n queues served in
   parallel. **`IFF_VNET_HDR` was evaluated and is not adopted yet**: with `TUNSETOFFLOAD`
   (TSO / USO) the kernel hands over 64 KiB GSO super-packets behind a `virtio_net_hdr` and takes
   them back the same way, which is where wireguard-go and Tailscale find most of their TUN
   throughput. It changes what a handler sees (one super-packet that it must segment, partial
   checksums), so it would be an opt-in (`TunConfig::offload`) delivering either segments or the
   header; it is a follow-up, measured when it is built.
6. **macOS**: one queue (`queues(n > 1)` is `Unsupported`), names `utunN` only, root only.
   Routes for the prefix are the application's (`route add -net ... -interface utunN`).
7. **Privileges.** Creating a device needs `CAP_NET_ADMIN` on Linux (opening an existing
   persistent device made with `TUNSETOWNER` does not, but the settings do) and root on macOS;
   without them `create` fails with the system's error (`PermissionDenied`, or `NotFound` when
   `/dev/net/tun` is absent). The tests detect that once, print why they skip, and pass;
   `AKIO_TEST_EXPECT_TUN=1` makes a skip a failure for the runs meant to be privileged: Linux
   Docker with `--privileged` (or `--cap-add NET_ADMIN --device /dev/net/tun`) and the IPv6
   sysctls, and the x86_64 benchmark host natively as root.
8. **Lifecycle.** The `TunServer` owns its threads; dropping it shuts them down and joins them.
   `Engine::shutdown` does not reach them, because the engine's groups are fixed when it is built;
   once groups can be added at run time (ADR-094's runtime listeners), `serve_tun` can register
   the server there too.

## Consequences

- A VPN node reads and writes its TUN on akio threads, with the same `Handler`, `Conn`,
  backpressure, telemetry and pool as its sockets; a relay between the device and a UDP or QUIC
  connection is `Conn::send` across threads plus `hold_reads` / `on_drain`.
- Nothing in `akio-core`, the backends or `akio`'s listener code changed; `akio` gains a module
  line, a re-export and `Engine::serve_tun` in its own file.
- A packet written from another thread takes a wake-up hop (queue, wake, written by the loop)
  rather than a direct `write` from the sender, as for any virtual connection. A `Sock` variant
  for packet descriptors in `akio-core`, writing directly from `send` like UDP does, would remove
  it at the cost of changing the core write path (model-checked with loom); not done until a
  benchmark shows the hop matters.
- The loop is not TUN-specific: any non-blocking descriptor with packet semantics could be
  served the same way (fib's `AttachPacketFD`), by a constructor from raw descriptors, if needed.

## Alternatives

- **TUN queues on the engine's UDP loops** (`akio-epoll`'s `UdpGroup`): those loops key peers by
  address with idle eviction and caps; a device is one long-lived connection per queue, and the
  change would have reached into a backend other work is changing. A thread per queue also
  matches multi-queue, which wants one queue per thread.
- **In `akio-core` / `akio`**: rejected for the reasons in 2.
- **netlink for addresses and routes**: more code (message building, ack parsing) for nothing
  the ioctls do not already do; routes can come later.
- **A blocking reader thread per device** (what wireguard-go does): against rule 1 and a thread
  switch per packet.

## Verification

- `akio-sys` unit tests (masks, names, `ifreq` fields, errors on a missing interface).
- `crates/akio-tun/tests/device.rs`: invalid configurations (no privileges needed);
  create / configure / destroy (MTU, IPv4 and IPv6 addresses listed by `getifaddrs`, MTU change,
  address removal and addition, down / up, the interface gone after the last queue closes); UDP
  through the device over IPv4 and IPv6 on an engine (`Engine::serve_tun`, the queue in the
  engine's connection table); ping through the device (`ping -4` and `ping -6`, the handler
  writing the ICMP and ICMPv6 echo replies); 1000 packets from four threads through `TunWriter`,
  all delivered; the queue limit (4 x 1000 bytes accepted under 4096, the fifth `Overloaded`,
  `on_drain` once the loop drains it, sends accepted again); `hold_reads` pausing and resuming
  the device's reads; the device deleted underneath (`ip link del`: `on_close` with an error,
  `send` then `Closed`); a four-queue device spreading 64 flows over at least two queues, each
  queue echoing on its own.
- Linux arm64 Docker (privileged, `AKIO_TEST_EXPECT_TUN=1`): the nine pass three runs in a row;
  unprivileged, all nine pass with the skip message. x86_64 on the benchmark host (root, kernel
  7.0): the nine pass three runs in a row with `AKIO_TEST_BACKEND` epoll and uring; that kernel
  is where the held-reads deletion case first failed, before the probe of decision 3 was added.
  macOS: the unprivileged tests pass; the utun path is compile-checked only (no root in the
  development session). Workspace suites: macOS, Linux arm64 Docker on epoll and io_uring, and
  x86_64 natively on epoll and io_uring; the only failures were in code this change does not
  touch and passed when rerun alone or on the base commit failed the same way (see the commit).
- `examples/tun-bench.rs` measures echoes per second through the device (queues, flows, payload
  size); no numbers are recorded here yet (the benchmark host was busy).
