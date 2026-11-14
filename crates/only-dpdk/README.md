# only-dpdk

[中文](README.zh-CN.md)

The kernel-bypass backend of [`only`](https://github.com/lesismal/only) (**experimental**): a
userspace TCP/IP stack of its own (Ethernet, ARP, IPv4 with fragmentation, ICMP, UDP, and TCP
with SACK, fast recovery, CUBIC / NewReno, window scaling, timestamps, SYN cookies; safe Rust,
`#![forbid(unsafe_code)]`, no dependencies) driven by `only` I/O threads, over

- a **DPDK** port (feature `pmd`, Linux, links libdpdk via `pkg-config`): EAL initialised from
  `EalConfig`, one rx/tx queue pair and one I/O thread per queue, mbuf rx/tx bursts, RSS;
- a Linux **TAP** interface or an **AF_PACKET** socket (same stack, no DPDK);
- an in-process **memory wire** (any platform; tests and examples).

Use it through `only` with the `dpdk` feature (`dpdk-pmd` for DPDK ports):

```rust,ignore
use only::{Backend, Listener, dpdk::{Device, DpdkConfig}};

let cfg = DpdkConfig::new(Device::Tap("ftap0".into()), "10.0.0.2".parse()?);
let listener = Listener::udp("10.0.0.2:7000".parse()?).backend(Backend::Dpdk(cfg)).serve(acceptor);
```

UDP listeners deliver one datagram per `on_data`, TCP listeners a byte stream; `dial`,
`dial_udp`, backpressure, idle timeouts, telemetry and graceful shutdown work as on the kernel
backends, so protocol crates (only-kcp, ...) run unchanged.

- Guide: [Kernel bypass (DPDK)](https://lesismal.github.io/only/en/dpdk.html)
- Example: `cargo run -p only-dpdk --example guide-dpdk`
- Benchmark: `cargo run --release -p only-dpdk --example stack-bench`
- Tests: `cargo test -p only-dpdk` (per-layer unit tests, a simulated lossy / reordering link,
  the memory wire; any platform); `tools/dpdk/test.sh` (Docker: DPDK `net_tap`, TAP and
  AF_PACKET against the Linux kernel stack, with `tc netem` loss); fuzz targets `dpdk_*` in
  `fuzz/`

`unsafe` is confined to `src/pmd.rs` (the DPDK FFI through `csrc/shim.c`) and `src/sys.rs`
(TAP / AF_PACKET); the stack (`src/net/`) forbids it. See
[docs/unsafe-review.md](../../docs/unsafe-review.md). Experimental: outside the semver promise
([docs/api-stability.md](../../docs/api-stability.md)).

License: MIT.
