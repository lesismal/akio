# flash-dpdk

[中文](README.zh-CN.md)

The kernel-bypass backend of [flash](https://github.com/lesismal/flash) (**experimental**): a
userspace TCP/IP stack ([smoltcp](https://docs.rs/smoltcp), IPv4) driven by flash I/O threads,
over

- a **DPDK** port (feature `pmd`, Linux, links libdpdk via `pkg-config`): EAL initialised from
  `EalConfig`, one rx/tx queue pair and one I/O thread per queue, mbuf rx/tx bursts, RSS;
- a Linux **TAP** interface or an **AF_PACKET** socket (same stack, no DPDK);
- an in-process **memory wire** (any platform; tests and examples).

Use it through `flash` with the `dpdk` feature (`dpdk-pmd` for DPDK ports):

```rust,ignore
use flash::{Backend, Listener, dpdk::{Device, DpdkConfig}};

let cfg = DpdkConfig::new(Device::Tap("ftap0".into()), "10.0.0.2".parse()?);
let listener = Listener::udp("10.0.0.2:7000".parse()?).backend(Backend::Dpdk(cfg)).serve(acceptor);
```

UDP listeners deliver one datagram per `on_data`, TCP listeners a byte stream; `dial`,
`dial_udp`, backpressure, idle timeouts, telemetry and graceful shutdown work as on the kernel
backends, so protocol crates (flash-kcp, ...) run unchanged.

- Guide: [Kernel bypass (DPDK)](https://lesismal.github.io/flash/en/dpdk.html)
- Example: `cargo run -p flash-dpdk --example guide-dpdk`
- Tests: `cargo test -p flash-dpdk` (memory wire, any platform); `tools/dpdk/test.sh` (Docker:
  DPDK `net_tap` and TAP against the Linux kernel stack)

`unsafe` is confined to `src/pmd.rs` (the DPDK FFI through `csrc/shim.c`); see
[docs/unsafe-review.md](../../docs/unsafe-review.md). Experimental: outside the semver promise
([docs/api-stability.md](../../docs/api-stability.md)).

License: MIT.
