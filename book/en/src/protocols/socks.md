# SOCKS and HTTP CONNECT proxies

`flash-socks` provides a SOCKS5 / SOCKS4 / SOCKS4a server (`Socks`) and an HTTP `CONNECT` proxy
(`connect_proxy`). Both relay callback to callback with **backpressure in both directions**:
when one side cannot keep up, reading from the other side pauses until it drains
(`hold_reads` + `on_drain`, see [Backpressure](../concepts/backpressure.md)).

```rust,ignore
{{#include ../../../../crates/flash-socks/examples/guide-socks.rs:server}}
```

- A proxy has to dial upstream connections through the engine it is served on, which does not
  exist when the acceptor is built. `EngineRef` solves that: create it first, pass clones to the
  proxies, `set` it once the engine is built. It holds the engine weakly.
- `Socks::new(engine_ref)` accepts SOCKS5 without authentication, SOCKS4 and SOCKS4a.
  `.auth(|user, pass| ..)` requires SOCKS5 username/password (RFC 1929) and turns SOCKS4 off
  (it has no authentication).
- Targets: IPv4, IPv6 and domain names. Domain names are resolved on the logical pool, never on
  the I/O thread; every resolved address is tried in turn.
- `connect_proxy(engine_ref)` is a flash-http `Service` that tunnels `CONNECT host:port` (other
  methods get 405). Serve it alone or as a router fallback; it takes over the connection with
  `Context::upgrade_raw`.
- Upstream connections run on `client_threads` when the engine has them.

Run `cargo run -p flash-socks --example guide-socks`: it performs a SOCKS5 handshake with
username/password by hand and relays through to a local echo server.

## In-kernel relaying

For pure TCP relays on Linux, `flash::ebpf::Relay` can splice two TCP connections in the kernel
with a sockmap (`SOCKHASH` + `sk_skb` verdict), so payload bytes never reach user space. It needs
privileges and, by default, Linux 6.15+ (6.12 was found to lose data when the destination's send
buffer fills). It is not wired into flash-socks yet.

## Not supported

SOCKS `BIND` and `UDP ASSOCIATE`; a Linux `splice(2)` path.
