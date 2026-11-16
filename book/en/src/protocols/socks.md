# SOCKS and HTTP CONNECT proxies

`only-socks` provides a SOCKS5 / SOCKS4 / SOCKS4a server (`Socks`) and an HTTP `CONNECT` proxy
(`connect_proxy`). Both relay callback to callback with **backpressure in both directions**:
when one side cannot keep up, reading from the other side pauses until it drains
(`hold_reads` + `on_drain`, see [Backpressure](../concepts/backpressure.md)).

```rust,ignore
{{#include ../../../../crates/only-socks/examples/guide-socks.rs:server}}
```

- A proxy has to dial upstream connections through the engine it is served on, which does not
  exist when the acceptor is built. `EngineRef` solves that: create it first, pass clones to the
  proxies, `set` it once the engine is built. It holds the engine weakly.
- `Socks::new(engine_ref)` accepts SOCKS5 without authentication, SOCKS4 and SOCKS4a.
  `.auth(|user, pass| ..)` requires SOCKS5 username/password (RFC 1929) and turns SOCKS4 off
  (it has no authentication).
- Targets: IPv4, IPv6 and domain names. Domain names are resolved on the logical pool, never on
  the I/O thread; every resolved address is tried in turn.
- `connect_proxy(engine_ref)` is a only-http `Service` that tunnels `CONNECT host:port` (other
  methods get 405). Serve it alone or as a router fallback; it takes over the connection with
  `Context::upgrade_raw`.
- Upstream connections run on `client_threads` when the engine has them.

Run `cargo run -p only-socks --example guide-socks`: it performs a SOCKS5 handshake with
username/password by hand and relays through to a local echo server.

## Limits and destination policy

`ProxyConfig` (`Socks::config`, `connect_proxy_with`) bounds every session. A configuration
that sets nothing is still bounded:

| Field | Default | Meaning |
| --- | --- | --- |
| `handshake_timeout` | 10 s | From accepting the client until its upstream is connected (greeting, authentication, request, name resolution, connect). Past it the client is closed, so a client that never finishes (or trickles) its request cannot hold a session. |
| `idle_timeout` | 5 min | A tunnel that moved no byte in either direction for this long is closed, both ends. |
| `destinations` | `Destinations::PublicOnly` | Which addresses may be dialled, checked after name resolution. |

- `Destinations::PublicOnly` denies loopback, private (RFC 1918, IPv6 ULA), carrier-grade NAT,
  link-local (including the `169.254.169.254` cloud metadata service), multicast, broadcast and
  reserved targets, and their IPv4-mapped, 6to4 and NAT64 forms. A proxy that others can reach
  would otherwise be a way into the networks behind it (server-side request forgery, an open
  relay into `localhost`). SOCKS5 answers `2` (not allowed by ruleset), SOCKS4 `0x5b`,
  `CONNECT` 403. A host name that resolves to a denied address is denied too.
- `Destinations::Any` restores the old behaviour, for a proxy whose purpose is to reach a
  private network (a bastion); restrict who can use it (`auth`, a listener on a trusted
  interface). `Destinations::Custom(f)` takes your own rule.
- Data a client sends before its upstream is connected is held up to 256 KiB (the relay's
  pause threshold); more closes the client.
- `CONNECT` targets are resolved on a small bounded resolver pool (4 threads, 1024 queued
  requests; 503 when full), never on the I/O thread.
- Stalled readers are also bounded by the engine's `Config::write_timeout`.

## In-kernel relaying

For pure TCP relays on Linux, `only::ebpf::Relay` can splice two TCP connections in the kernel
with a sockmap (`SOCKHASH` + `sk_skb` verdict), so payload bytes never reach user space. It needs
privileges and, by default, Linux 6.15+ (6.12 was found to lose data when the destination's send
buffer fills). It is not wired into only-socks yet.

## Not supported

SOCKS `BIND` and `UDP ASSOCIATE`; a Linux `splice(2)` path.
