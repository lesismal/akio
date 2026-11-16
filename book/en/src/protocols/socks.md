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
- `Socks::new(engine_ref)` accepts SOCKS5 `CONNECT` without authentication, SOCKS4 and SOCKS4a
  (`BIND` and `UDP ASSOCIATE` are opt-in, below).
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

## BIND and UDP ASSOCIATE

Both SOCKS5 commands are off by default (they open ports on the proxy host on a client's
request); turn them on per server:

```rust,ignore
let socks = Socks::new(er.clone())
    .bind(true)                                   // SOCKS5 BIND
    .bind_timeout(Duration::from_secs(30))        // default 60 s
    .udp_associate(true)                          // SOCKS5 UDP ASSOCIATE
    .udp_idle_timeout(Duration::from_secs(60));   // default 120 s
let engine = Engine::builder()
    .listen(Listener::tcp(addr).serve(socks))
    .udp_client_threads(1)                        // UDP ASSOCIATE's relay sockets
    .build()?;
```

- **BIND** (active FTP and other "the far side connects back" protocols): the server listens on
  a new port of the address the client reached it on, replies with it, accepts one connection
  (only from the requested IP, unless the request's address is unspecified), replies again with
  the peer's address, then relays like `CONNECT`. Nobody within `bind_timeout`: reply 1, closed.
  The accepted stream joins the engine through `Engine::adopt_tcp`, which serves any TCP stream
  accepted outside the engine like a dialed connection.
- **UDP ASSOCIATE**: each association gets its own UDP socket (`Engine::bind_udp`) on the
  address the client reached the proxy on, so the engine needs UDP I/O threads
  (`udp_client_threads` or a UDP listener; without them the reply is 1). Datagrams count as the
  client's only from the control connection's IP, and from one port once the request or the
  first datagram fixed it. Datagrams with a non-zero fragment number are dropped (RFC 1928 allows
  that when fragmentation is not implemented). Answers are relayed only from addresses the client
  has sent to, so an association is not an open inbound port. Host names are resolved on the
  logical pool and cached per association. The association ends when its control connection
  closes, or after `udp_idle_timeout` without a datagram either way (the server then closes the
  control connection). If `Config::idle_timeout` is set it also applies to the control
  connection, which is silent while UDP flows: raise it when you use both.

## Access control

`Socks::allow` decides each request after authentication and before anything is dialed, bound or
resolved:

```rust,ignore
use only_socks::{Command, Dest};
let socks = Socks::new(er.clone())
    .auth(|u, p| check_password(u, p))
    .udp_associate(true)
    .allow(|r| match (r.command(), r.dest()) {
        // UDP ASSOCIATE's destination is the client's own address: let it through.
        (Command::UdpAssociate, _) => true,
        (_, Dest::Addr(a)) => !a.ip().is_loopback() && !is_private(a.ip()),
        (_, Dest::Name(host, _)) => r.user() == Some("admin") || !host.ends_with(".internal"),
    });
```

`Request` gives `version()` (5 or 4), `client()`, `user()` (the RFC 1929 name, or the SOCKS4
user id), `command()` (`Connect`, `Bind`, `UdpAssociate`, `UdpDatagram`) and `dest()` (an address,
or a host name not resolved yet: resolve it in the hook to check addresses). The hook runs for
SOCKS5 and SOCKS4/4a `CONNECT`, `BIND`, `UDP ASSOCIATE`, and once per distinct destination of an
association's datagrams (`UdpDatagram`, cached). A refusal answers reply 2 ("connection not
allowed by ruleset"), 0x5b for SOCKS4, or drops the datagram.

`tools/interop/socks/run.sh` checks all of this against curl (`--socks5`, `--socks5-hostname`,
`--socks4`, `--socks4a`, with and without a password), PySocks's UDP ASSOCIATE and a hand-written
client for BIND and the UDP edge cases, running the same clients against Dante as a reference.

## In-kernel relaying

For pure TCP relays on Linux, `only::ebpf::Relay` can splice two TCP connections in the kernel
with a sockmap (`SOCKHASH` + `sk_skb` verdict), so payload bytes never reach user space. It needs
privileges and, by default, Linux 6.15+ (6.12 was found to lose data when the destination's send
buffer fills). It is not wired into only-socks yet.

## Not supported

UDP fragment reassembly (fragments are dropped), SOCKS4 `BIND`, GSSAPI authentication, a SOCKS
client, a Linux `splice(2)` path.
