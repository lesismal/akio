# SOCKS and HTTP CONNECT proxies

`only-socks` provides a SOCKS5 / SOCKS4 / SOCKS4a server (`Socks`), an HTTP `CONNECT` proxy
(`connect_proxy`) and a SOCKS client (`SocksClient`, [below](#socks-client)). The server and
the proxy relay callback to callback with **backpressure in both directions**:
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
  **This is a default change**: earlier versions dialled any destination; set
  `Destinations::Any` to keep that.
- `Destinations::Any` restores the old behaviour, for a proxy whose purpose is to reach a
  private network (a bastion); restrict who can use it (`auth`, a listener on a trusted
  interface). `Destinations::Custom(f)` takes your own rule.
- Data a client sends before its upstream is connected is held up to 256 KiB (the relay's
  pause threshold); more closes the client.
- `CONNECT` targets are resolved on a small bounded resolver pool (4 threads, 1024 queued
  requests; 503 when full), never on the I/O thread.
- The policy covers every command: `CONNECT`, a `BIND`'s expected peer (a refused address gets
  reply 2, and a connection from a denied address is never accepted) and each `UDP ASSOCIATE`
  datagram's destination (checked on the resolved address; denied ones are dropped). It applies
  before and in addition to the `allow` hook.
- After a `BIND`'s first reply the handshake timeout no longer applies (`bind_timeout` bounds
  the wait, then the idle timeout the relay); once a `UDP ASSOCIATE` is set up, the session
  timeouts stop and `udp_idle_timeout` governs the association.
- Stalled readers are also bounded by the engine's `Config::write_timeout`.

## BIND and UDP ASSOCIATE

Both commands are off by default (they open ports on the proxy host on a client's request); turn
them on per server (`bind` covers SOCKS5 and SOCKS4 `BIND`):

```rust,ignore
let socks = Socks::new(er.clone())
    .bind(true)                                   // SOCKS5 and SOCKS4 BIND
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
  accepted outside the engine like a dialed connection. SOCKS4 (and 4a) `BIND` works the same
  way with SOCKS4 replies (`0x5a` with port and IPv4 address, `0x5b` on failure); only a
  connection from `DSTIP` is taken (any when it is `0.0.0.0` or a 4a host name), others are
  dropped while waiting. A proxy reached over IPv6 refuses SOCKS4 `BIND` (no way to say where).
- **UDP ASSOCIATE**: each association gets its own UDP socket (`Engine::bind_udp`) on the
  address the client reached the proxy on, so the engine needs UDP I/O threads
  (`udp_client_threads` or a UDP listener; without them the reply is 1). Datagrams count as the
  client's only from the control connection's IP, and from one port once the request or the
  first datagram fixed it. Fragmented datagrams (non-zero `FRAG`, RFC 1928) are reassembled and
  relayed as one datagram: one sequence at a time per association, taken only in order (1, 2, 3,
  …; fragments carry no sequence number, so a gap, a repeat, another destination or a whole
  datagram in the middle drops the sequence), at most 65,507 bytes, dropped 5 s after its first
  fragment. Answers are relayed only from addresses the client
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
client for BIND, SOCKS4 BIND, fragments and the UDP edge cases, running the same clients against
Dante as a reference; it also runs `SocksClient` (below) against Dante and against only-socks.

## SOCKS client

`SocksClient` speaks SOCKS5 (`CONNECT`, `BIND`, `UDP ASSOCIATE`; no authentication or
username/password), SOCKS4 and SOCKS4a (`CONNECT`, `BIND`), either on the engine (callbacks on
the I/O threads, nothing blocks) or blocking over `std::net`:

```rust,ignore
use only_socks::{Dest, SocksClient, Version};
let client = SocksClient::from_url("socks5h://alice:secret@proxy.internal:1080")?;
// or SocksClient::new(Version::Socks5, addr).auth("alice", "secret")

// Blocking: a TcpStream connected to the target through the proxy.
let stream = client.dial_blocking(&Dest::Name("example.com".into(), 443))?;

// On the engine: `acceptor` serves the tunnel (a `Tls` acceptor runs TLS inside it).
client.dial(&engine, Dest::Name("example.com".into(), 80), acceptor, |e| eprintln!("{e}"));

// BIND: tell the peer where to connect, then serve its connection.
client.bind(&engine, peer_ip.into(), |bound| announce(bound), acceptor, |e| eprintln!("{e}"));

// UDP ASSOCIATE (SOCKS5): datagrams through the relay.
client.udp_associate(
    &engine,
    |assoc, from, payload| { /* a datagram from `from` */ },
    |r| { let assoc = r.expect("associated"); assoc.send_to(b"query", &dns_server.into()).ok(); },
);
```

- On the engine, `acceptor.on_open` runs once the TCP connection to the proxy is up (as for a
  TLS dial): what the handler sends waits for the tunnel, and `on_data` sees the target's bytes
  only. **Every failure before the tunnel opens goes to `on_error`**: resolving or reaching the
  proxy (each of its addresses in turn), a refusal (an `io::Error` carrying
  `only_socks::ProxyRefused`: `status()` is the closest HTTP status, `socks_reply()` the SOCKS
  code), a reply that is not SOCKS, the handshake timeout. The connection then closes.
- `bind`'s `on_bound` gets the proxy's first reply (an unspecified address is replaced by the
  proxy's) on the I/O thread, mid-handshake: hand it to the peer, do not use the BIND
  connection from it. Blocking: `bind_blocking` returns once the proxy listens
  (`bound_addr()`), `accept()` waits for the peer.
- `udp_associate` binds a UDP socket on the engine (it needs `udp_client_threads`), announces
  it and hands a `UdpAssociation` to `done` (`send_to`, `relay_addr`, `close`). Datagrams from
  anything but the relay are dropped; fragmented ones are reassembled first. Blocking:
  `udp_associate_blocking()` returns a `BlockingUdp` (`send_to`, `recv_from`), ended by dropping
  it.
- Limits: `handshake_timeout` (default 10 s) bounds connecting to the proxy and its reply;
  `bind_timeout` (default 60 s) bounds a BIND's wait for the peer. Blocking replies are read a
  byte at a time, so the stream you get back starts exactly at the tunnel's first byte.
- Host names: a `Dest::Name` goes to SOCKS5 and SOCKS4a proxies as a name; over SOCKS4 the
  client resolves it (IPv4 only).

The HTTP and WebSocket clients use the same handshake for their `socks5://` / `socks4a://`
proxies ([HTTP clients](http-clients.md#proxies)). See
[ADR-019](https://github.com/lesismal/only/blob/main/docs/adr/019-socks-client-fragments-socks4-bind.md).

## In-kernel relaying

For pure TCP relays on Linux, `only::ebpf::Relay` can splice two TCP connections in the kernel
with a sockmap (`SOCKHASH` + `sk_skb` verdict), so payload bytes never reach user space. It needs
privileges and, by default, Linux 6.15+ (6.12 was found to lose data when the destination's send
buffer fills). It is not wired into only-socks yet.

## Not supported

GSSAPI authentication; a Linux `splice(2)` relay path (not attempted: the engine's relay with
two-way backpressure stays, and `only::ebpf::Relay` covers in-kernel relaying); sending
fragmented UDP datagrams (they are only reassembled); TLS to the proxy in the clients.
