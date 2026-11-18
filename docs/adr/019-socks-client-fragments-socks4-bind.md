# ADR-019: SOCKS client, SOCKS proxies for the HTTP/WebSocket clients, UDP fragment reassembly and SOCKS4 BIND

English | [简体中文](019-socks-client-fragments-socks4-bind.zh-CN.md)

Status: accepted (2026-11-17)

## Context

`docs/DEV-PLAN.md` (M4, only-socks) left open: a SOCKS client, UDP fragment reassembly (the
server dropped every datagram with a non-zero `FRAG`, which RFC 1928 allows), SOCKS4 `BIND`,
GSSAPI and a Linux `splice` relay. ADR-010 gave the HTTP and WebSocket clients HTTP proxies
(`only_ws::proxy::Proxy`, a `CONNECT` tunnel as a `Transport` layered under TLS) and named SOCKS
as "not supported, additive later".

The dependency direction is `only-ws → only-http → only-socks` (the server's HTTP `CONNECT`
proxy is an only-http service), so a client written inside only-socks cannot be used by the
HTTP or WebSocket clients without a cycle.

## Decision

1. **One sans-io client handshake, in only-ws** (`only_ws::socks`, `#[doc(hidden)]`, next to
   the HTTP proxy tunnel of ADR-010). `Handshake::new(version, cmd, target, auth)` refuses what
   the protocol cannot carry (a name or IPv6 over SOCKS4, IPv6 over SOCKS4a, `UDP ASSOCIATE`
   over SOCKS4, names and credentials over 255 bytes, empty SOCKS5 credentials); `start` writes
   the greeting (SOCKS5 offers "no authentication" and, with credentials, username/password:
   the proxy chooses) or the SOCKS4 request; `feed` consumes the proxy's bytes, writes what must
   be answered (RFC 1929 credentials, the request), returns how many bytes it used and each
   successful reply (`BIND` has two). Anything after the last reply is tunnel data. Refusals are
   errors carrying `ProxyRefused`; bytes that are not SOCKS are `InvalidData`. It is the only
   SOCKS client parser: the proxy tunnel, only-socks' client and the fuzz target all run it.

   *Why only-ws*: it is the lowest crate both clients share, it already owns the proxy tunnel
   (`Connect`), and the handshake is the same shape as `CONNECT` (a prefix exchange before the
   stream), so it plugs into the same `Transport` with no change to the clients' structure.

2. **SOCKS proxies for the HTTP and WebSocket clients.** `Proxy::all/http/https` and
   `ProxyServer` accept `socks5://`, `socks5h://`, `socks4://` and `socks4a://` (default port
   1080; URL credentials become RFC 1929 credentials, or the SOCKS4 user id). `Proxy::from_env`
   also reads `all_proxy` / `ALL_PROXY` for the schemes the specific variables leave unset
   (curl's convention; `ALL_PROXY=socks5h://…` is how SOCKS is usually configured).
   `Connect::new` runs the SOCKS handshake instead of `CONNECT` for a SOCKS proxy, and every
   request goes through a tunnel to the target, `http://` ones included (no absolute form).
   `socks5h` and `socks4a` send host names to the proxy; `socks5` and `socks4` resolve the target
   first with `only::dns` (curl's semantics) and ask for the first IPv4 address (else the first;
   SOCKS4 IPv4 only), because a tunnel names one address and `localhost` / dual-stack names often
   list an IPv6 address first that the target does not listen on.

3. **`ProxyRefused` covers SOCKS.** A SOCKS refusal is the same error type the clients already
   report: `status()` is the closest HTTP status (407: no acceptable method or failed
   authentication; 403: "not allowed by ruleset", identd refusals; 502: failures to reach the
   target; 501: unsupported command or address type; 504: TTL expired), `reason()` the meaning
   of the code, and the new `socks_reply()` the SOCKS5 `REP` / SOCKS4 `CD` (0xff for method and
   authentication failures). Code that checks `status() == 407` works for both kinds of proxy.

4. **only-socks client: `SocksClient`.** `new(version, addr)`, `with_host(version, host,
   port)`, `from_url(url)`, `auth(user, password)`, `handshake_timeout` (10 s), `bind_timeout`
   (60 s), and `Version` (`Socks5`, `Socks4`, `Socks4a`). Targets are the server's `Dest`
   (address or name; `From<SocketAddr>` added). On the engine, without blocking:
   - `dial(engine, to, acceptor, on_error)`: `CONNECT`; the acceptor may be a `Tls` acceptor (TLS
     runs inside the tunnel). The handler is opened when the TCP connection to the proxy is up,
     as for a TLS dial: what it sends is held until the tunnel opens and `on_data` sees target
     bytes only.
   - `bind(engine, from, on_bound, acceptor, on_error)`: `on_bound(SocketAddr)` gets the first
     reply (an unspecified address is replaced by the proxy's) on the I/O thread, mid-handshake.
   - `udp_associate(engine, on_datagram, done)`: a UDP socket bound through `Engine::bind_udp`
     on the unspecified address of the proxy's family is announced (`0.0.0.0:port`), `done` gets
     a `UdpAssociation` (`send_to(payload, &Dest)`, `relay_addr`, `local_addr`, `is_open`,
     `close`); `on_datagram(&UdpAssociation, Dest, &[u8])` runs for every datagram from the
     relay (others are dropped), after reassembly.

   **Errors before the tunnel opens all go to `on_error`**: resolution, connect (each proxy
   address in turn), a refusal, a reply that is not SOCKS, and the handshake timeout. The engine
   does not pass a transport's error to `on_close` (a TLS failure there is `None` too), so the
   tunnel transport gets hidden `on_fail` / `on_open` hooks, and the deadline is the existing
   only-socks watchdog with an `on_fire` callback (disarmed when the tunnel opens; TLS inside it
   keeps its own handshake timeout). The connection then closes and the handler's `on_close`
   runs with no error.

   Blocking helpers over `std::net`: `dial_blocking(&Dest) -> TcpStream`,
   `bind_blocking(&Dest) -> BlockingBind` (`bound_addr`, `accept() -> (TcpStream,
   SocketAddr)`, bounded by `bind_timeout`), `udp_associate_blocking() -> BlockingUdp`
   (`send_to`, `recv_from` with reassembly, `set_read_timeout`, `relay_addr`, `local_addr`,
   `is_open`; dropping it ends the association). Replies are read a byte at a time so that no
   tunnel byte is consumed by the handshake. A SOCKS4 target name is resolved by the client
   (`only::dns` on the engine, the calling thread when blocking), IPv4 only.

5. **UDP fragment reassembly (RFC 1928 section 7)**, in the server's relay (client to
   destination) and in both client associations (relay to client), one shared implementation:
   one queue per association (the client's relay peer holds it, so no lock on the datagram path;
   a `FRAG` 0 datagram costs one branch), fragments taken only in order 1, 2, 3, …; a gap, a
   repeated or lower position (RFC 1928's reset rule), another destination or a whole datagram in
   the middle drops the sequence (the whole datagram passes); a sequence ends at the fragment
   with the high bit; at most 65,507 bytes (one UDP datagram's payload), dropped 5 s after its
   first fragment (RFC 1928's minimum timer; checked when the next fragment arrives, the memory
   goes with the association). Fragments carry no sequence number, so a lost fragment cannot be
   told apart from a reordered one: in-order-only is the only rule that never splices two
   sequences. The access-control hook still decides per destination, before buffering.
   Our side never fragments what it sends.

6. **SOCKS4 `BIND`**, under the same `Socks::bind(true)` switch and hook (`Command::Bind`,
   version 4) as SOCKS5's: the listener and the accept thread are shared, replies are SOCKS4
   (`0x5a` with port and IPv4 address, `0x5b` on failure or timeout); an IPv6 control connection
   cannot be expressed and is refused. Only a connection from `DSTIP` is taken (any when it is
   `0.0.0.0` or a SOCKS4a name); others are dropped while waiting, as for SOCKS5, rather than
   ending the request with `0x5b` as the SOCKS4 text describes (a scan of the port must not end
   a legitimate wait).

7. **No Linux `splice` relay.** The task allowed it only with a measured gain. The relay is
   callback-to-callback on the engine's buffers with two-way backpressure; a `splice` path needs
   pipes per tunnel, bypasses the engine's queues and metrics, and only-ebpf already has the
   in-kernel relay (`Relay::splice`, sockmap). It was not attempted.

Public API (only-socks): `SocksClient`, `Version`, `UdpAssociation`, `BlockingBind`,
`BlockingUdp`, `DEFAULT_CLIENT_HANDSHAKE_TIMEOUT`, `DEFAULT_BIND_TIMEOUT`, `ProxyRefused`
(re-export), `impl From<SocketAddr> for Dest`. only-ws: `ProxyRefused::socks_reply`. Hidden
(outside semver): `only_ws::socks`, `ProxyServer::{kind, credentials, parse, is_http,
resolves_locally, is_socks4}`, `ProxyKind`, `proxy::pick_target`, `Connect::{socks, on_bound,
on_fail, on_open, handshake_timeout}`, `ProxyRefused::socks`.

## Consequences

- `socks5://` / `socks5h://` work for `only_http::client::Client` and `only_ws::client::dial`
  with no new client API; `ProxyServer::parse` no longer rejects SOCKS schemes, and an unknown
  scheme's message lists the supported ones.
- Behaviour changes: `Proxy::from_env` now honours `ALL_PROXY`; a SOCKS5 relay that used to drop
  fragmented datagrams now relays complete in-order sequences; a SOCKS4 `BIND` request on a
  server with `bind(true)` is served instead of refused.
- The datagram path of a UDP association is unchanged for `FRAG` 0 apart from one branch; the
  TCP relay is untouched.
- Verified by unit tests (codec, transport, reassembly), integration tests (`tests/client.rs`:
  every version blocking and on the engine, refusals, timeouts, garbage, BIND, UDP, fragment
  reassembly both ways, the HTTP client through `socks5h://` / `socks5://`; only-ws: the
  WebSocket client through a SOCKS5 proxy), the fuzz target `socks_client`, and
  `tools/interop/socks/run.sh` (our client against Dante and against only-socks; PySocks, curl
  and the hand-written clients against the server, including fragments and SOCKS4 BIND).

## Alternatives considered

- *The client codec in only-socks, no HTTP/WebSocket integration*: simplest, but leaves
  `ALL_PROXY=socks5h://…` unusable for the clients and would need a second parser later.
- *A new `only-socks-client` crate below only-ws*: one more crate for ~400 lines whose only
  users are only-ws and only-socks.
- *Passing transport errors to `on_close` in only-core*: the general fix, but a behaviour change
  for every TLS connection's handlers; the hooks keep the change local.
- *Reassembling out of order by position*: impossible to do safely without sequence numbers (a
  lost fragment would splice two datagrams).
