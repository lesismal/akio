# ADR-119: A proxy's tunnel checked once connected, and its connect timeout

English | [简体中文](119-socks-connected-check-and-connect-timeout.zh-CN.md)

Status: accepted (2026-11-24)

## Context

akio-socks decides where its proxies may connect with `ProxyConfig::destinations`, checked on
each address before it is dialed, and an access hook (`Socks::allow`) that sees the request, a
host name as a name. Neither sees both at once: the hook does not know what a name resolves to,
and `Destinations` does not know which name an address came from or which local address the
connection was opened from.

akit (the gateway built on akio) ports fit's forward proxy, `listeners[].socks` and the
`forward_proxy` handler for HTTP `CONNECT`, whose rules need both. fit decides a destination
host name by the address it resolved to, differently by the name: a name its `allow` list holds
is refused only by a `deny` range or by the default refusal of loopback, link-local, multicast,
unspecified and the host's own addresses; any other name needs an `allow` range to hold its
address. A connection to the host's own address shows as one coming from the address it goes to,
which only the open connection tells. fit makes this check on the open connection, before
anything is sent on it, so that DNS cannot change the answer between a check and the dial.

fit also gives its proxies a connect timeout of their own (`connect_timeout`, 10 s by default),
separate from the SOCKS handshake's, answered as such: HTTP `504 Gateway Timeout`, SOCKS5 "host
unreachable". akio's `handshake_timeout` covers the greeting through the connect and closes the
client without a reply. akit asked for both as A132 and A133 (`akit/docs/akio-api-requests.md`).

## Decision

Two fields of `ProxyConfig`, both `None` by default, which keeps every proxy as it was:

- `connected: Option<Connected>`, where
  `Connected = Arc<dyn Fn(&Dest, SocketAddr, SocketAddr) -> bool + Send + Sync>`. It decides
  each `CONNECT` tunnel's upstream connection (SOCKS5, SOCKS4 and 4a, HTTP `CONNECT`) when it
  opens, on its I/O thread, before the tunnel uses it or the client hears of it: given the
  destination as the client asked for it (`Dest::Name` for a host name, `Dest::Addr` for an
  address, an HTTP `CONNECT`'s literal address included), the address connected to and the local
  address (both with IPv4-mapped addresses written as IPv4). `false` closes the connection, tries
  no other address and fails the request as not allowed: SOCKS5 reply 2, SOCKS4 `0x5b`, HTTP
  `502 Bad Gateway`, as fit answers it. `destinations` still filters the addresses first.
  `BIND` and `UDP ASSOCIATE` keep `destinations` alone.
- `connect_timeout: Option<Duration>`: the longest time from a `CONNECT` request to its upstream
  being connected, name resolution and every address included. Past it the request fails with a
  reply (SOCKS5 4, SOCKS4 `0x5b`, HTTP `504 Gateway Timeout`) and the client is closed once it is
  sent. The proxies' watchdog thread times it, as it times the other two; `handshake_timeout`
  still runs from the client's connect.

The access hook's `Request::client` is the client a PROXY header names when akio-mux's
`proxy::ProxyProtocol` layer took one from a trusted proxy in front of the SOCKS server, as
ADR-118 made it a request's peer in akio-http; the socket's peer otherwise. fit checks a SOCKS
client that way behind a load balancer. akio-socks now depends on akio-mux (akio-http already
did).

A tunnel's outcome is now settled once (`Pending`): the first upstream that opens and passes the
check, a failure, or the connect timeout, whichever comes first; a connection that opens after
the timeout fired is closed. A SOCKS request whose name the logical pool cannot take (the pool
full) now gets reply 1 before the close, where it was closed without one.

## Consequences

- A proxy may decide by the name and the address together, and see the host's own address,
  without resolving anything itself and without a second lookup DNS could answer differently.
- akit's `socks` listeners and `forward_proxy` handler apply fit's rules and timeouts as fit
  does.
- Tests (`crates/akio-socks/tests/proxy.rs`): the check sees the name and both addresses and
  refuses with SOCKS5 2, SOCKS4 `0x5b` and HTTP 502, nothing reaching the upstream; the connect
  timeout answers SOCKS5 4 and HTTP 504 and does not cut a tunnel connected in time. Epoll and
  io_uring. The access hook behind a PROXY header sees the header's client.
