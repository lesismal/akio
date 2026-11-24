# ADR-118: A request's peer is the client a trusted PROXY header names

English | [简体中文](118-http-peer-from-proxy-header.zh-CN.md)

Status: accepted (2026-11-24)

## Context

ADR-095 gave akio-mux a listener layer, `proxy::ProxyProtocol`, that reads a PROXY protocol
header (v1 or v2) from the peers it trusts, attaches it to the connection and hands the rest to
the next acceptor. It left `Conn::peer_addr` alone and left akio-http reporting the socket's peer
as a request's address: "using `proxy::client_addr` there is left to the application or a later
change".

An application cannot make that change itself: a request handler sees `Request::peer` and
`Context::peer`, not the connection, so it never reaches the attached header. akit (the gateway
built on akio) serves HTTP listeners behind load balancers as fit does, where the client a
trusted header names is the request's client: its `X-Forwarded-For`, its access log line, its
`remote_ip` matchers, its rate limits and its `ip_hash` balancing all read `Request::peer`. akit
asked for it as A105 (`akit/docs/akio-api-requests.md`).

## Decision

akio-http fills `Request::peer` with `akio_mux::proxy::client_addr(conn)`: the source of the
header the PROXY layer attached, when it attached one naming an address, else the socket's peer
as before. The same address names the connection's span and is what HTTP/2 sessions (prior
knowledge, over TLS, or upgraded from HTTP/1.1 with `h2c`) give their streams' requests.

- No option turns it off. The header is attached only by a `ProxyProtocol` layer the server put
  in front of akio-http, and only for peers its `trusted` test accepts: a server that installed
  the layer asked for the address it reads. A header naming no address (`PROXY UNKNOWN`, v2
  `LOCAL`, an unspecified or Unix family) leaves the socket's peer.
- `Conn::peer_addr` and `RawConn::peer_addr` are unchanged (ADR-095): code that wants the hop's
  own address still has it from the connection.
- akio-http depends on akio-mux, which depends on akio-core alone. akio-mux's dev-dependency on
  akio-http makes a cycle through dev-dependencies only, which Cargo allows.
- The cost is one read of the connection's write-once attachment (`OnceLock::get`) and a type
  check per request; a connection without one pays the `get`.

## Consequences

- Behind a trusted load balancer, akio-http applications see the client's address without
  reading the header themselves.
- Tests (`crates/akio-http/tests/proxy_peer.rs`): the header's source over HTTP/1.1, HTTP/2 with
  prior knowledge, an `h2c` upgrade and HTTPS (the header before TLS); the socket's peer for v1
  `UNKNOWN`, v2 `LOCAL` and an untrusted peer. Epoll and io_uring.
- akio-h3 is unchanged: no PROXY header comes over QUIC (ADR-095).
