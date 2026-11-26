# ADR-178: An accept filter on UDP listeners, bound sockets and QUIC servers

English | [简体中文](178-udp-accept-filter.zh-CN.md)

Status: accepted (2026-11-26). akit's A220.

## Context

ADR-099 gave TCP listeners an accept filter: `Listener::filter`, a `Fn(&SocketAddr) -> bool`
called right after `accept`, swapped while the engine runs with `Engine::set_listener_filter`.
akit builds its access lists (allow and deny lists of client addresses, its decision 034) on it
and swaps the filter on every reload without binding anew. UDP had nothing of the kind: on a UDP
or datagram listener `Listener::filter` failed the build with `InvalidInput`, and
`set_listener_filter` answered `Unsupported`.

So akit could not drop a refused client's datagrams as fit does (fib's `Binding.Filter`) before a
session or a QUIC connection is made for it. A refused HTTP/3 client got a full QUIC handshake (TLS
work for every Initial it sends) before its request was answered 403, and every datagram of a
refused `udp` client opened a per-peer connection that akit closed at once. Its runtime UDP
listeners are `Engine::bind_udp` sockets, which had no filter either.

## Decision

1. **`Listener::filter` on UDP listeners.** On a per-peer UDP listener (`Listener::udp(..).serve`)
   the filter is asked, on the I/O thread, for each datagram from a peer that has no connection
   yet, before the `udp_max_peers` check and the acceptor's `on_open`: `false` drops the datagram.
   Nothing is remembered of a refused peer, so its next datagram asks again: a swapped filter
   applies at once and nothing grows with the peers refused (fit's decision 7 on I195). Peers
   that already have a connection are not asked again, as TCP connections accepted before a swap
   are not checked again. The per-peer UDP loop is the epoll / kqueue one whatever backend or
   scheduling the listener asked for, so the filter works there too.
2. **On datagram listeners** (`serve_datagrams`, ADR-065), which keep no peers, every datagram is
   asked: those refused are dropped before the handler's batch is made (`DatagramPort`, shared by
   epoll, kqueue and io_uring) and are not counted as received. The view of the filter is read
   once per receive batch (one atomic load), then the filter is called per datagram.
3. **Counted** in `LoopCounters::filtered` (`akio_connections_filtered_total`): on UDP, each
   datagram dropped because the filter refused its peer. A filter that panics refuses, as on TCP.
4. **Swapped while running**: `Engine::set_listener_filter` / `clear_listener_filter` work on UDP
   and datagram listeners, with ADR-099's cell (generation counter, filter replaced under a lock,
   each loop keeping its own view): in force for every datagram received after the call returns.
   Only DPDK listeners still answer `Unsupported` (and fail `build` with a filter).
5. **Bound sockets.** `Engine::bind_udp_filtered(addr, acceptor, filter)` binds with the filter in
   force from the socket's first datagram (the cell is filled before the loop learns of the
   socket). Every `UdpBinding` the epoll / kqueue UDP group makes carries its own cell:
   `UdpBinding::set_filter` / `clear_filter` swap it (a filter set after `bind_udp` returned
   misses what arrived before). The group trait gains `Group::bind_udp_filtered`, whose default
   refuses a filter (`Unsupported`); `UdpBinding::set_filter` on a binding without a cell answers
   `Unsupported` too. `Engine::set_listener_filter` does not reach bindings: they have no
   listener id.
6. **A QUIC connection asks again.** A UDP peer's connection can carry several QUIC connections
   (a client that reconnects from the same port), and a filter swapped after the peer was opened
   must apply to the new ones. The UDP connection keeps the cell of the listener or bound socket
   it came to (`Sock::Udp` in akio-core, one pointer), and the new `Conn::filter_allows(peer)`
   asks it (taking the cell's lock only once a filter was ever installed) and counts a refusal in
   `filtered`. akio-quic's server asks it when an Initial packet would make a new connection,
   before its `max_connections` check, the token check and any TLS work
   (`Endpoint::handle_gated`): refused, the datagram is dropped with nothing kept and nothing sent
   (no Retry, no CONNECTION_REFUSED, which would tell a refused client the server is there).
   Datagrams to existing connections, migrations included, are not asked. akio-h3 serves through
   `QuicServer`, so HTTP/3 listeners get the same.

## Consequences

- Additive API: `Engine::bind_udp_filtered`, `UdpBinding::set_filter` / `clear_filter`,
  `Conn::filter_allows`; `Listener::filter` and `Engine::{set,clear}_listener_filter` accept UDP
  and datagram listeners. Hidden, backend-facing: `Group::bind_udp_filtered`,
  `UdpBinding::with_filter_cell`, `DatagramPort::with_filter`, `FilterCell::allows`,
  `FilterView::{current, check, cell}`, and a `filter` argument to `ConnInner::new_udp`.
- A build that set a filter on a UDP listener used to fail; it now runs with the filter.
- Cost without a filter: per new UDP peer one atomic load; per datagram listener batch one atomic
  load; per new QUIC connection one atomic load. With one: the filter's own call per new peer, per
  datagram on datagram listeners, and per new QUIC connection a lock to take the filter. The read
  path of known peers is unchanged. Each UDP connection is one pointer larger.
- akit can install its TCP side's access policy on the UDP side, drop its per-request HTTP/3
  check and its `udp` session check.

Not done: DPDK UDP listeners (no filter, as for TCP).

## Verification

- `crates/akio/tests/udp_filter.rs`: a UDP listener refusing a peer (dropped, counted per
  datagram, no peer kept, allowed later), the filter swapped and cleared on a running listener
  (known peers kept), refused peers taking no room under `udp_max_peers` (just under, at and over
  the limit), a panicking filter, a UDP listener asking for work stealing, a bound socket filtered
  from its first datagram and swapped through `UdpBinding`, a plain binding filtered later, and a
  datagram listener on the backend under test (io_uring with `AKIO_TEST_BACKEND=uring`).
- `crates/akio-quic/tests/filter.rs`: a refused QUIC client gets no connection and nothing back
  until the filter is swapped; a new QUIC connection from a UDP peer the server already has is
  refused by the filter asked again, and served once it is swapped; a QUIC server on a bound
  socket.
- `crates/akio/tests/runtime_listeners.rs` no longer expects UDP filters to be refused.
- Workspace suite on macOS (kqueue) and gpu51 (epoll, and io_uring with `AKIO_TEST_BACKEND=uring`).
