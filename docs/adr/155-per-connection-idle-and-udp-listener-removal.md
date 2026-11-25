# ADR-155: An idle timeout per connection, and UDP listeners removed and drained

English | [简体中文](155-per-connection-idle-and-udp-listener-removal.zh-CN.md)

Status: accepted (2026-11-26). akit API requests A78 and A22.

## Context

**Idle timeouts.** The engine has two idle timeouts, each for every connection it serves:
`Config::idle_timeout` (TCP, counting received data only) and `Config::udp_idle_timeout` (UDP
peers, the HTTP/3 listeners' too). A gateway's layer 4 services (akit's, after fit's) each have an
idle timeout of their own (10 minutes for TCP and 1 for UDP by default), and a relay between a
client connection and an upstream one is idle only when neither side sends: a download is a
client connection that only receives writes. akit sweeps its connections on a timer thread of its
own and raises the engine's UDP idle timeout to the longest of its services' so that akio does
not close a session first.

**UDP listeners at run time.** ADR-099 adds, removes and drains TCP listeners on a running
engine; UDP listeners could only be given to the builder (`remove_listener` and
`shutdown_listener` answered `Unsupported`, `add_listener` `InvalidInput`), and a socket bound
at run time (`Engine::bind_udp`) could only be closed with its peers at once
(`UdpBinding::close`). akit serves HTTP/3 on such sockets, so a reload that removes or changes a
listener serving `h3` was refused until a restart, and HTTP/3 added by a reload was cut off
without a drain when removed. A per-peer UDP listener differs from a TCP one in one way that
matters here: its peers have no socket of their own, they all exchange datagrams on the
listener's socket (on Linux, one `SO_REUSEPORT` socket per I/O thread).

## Decision

1. **`Conn::set_idle_timeout(Option<Duration>)`** gives one connection an idle timeout in place
   of the engine's: a TCP connection (accepted or dialed) or a UDP peer (of a listener or a bound
   socket, or `dial_udp`'s). `Some(d)` closes it after `d` without activity (at least 1 ms),
   `None` never. **`Conn::set_idle_counts_writes(bool)`** counts data the connection sends as
   activity too, for its own timeout or the engine's. Both can be called from any thread at any
   time; the close happens on the connection's I/O thread exactly as the engine's idle close
   does (`on_close` with `ErrorKind::TimedOut` "idle timeout", counted in `idle_timeouts`).
   `Err(Closed)` once closed; `Err(Io(Unsupported))` on backends that keep the engine's (DPDK,
   TUN).
2. **The I/O path pays nothing for it.** The setting is two atomics on `ConnInner` that the loop
   reads only when told: the setter calls `LoopLink::retime_conn(id)` (a default method
   answering `false`), which posts a command to the epoll/kqueue, io_uring and UDP loops (and,
   with rounds scheduling, re-arms the timer in the poller's connection table under its shard's
   lock, from the calling thread). The loop copies the setting into its per-connection
   `IdleRule` and re-arms the timer from the connection's last activity. A connection that never
   sets one has `IdleRule::ENGINE`, whose checks are those the loops always made; reads still
   only store the loop clock.
3. **Writes are sampled, not timestamped.** Counting writes on the write path would put a clock
   read (or a shared store) on every `send`, from any thread. Instead a connection counting its
   writes is checked every eighth of its timeout: bytes sent since the last check (the
   connection's existing `sent` counter) move its last activity to the check's time. Never
   earlier than the truth, so it is never closed early; it is closed at most an eighth of the
   timeout late. Eight checks per timeout per such connection cost nothing measurable at the
   timeouts relays use (seconds to minutes).
4. **UDP listeners are removed and drained.** `remove_listener` and `shutdown_listener(id,
   drain)` take per-peer UDP listeners: from then on datagrams from new addresses are dropped
   (no peer is opened for them, `open_udp_peer` is refused) while the listener's peers keep
   exchanging datagrams; with a drain each peer gets `Acceptor::on_shutdown` at once and those
   left at the deadline are closed. A listener's sockets close once it has **no peer left on any
   thread** (or at the deadline): on Linux the threads' sockets form one `SO_REUSEPORT` group,
   and a socket leaving it early would make the kernel hash the remaining peers' flows onto
   sockets that do not know them. Each thread looks every 50 ms while it waits for the others.
   The threads exit then, unless they also serve `dial_udp` and `bind_udp` (the builder's last
   UDP listener without `udp_client_threads`), which keep them. `add_listener` takes a per-peer
   UDP listener and gives it threads of its own (UDP groups are not shared, ADR-130); it does
   not become a target of `dial_udp` or `bind_udp`. Datagram listeners (ADR-065) and DPDK stay
   `Unsupported`.
5. **`UdpBinding::shutdown(drain)`** does the same for a socket bound at run time: no new
   peers, `on_shutdown` for its peers, the socket closed once they are gone or at the deadline.
   `close` ends a drain early; a second `shutdown` does nothing.
6. **HTTP/3 drains.** `akio_quic::QuicHandler::on_shutdown` (default: nothing) is delivered to a
   server's connections whose peer's UDP connection got `on_shutdown` (a drained listener or
   bound socket, or engine shutdown). akio-h3 sends `GOAWAY` on its control stream with the
   first client request stream it has not seen (RFC 9114 section 5.2), answers the requests it
   has, refuses later ones with `H3_REQUEST_REJECTED`, and closes at once a connection that
   never had a request.

## Consequences

- akit sets each relayed connection's and UDP session's idle timeout from its service (with
  writes counted on both sides of a relay) and lets akio close it; its timer sweep and the
  raised engine UDP idle timeout go. A reload removes, changes and drains HTTP/3 listeners as it
  does TCP ones.
- `IdleRule` makes each loop's per-connection record 16 bytes larger.
- While a removed UDP listener drains next to a new one on the same address, the kernel still
  hashes part of the new peers onto the old sockets, which drop them until the drain ends: a
  short drain (or another port) keeps that gap small. Without a drain (`remove_listener`) the
  gap lasts until the old peers are gone, so `shutdown_listener` is the one to use for UDP.
- A QUIC connection whose UDP peer was closed at the drain deadline is not sent a
  `CONNECTION_CLOSE` (its socket is gone); it ends with its idle timeout.
- The engine's own shutdown now also sends HTTP/3 clients `GOAWAY` (it already called
  `on_shutdown` on UDP peers).
