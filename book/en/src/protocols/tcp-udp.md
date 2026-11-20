# TCP and UDP

## TCP servers

A TCP server is a `Listener::tcp(addr)` serving an acceptor; see
[Getting started](../getting-started.md) and [Handlers](../concepts/handlers.md). Useful
details:

- Port 0 picks a free port; read it back with `Engine::local_addrs()`.
- On Linux each I/O thread binds its own `SO_REUSEPORT` socket on the address and the kernel
  spreads new connections; on macOS the threads share one socket.
- `Config::backlog` is the `listen(2)` backlog (default 1024), `Config::max_connections` refuses
  accepts beyond a number of open connections (counted engine-wide, dialed connections and UDP
  peers included).
- File bodies: protocol code can send a file range with `sendfile(2)` through ordered response
  parts (`Part::File`); only-http uses it for static files on plain TCP.

## TCP clients

```rust,ignore
{{#include ../../../../crates/only/examples/guide-basics.rs:dial}}
```

`Engine::dial` runs the client connection with the same `Acceptor`/`Handler` model as a server
connection. Give the engine `client_threads(n)` to keep clients off the listeners' threads.

## UDP servers

`Listener::udp(addr)` turns every distinct peer address into a *connection*:

- the acceptor's `on_open` runs on the peer's first datagram;
- `on_data` runs **once per datagram** (boundaries are kept);
- `Conn::send` sends **one datagram** to that peer, from any thread;
- a peer that has been silent for `Config::udp_idle_timeout` (default 60 s; `idle_timeout` wins
  when it is set and shorter) is closed and its `on_close` runs.

```rust,ignore
{{#include ../../../../crates/only/examples/udp-echo.rs}}
```

On Linux the listener's threads each bind a `SO_REUSEPORT` socket, and a given peer always lands
on the same thread; on other systems one thread serves the listener. Receives are batched with
`recvmmsg`. `spawn_blocking`, `close_after_send` and ordered slots work as on TCP.

Linux batching on the send side: the replies produced while handling one receive batch leave
with `sendmmsg` across peers, and runs of equal-size datagrams to one peer become a single UDP
GSO send (probed at runtime and disabled for good on `EIO`/`EINVAL`; `ONLY_UDP_GSO=0` turns it
off). `Conn::send_segments(buf, size)` sends a buffer as consecutive datagrams of `size` bytes in
one call; only-quic uses it for multi-datagram transmits.

Protecting a public UDP port:

- `Config::udp_max_peers`: at most this many peers per listener; datagrams from new peers beyond
  it are dropped without creating a connection and counted (`Engine::udp_stats().rejected`).
- `Config::udp_gro` (Linux, on by default where the kernel supports it): lets the kernel
  coalesce datagrams of one flow; `only` splits them again by the segment size the kernel reports,
  so `on_data` still sees one datagram per call. It helps bulk flows from GSO senders (QUIC
  transfers); request/response traffic is not measurably slower. Needs a `read_buffer` of at
  least 64 KiB; `ONLY_UDP_GRO=0` turns it off.

## Connectionless UDP servers

A peer table is what QUIC, DTLS or a game server need, but a DNS, syslog or StatsD server
answers each datagram on its own and would only pay for it (a `Conn`, a handler and an idle
timer per source address, and a table spoofed sources can fill). Serve the UDP listener with
`serve_datagrams` instead of `serve` and it has no connections at all (ADR-065):

```rust,ignore
{{#include ../../../../crates/only/examples/udp-dns.rs:handler}}

{{#include ../../../../crates/only/examples/udp-dns.rs:listener}}
```

- The factory runs **once per I/O thread** (on Linux each thread has its own `SO_REUSEPORT`
  socket, and the kernel keeps a peer on one thread; elsewhere one thread serves the port), so
  the handler's state is per thread and needs no lock.
- `on_datagrams` gets each receive batch as `(peer, &[u8])` pairs, borrowed for the call
  (GRO receives are already split back into datagrams). There is no `on_open`, `on_close` or
  idle timeout, and `udp_max_peers` / `udp_idle_timeout` do not apply: memory does not depend on
  how many addresses send.
- `Replies::send_to(data, addr)` queues a datagram to **any** address; when the callback
  returns, the batch's datagrams leave together: one `sendmmsg` per 64 messages on Linux, with
  runs of equal-size datagrams to one address merged into one UDP GSO message (one `sendto` each
  elsewhere). Datagrams the socket has no room for wait, and the thread stops reading until
  they are out; the queue is bounded by `Config::max_queued_bytes` (`send_to` then fails with
  `WouldBlock`).
- From any other thread, a `DatagramSender` (`Send + Sync + Clone`; from the factory,
  `Replies::sender()` or `Engine::datagram_sender(local)`) sends right away with one `sendto`;
  a full socket drops the datagram with `WouldBlock`. Do slow work on your own threads and
  answer from there with it: the callbacks run on the I/O thread and must not block.
- `on_shutdown(out)` lets the handler send last datagrams; the engine waits up to
  `shutdown_timeout` for them. A panic in a callback is logged and the handler keeps serving.
- Backends: epoll, kqueue and io_uring (the ring reports readiness, the datagrams go through
  the same `recvmmsg` / `sendmmsg` path). Not DPDK (`build` fails with `Unsupported`). The
  thread count is fixed (`Engine::set_threads` refuses it), as for per-peer UDP listeners.

The snippets are from `crates/only/examples/udp-dns.rs`, a small DNS-style responder. On the same
host, a 64-byte echo served this way handles about as many requests as the per-peer listener
with less server CPU per request (see `docs/BENCHMARKS.md`, "Connectionless UDP").

## UDP clients

```rust,ignore
{{#include ../../../../crates/only/examples/guide-config.rs:udp_dial}}
```

`Engine::dial_udp(addr, acceptor, on_error)` creates a socket of its own (so its own local port)
`connect`ed to `addr`. `on_open` runs right away (UDP has no handshake), `on_data` per datagram,
`close()` ends it, and an ICMP "port unreachable" closes it with `ConnectionRefused`. The engine
needs `udp_client_threads(n)` or a UDP listener whose threads can host it.

`Engine::dial_udp_from(local, peer, acceptor, on_error)` instead opens a peer `Conn` on the
socket of the UDP listener bound at `local`: datagrams leave from the listener's port, which is
what a peer-to-peer node sharing one port needs (a DHT node, uTP; see
[BitTorrent](bittorrent.md)). It fails with `AlreadyExists` when the peer already has a
connection on that listener (its datagrams go there). On Linux the peer's answers may reach
another of the listener's threads, which then opens a peer through the listener's own acceptor.

## Not provided

- Per-peer UDP listeners on io_uring: they run on the epoll UDP loop (`recvmmsg` / `sendmmsg`
  already make it one syscall per batch). Connectionless datagram listeners do run on io_uring.
