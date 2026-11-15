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

- A connectionless datagram API (one callback per datagram without per-peer state): every peer
  is a `Conn`.
- UDP on io_uring.
