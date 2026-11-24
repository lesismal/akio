# ADR-121: Unix-domain stream listeners, and a TLS server capped at TLS 1.2

English | [简体中文](121-unix-listeners-tls12-cap.zh-CN.md)

Status: accepted (2026-11-25)

## Context

akit (the gateway built on akio) carries over fit's listener settings. Two of them had no akio
API (akit's `docs/akio-api-requests.md`):

- **A23.** fit's Admin API listens on a Unix-domain socket when `admin.address` is
  `unix/<path>`: the file is made `0600`, a stale socket file is replaced and one in use refused,
  so only the owner's processes reach the API, with no port and no token. akio's listeners took a
  `SocketAddr` only (TCP or UDP); ADR-120 added dialing such a socket, not serving one.
- **A9.** fit's `listeners[].tls.max_version` takes `1.2` (Go's `tls.Config.MaxVersion`), for
  network cards that offload TLS 1.2 alone. `ServerConfigBuilder` capped a server at TLS 1.2 only
  through `__tls12_only`, hidden and meant for tests and interop tools.

## Decision

**A23: `Listener::unix`.**

- `Listener::unix(path)` is a stream listener at a socket file, served like a TCP one: the same
  acceptors (akio-http, TLS, akio-mux), on epoll, kqueue and io_uring, at build time or through
  `Engine::add_listener` / `remove_listener`. Its I/O threads share the one socket and race to
  accept, as for `Listener::tcp_from_std`.
- `Listener::unix_from_std(UnixListener)` serves a socket already bound and listening.
- `Listener::unix_mode(mode)` sets the file's permission bits after `bind` and before `listen`, so
  no connection is accepted while the file has the umask's bits. On any other listener (and on
  `unix_from_std`, already listening) `build` fails with `InvalidInput`.
- A socket file already at the path that no one listens on (a non-blocking connect is refused)
  is replaced; one in use, or a file that is not a socket, fails with `AddrInUse`. The file stays
  when the listener is removed or the engine stops: it is the caller's, as with `tcp_from_std`.
- A connection has no IP address: its `peer_addr` and `local_addr` are `UNIX_ADDR`
  (`0.0.0.0:0`, ADR-120), as is the listener's `Engine::local_addrs` entry; an accept filter
  sees that address. DPDK refuses the listener (`Unsupported`); `Accel::Ebpf` has nothing to
  steer.
- `akio_sys::listen_unix(path, backlog, mode)` binds it (non-blocking, close-on-exec; the path's
  rules are `connect_unix_nonblocking`'s) and `akio_sys::accept_stream(listener)` accepts without
  reading an address (`accept4` on Linux, `accept` then `fcntl` on macOS): `std`'s
  `TcpListener::accept` turns an `AF_UNIX` peer into an error and closes the connection.
  The backends keep holding the socket as a `TcpListener`, as ADR-120 holds a dialed one as a
  `TcpStream`: `EpollGroup::bind_unix_listener` and `UringGroup::bind_unix_listener` mark the
  group's loops, which then accept with `accept_stream` (epoll, kqueue) or take io_uring's
  multishot accept without asking the peer's address, and skip `TCP_NODELAY` and the local
  address.

**A9: `tls12_only`.** `ServerConfigBuilder::tls12_only(bool)` and
`ClientConfigBuilder::tls12_only(bool)` are public (the hidden `__tls12_only` stays, calling
them). The TLS 1.3 suites are left out: a client that offers 1.3 too negotiates 1.2, without the
RFC 8446 downgrade sentinel (1.2 is the most this server speaks), and one that offers only 1.3
fails. `tls12_only` together with `tls13_only` fails `build`.

Rejected:

- **An enum peer address on `Conn`** (`Tcp(SocketAddr) | Unix(PathBuf)`). Every handler,
  filter, log and metric of akio reads a `SocketAddr`; ADR-120 already chose a placeholder for
  dialed Unix-domain connections, and listeners follow it.
- **Removing the socket file when the listener goes.** A listener does not know whether another
  process bound the path since; the stale-file check at the next bind covers restarts.
- **`min_version` / `max_version` taking a `TlsVersion`.** akio speaks TLS 1.2 and 1.3 only, so
  the two flags say every combination there is.

## Consequences

- akit's Admin API listens on `unix/<path>` as fit's does, and the file provider's control
  socket may too; akit's `tls.max_version: 1.2` builds its listener with `tls12_only`.
- Six new `unsafe` blocks in `akio-sys/src/net.rs` (`bind` and `listen` of the Unix socket, the
  accept and owning its descriptor, on Linux and macOS), with the invariants of the other sockets
  there; the Unix socket's creation and address are shared with ADR-120's connect.
- Tests: `crates/akio-http/tests/unix_listener.rs` (requests and the mode, large bodies both ways
  and a client cut midway, a stale file replaced, one in use and a regular file refused, bad paths,
  `unix_from_std`, a listener added and removed at run time with a filter), on epoll and io_uring;
  `akio-tls` `config_tests::a_server_capped_at_tls12`.
