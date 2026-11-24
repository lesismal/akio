# ADR-120: Dialing a Unix-domain socket, and the HTTP client over one

English | [简体中文](120-unix-socket-dial.zh-CN.md)

Status: accepted (2026-11-24)

## Context

The engine dials TCP only: `Engine::dial` and `dial_from` take a `SocketAddr`, and the backends
hold a connecting socket as a `TcpStream` whose peer and local addresses they read when it
connects. akio-http's `Client` resolves the URL's host and dials it.

akit (the gateway built on akio) reads routes from Docker containers' labels, as fit does, and
follows the daemon's events. The Docker daemon's API is on a Unix-domain socket,
`/var/run/docker.sock`, by default. akit's rules keep its control plane off blocking clients and
async runtimes and send what akio lacks to akio; akit asked for this as A135
(`akit/docs/akio-api-requests.md`).

## Decision

- **`akio_sys::connect_unix_nonblocking(path) -> io::Result<OwnedFd>`** starts a non-blocking
  connect of an `AF_UNIX` stream socket (close-on-exec), with `ffi::AF_UNIX` and
  `ffi::sockaddr_un` (checked against `libc` in the layout tests). An empty path, one with a NUL
  byte, or one too long for `sun_path` (107 bytes on Linux, 103 on macOS) is `InvalidInput`;
  abstract sockets are not supported.
- **`Engine::dial_unix(path, acceptor, on_error)`** serves the connection like a dialed TCP one,
  on the same group (`client_threads`, else the last TCP listener's), through the new
  `Group::dial_unix` (unsupported by default; epoll and io_uring implement it). The backends keep
  holding the socket as a `TcpStream` (`TcpStream::from(OwnedFd)`, safe): a flag on the dial
  command makes them skip what is TCP's only (`TCP_NODELAY`, reading the peer and local
  addresses), and the connection's `peer_addr` and `local_addr` are the new constant
  `UNIX_ADDR`, `0.0.0.0:0`. Everything else (reads, writes, `SO_ERROR`, shutdown, close) is what
  any stream socket supports.
- **`Client::with_unix_socket(Option<PathBuf>)`** sends every request of the client to that
  socket, whatever the URL's host and port, as Go's `http.Transport` with a `DialContext` and
  curl's `--unix-socket` do: the URL's host is still the `Host` field and keys the idle
  connections, `https://` still runs TLS over the socket, and no name is resolved and no proxy
  used. Every timeout of the request applies as before.

## Consequences

- akit's Docker provider lists containers and follows `/events` on akio's client, its callbacks
  on akio's I/O threads, with nothing blocking.
- A Unix-domain connection has no IP address; code that logs or keys by `peer_addr` sees
  `0.0.0.0:0`.
- Six new `unsafe` blocks in `akio-sys/src/net.rs` (the zeroed `sockaddr_un`, `socket`, owning
  the fd and `connect`), with the invariants of the other sockets there (the fd owned before any
  fallible step, the length within the structure).
- Tests (`crates/akio-http/tests/unix_socket.rs`): requests over one kept-alive connection; a
  chunked stream read as it is written and cut midway; a missing socket, a path too long and a
  socket that closes at once are errors; `Engine::dial_unix`'s addresses and bytes both ways.
  Epoll and io_uring (dialed on a listener's group, so on the backend under test).
