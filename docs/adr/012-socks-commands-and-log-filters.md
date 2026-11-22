# ADR-012: SOCKS5 BIND / UDP ASSOCIATE, `Engine::adopt_tcp`, and akio-log filters

English | [简体中文](012-socks-commands-and-log-filters.zh-CN.md)

Status: accepted (2026-11-16)

## Context

Two items were left open in `docs/DEV-PLAN.md`:

- `akio-socks` served SOCKS5 `CONNECT` only. `BIND` (active FTP and other protocols where the
  far side connects back) and `UDP ASSOCIATE` (DNS, QUIC, games through a proxy) answered
  "command not supported". There was no way to restrict what clients may reach beyond
  username/password.
- `akio-log` had a run-time maximum level and per-target ceilings set in code, but no way to set
  levels per target from the environment (what `RUST_LOG` does for env_logger) and no way to
  compile verbose statements out of release builds (the `log` crate's `max_level_*` features).

`BIND` needs a TCP listener opened at run time, and the accepted connection must be relayed by the
engine like any other; the engine had no way to take over a stream it did not accept or dial.

## Decision

1. **`Engine::adopt_tcp(stream, acceptor, on_error)`** (in `akio`): serves an already connected
   `std::net::TcpStream` like a dialed connection that has just connected, on the same I/O threads
   as `dial`. Backends implement a new hidden `Group::adopt` (default: `Unsupported`); the epoll and
   io_uring groups pass the stream through their existing dial path, which opens a connected
   stream immediately (writable at once, no pending error). No new reactor code.
2. **SOCKS5 `BIND` and `UDP ASSOCIATE` (RFC 1928), off by default.** `Socks::bind(bool)`,
   `Socks::bind_timeout(Duration)` (60 s), `Socks::udp_associate(bool)`,
   `Socks::udp_idle_timeout(Duration)` (120 s). Off by default because both open ports on the
   proxy host on a client's request; an existing deployment keeps answering "command not
   supported" (reply 7) until it opts in.
   - **BIND**: a listener on the address the client reached the proxy on (port 0), first reply
     with it, one connection accepted (only from the requested IP unless that is unspecified),
     second reply with the peer's address, then the same two-way relay with backpressure as
     `CONNECT`. The accept runs on a short-lived thread that polls every 10 ms, so it notices the
     client leaving and the timeout without a reactor listener API; a BIND is rare and waits for
     one connection, so a thread per pending BIND is acceptable. The accepted stream is adopted
     into the engine (point 1). Data from the client before the second reply closes the session.
   - **UDP ASSOCIATE**: one UDP socket per association, bound through `Engine::bind_udp` on the
     address the client reached the proxy on, so the engine needs UDP I/O threads
     (`udp_client_threads`); without them the request gets reply 1. Rules: datagrams count as the
     client's only from the control connection's IP and, once fixed by the request or the first
     datagram, from one port; datagrams with a non-zero FRAG are dropped (RFC 1928 allows an
     implementation without fragmentation to drop them); answers from remote hosts are relayed
     only from addresses the client has sent to (endpoint-dependent filtering, so an association
     is not an open inbound port); host-name destinations are resolved on the logical pool and
     cached per association; the association ends with its control connection or after the idle
     timeout, enforced by one sweeper thread per `Socks` (started with the first association,
     250 ms period, exits when the server and its sessions are gone).
3. **Access control: `Socks::allow(Fn(&Request) -> bool)`.** Called after authentication and
   before anything is dialed, bound or resolved, for every command: `CONNECT` (SOCKS5, 4, 4a),
   `BIND`, `UDP ASSOCIATE`, and each distinct destination of an association's datagrams (decided
   once per destination and association, cached). `Request` gives the version, the client's
   address, the user (RFC 1929 name, or SOCKS4 user id), the `Command` and the `Dest` (address,
   or host name not resolved yet). A refusal is reply 2 ("not allowed by ruleset"), 0x5b for
   SOCKS4, a dropped datagram for UDP. `Command` is `#[non_exhaustive]`; `Request` has private
   fields and accessors, so both can grow.
4. **akio-log `Filter` and `init_from_env`.** `Filter` holds a default level and per-target levels
   and parses env_logger-style directives (`info,akio_http=debug,akio_quic::conn=trace`):
   `level`, `target=level`, `target` (= trace). It differs from env_logger in two places, both
   inherited from `FmtLogger::target_level`: a target matches itself and `target::...` only (not
   any string prefix), and the longest match wins regardless of order. `/regex` message filters
   are rejected. `init_from_env(default)` reads `AKIO_LOG` once, installs a `FmtLogger` with the
   filter and sets the global maximum to the filter's most verbose level; unset uses `default`,
   unparsable prints why to stderr and uses `default`. **Opt-in**: nothing reads the environment
   unless it is called, so `init` and the default behaviour are unchanged. `FmtLogger::filter`
   and `init_filtered` take a `Filter` built in code; custom loggers can call `Filter::enabled`.
5. **Compile-time caps: `max_level_*` / `release_max_level_*` features and
   `STATIC_MAX_LEVEL`**, with the `log` crate's names and rules (release features apply without
   `debug_assertions` and win there; with several enabled the most restrictive wins). The macros'
   first check becomes `level <= STATIC_MAX_LEVEL && level <= max_level()`; for a literal level the
   first comparison is a constant, so a statement above the cap is compiled out and without a
   cap feature the code is unchanged.

## Consequences

- Disabled-statement cost unchanged: on macOS the benchmark binary built against this change is
  byte-identical to the one built against the previous commit; on x86_64 (gpu51, quiet host,
  5 alternating rounds, medians) a disabled `trace!` with 2 key-values is 0.400 → 0.401 ns,
  `log_enabled!` 0.402 → 0.401 ns, an enabled `info!` 4.250 → 4.251 ns. With `max_level_info`
  the disabled `trace!` is gone (0.199 ns, the benchmark loop alone).
- Cargo features are unified across the dependency graph: a library that enabled a cap would cap
  every crate of the application, so the docs reserve them for applications. The 12 features are
  left out of CI's feature powerset (it would grow 4096×) and covered by a dedicated test.
- `Config::idle_timeout`, when set, also applies to a UDP association's control connection, which
  carries no bytes while the association is in use; deployments using both should raise it.
- Not done: UDP fragment reassembly, SOCKS4 `BIND`, GSSAPI authentication, a SOCKS client,
  per-association rate limits, env_logger's `/regex` filters and `tracing` spans. Each would be
  additive.
