# ADR-009: Safe defaults for engine limits and timeouts

English | [简体中文](009-safe-defaults.zh-CN.md)

Status: accepted (2026-11-16)

## Context

[docs/rules.md](../rules.md) (rule 10) requires every resource to have a limit with a safe
default, so that a configuration that sets nothing is still bounded. An audit of the engine
(`only_core::Config`) against that rule found three defaults that left a remote peer in control:

- `write_timeout: None`: a peer that stops reading keeps its connection, and up to
  `max_queued_bytes` (64 MiB) of queued output, forever.
- `udp_max_peers: None`: every datagram from a new source address creates a peer that lives for
  `udp_idle_timeout` (60 s), so spoofed sources grow the table without limit.
- No connect timeout for `Engine::dial`: a SYN to an address that drops it waits for the
  operating system (75–130 s on Linux), and every client built on `dial` (HTTP, h2, gRPC, arpc,
  SOCKS upstreams, BitTorrent) inherits that.

Changing a default changes behaviour for existing configurations, so it is recorded here.

## Decision

1. **`write_timeout` defaults to 60 s** (nginx `send_timeout`). It only fires when queued output
   made no progress for a whole period, so a slow but moving reader is not affected.
2. **`udp_max_peers` defaults to 65536 per listener.** Datagrams from new peers beyond it are
   dropped and counted in `UdpStats::rejected`; known peers are unaffected. Servers that expect
   more concurrent peers per listener raise it.
3. **New `Config::connect_timeout: Option<Duration>`, default 10 s.** A dial still pending after
   it is abandoned on its I/O thread (epoll, kqueue and io_uring; the pending poll is cancelled
   on io_uring) and `on_error` gets `ErrorKind::TimedOut`. `None` restores the old behaviour.
   only-dpdk already had its own 10 s.
4. **`idle_timeout` stays `None` at the engine level.** What "idle" means is protocol specific:
   long-lived RPC or WebSocket connections may legitimately stay quiet, while an HTTP keep-alive
   connection should not. The protocol crates own their timeouts (head read, keep-alive,
   handshake, sniffing) with safe defaults of their own.
5. **`max_connections` stays 0 (no engine limit).** The process's open-file limit already bounds
   accepted connections, and `accept` failing with `EMFILE` backs the listener off instead of
   spinning. A default derived from `RLIMIT_NOFILE` was considered and rejected: UDP peers count
   toward `max_connections` without using a descriptor, so such a default would turn TCP
   connections away on a busy QUIC server. The documentation recommends setting it below the
   open-file limit.

## Consequences

- Configurations built from `Config::default()` are bounded against stalled readers, spoofed
  UDP floods and unanswered dials. Code that relied on a dial waiting longer than 10 s, a peer
  being allowed to stall for more than 60 s, or more than 65536 UDP peers per listener sets the
  field explicitly.
- `Config::connect_timeout` is additive public API (`Config` is `#[non_exhaustive]`).
- Protocol crates follow the same rule for their own resources; the defaults chosen in the same
  change (HTTP, gRPC/arpc, WebSocket, media, QUIC/HTTP/3, KCP, SOCKS, mux, TURN, BitTorrent,
  DTLS) are listed in the CHANGELOG entry "safe defaults everywhere". Two were the user's call:
  SOCKS and HTTP CONNECT refuse non-public destinations by default (open-proxy / SSRF), and
  only-log keeps writing synchronously by default (`FmtLogger::non_blocking` is opt-in).
