# ADR-185: The QUIC server's handshake bounds

English | [简体中文](185-quic-handshake-bounds.zh-CN.md)

Status: accepted (2026-11-27). akit's A245.

## Context

A QUIC handshake costs the server a connection's state, a TLS handshake (a signature) and up to
three times the bytes it received, for one Initial that costs its sender nothing and may come from a
forged address. fit's tunnel hub bounds what handshakes may hold: `handshake_timeout` (10 s) drops a
connection whose handshake is not done in time, and `max_handshakes` (64) bounds those in progress:
past half of them a client proves its address with a Retry first, so Initials from forged addresses
hold at most half, and past all of them a new client's Initial is dropped (it sends it again and gets
in once a handshake is over). akit's hub, on akio-quic, needs the same. akio-quic had
`ServerConfig::max_connections` (every connection, refused with `CONNECTION_REFUSED`), a Retry from
a fixed 4096 handshakes in progress (and always, behind a hidden switch), and no bound on how long a
handshake may take but the idle timeout, which every packet the client sends renews.

## Decision

1. **`ServerConfig::max_handshakes(n)`** (default `DEFAULT_MAX_HANDSHAKES`, 8192; `usize::MAX`
   lifts it; 0 is taken as 1). The endpoint already counts handshakes in progress (from a new
   connection to its `HandshakeDone` or `Drained` event, shared by a server's clones). For a new
   client's Initial, after the accept filter and `max_connections`: at `n` it is dropped, nothing
   kept and nothing sent, and counted in `QuicServer::refused_connections()`; from `n / 2` on, one
   without a valid token (a Retry's, or NEW_TOKEN's) gets a Retry, as before from 4096. The default
   keeps the old threshold (half of 8192) and adds the cap above it. Dropping rather than
   `CONNECTION_REFUSED`: the overload is brief (a handshake takes milliseconds), and the client's
   own retransmission gets it in once there is room, as fit's listener does; a full server stays
   refused with `CONNECTION_REFUSED` through `max_connections`.
2. **`ServerConfig::handshake_timeout(Option<Duration>)`** (default `DEFAULT_HANDSHAKE_TIMEOUT`,
   10 s; `None`: only the idle timeout). A server connection's deadline is set when it is made and
   cleared when its handshake is confirmed (`confirm`, which also tells the endpoint); it is one more
   timer in `poll_timeout`, and on expiry the connection is drained at once, without a
   `CONNECTION_CLOSE`, as on an idle timeout: the handler's `on_close` gets `TimedOut`, the
   endpoint forgets the connection and its place among `max_handshakes`. A timer about time, not a
   retry. A server setting only (see "Not done").
3. **No new counter.** A dropped Initial counts as refused (a client sending it again counts again);
   the documentation of `refused_connections` says both.

## Consequences

- akit's hub maps its QUIC listener's `handshake_timeout` and `max_handshakes` onto these, with
  fit's defaults (10 s, 64) in its own configuration; the time a connection may go without its
  link's stream after the handshake stays akit's (a timer of its own, as fit's `streamWait`).
- Behaviour change: a server's handshakes now end after 10 s by default (before, only the idle
  timeout of 30 s, renewed by every client packet, ended them); and past 8192 in progress new
  clients wait instead of all being taken.
- Cost: one comparison per new client Initial, one more deadline in a server connection's timer
  until its handshake is confirmed; nothing per packet after it. DEV-PLAN section 4 names what a
  benchmark task should measure.
- Tests: akio-quic's simulation (`handshakes_bounded_with_retry_past_half`: straight in under half,
  a Retry then in from half, dropped unanswered at the limit, room again once handshakes end;
  `handshake_timeout_drops_a_stalled_handshake`: a stalled handshake drained with `TimedOut`
  between 2 and 4 s of a 2 s timeout, a completed one kept past it) and `tests/limits.rs` over UDP
  through a relay that stalls handshakes (a stalled handshake gone within the timeout, a completed
  one kept, none dropped without a timeout; with `max_handshakes(2)`, the second client getting a
  Retry and the third waiting until the stalled ones time out, counted as refused).
- Not done: a separate count of handshakes timed out (they end with `TimedOut` like idle
  connections); `INVALID_TOKEN` for a bad Retry token (it is still dropped, as before); a
  handshake timeout on the client side.
