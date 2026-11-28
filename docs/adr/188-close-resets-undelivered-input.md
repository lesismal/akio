# ADR-188: A connection closed with input it did not deliver resets its peer, on io_uring as on epoll

English | [简体中文](188-close-resets-undelivered-input.zh-CN.md)

Status: accepted (2026-11-28). akit's A302.

## Context

akit gives a FastCGI connection up in the middle of a response when its client went: it calls
`Conn::close` while the application is still writing. On epoll the application learns it at once:
`finalize` shuts the socket down (`shutdown(Both)`) and closes it, Linux finds received data unread
and sends a reset, and the application's next write fails, as Go's `net.Conn.Close` makes it fail in
fit. On io_uring, now and then, the application blocked until the kernel dropped akio's orphaned
socket (`tcp_fin_timeout`, 60 s): `ss` showed akio's side in FIN-WAIT-2 with nothing queued and the
application in CLOSE-WAIT with megabytes unsent against a zero window.

The mechanism, verified on Linux 7.0 (`tests/close_reset.rs`,
`a_close_right_after_resuming_reads_resets_the_peer`, which fails without this change): a multishot
recv that reaches the kernel after `finalize`'s shutdown, submitted with it (reads resumed and the
connection closed in the same round of the loop), or run late (with `DEFER_TASKRUN` a recv's retry
waits until the loop next enters the kernel), still takes what the socket has queued:
`shutdown(SHUT_RD)` does not stop a read of queued data. The loop ignored those completions (the
connection was gone), so the final close found nothing unread and sent a FIN, no reset. And Linux
sends no window update for data read after `SHUT_RD` (`tcp_cleanup_rbuf`), so a peer that had filled
the window kept facing a zero one: the orphan, turned into a FIN-WAIT-2 time-wait socket with the
window it last advertised, answers its probes and never resets it.

## Decision

1. **`Conn::close` keeps one meaning on every backend**: a TCP connection closed with input its
   handler was never given resets its peer, after the FIN the shutdown sends. On epoll that is
   Linux's own rule for a socket closed with input unread. The io_uring backend now gives the same
   result:
   - input read but held (reads paused: `held_in`), or read after the handler closed but before
     the loop's `finalize` ran, sets `SO_LINGER {on, 0}` on the socket at `finalize`;
   - a multishot recv still in flight at `finalize` keeps the connection's socket open
     (`Loop::reads_ending`) until its final completion, with a cancel submitted so that it ends;
     if it took any input meanwhile, `SO_LINGER {on, 0}` is set before the socket is let go. If
     the cancel lands first, the input stays queued and the kernel resets on its own.
   The reset goes out when the socket's last reference goes: at once, or when the last `Conn`
   handle is dropped, as on epoll.
2. **No new API for akit.** `Conn::abort` (option (b) of the request: always reset) is not added;
   a connection that read everything its peer sent still ends with a FIN alone on both backends,
   so a response written before `close_after_send` is not cut by a reset.
3. **akio-sys gets `reset_on_close(&TcpStream)`** (`SO_LINGER {on, 0}`), and its bindings
   `SO_LINGER` and `struct linger` (checked against `libc`).

## Consequences

- akit's FastCGI `cut_connections` passes on io_uring: the application's write is reset as on
  epoll. Nothing changes in akit.
- macOS (kqueue) is unchanged: its stack ends a socket closed with input unread with a FIN, flushes
  that input, and resets the peer's next segment, so a peer still writing is reset there too, one
  segment later. `Conn::close`'s documentation says so.
- Cost on io_uring: closing a connection whose recv is armed pushes one cancel entry (its
  completion is ignored) and keeps the socket's `Arc` in a map until the recv's last completion,
  which the shutdown brings at once. The data path is untouched (one flag test per completion of a
  connection being closed).
- Tests (`crates/akio/tests/close_reset.rs`, both backends): a close in the middle of an upload,
  with the loop busy while the peer fills the window, and with reads held, each resets the writer
  well inside a 20 s deadline; the resume-and-close race resets a peer that stopped writing (Linux);
  a connection that read a whole request and closed after its answer still ends with a FIN.
