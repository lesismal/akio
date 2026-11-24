# ADR-111: The HTTP/2 client heeds the response header and idle timeouts and `CancelToken`

English | [简体中文](111-h2-client-header-idle-timeouts-cancel.zh-CN.md)

Status: accepted (2026-11-24)

## Context

ADR-108 (akit's A36, A37) gave akio's HTTP/1 client a request's `response_header_timeout`,
`response_idle_timeout` and `cancel` (`CancelToken`), and left `H2Client` out: it ignored the three
fields. ADR-110 (A51) gave `H2Client`'s requests a reset (`H2Stream::cancel`) and the whole
request's `ClientRequest::timeout`. akit proxies to HTTP/2 upstreams with fit's same header and idle
timeouts and gives a request up when its client goes, wherever the request is; its I17b checked
each h2 stream for its head, its silence and its token on a per-address tick of 100 ms, and gave a
late stream up by retiring its whole connection. akit's request A66 asks `H2Client` to heed the
three fields as `Client` does, checked against akio main `f6750e93`
(`crates/akio-http/src/h2client.rs` read none of them).

Constraints: no new public API (the fields exist; `ClientError::HeaderTimeout`, `IdleTimeout`
and `Cancelled` exist); nothing blocks an I/O thread; a stream's timeouts must not touch the
connection's other streams; per DATA frame, no allocation and no post to another thread.

## Decision

`H2Client::request` and `H2Client::open` heed the request's three fields:

- **`response_header_timeout`** runs from the request's END_STREAM going out (with its HEADERS
  for a request without a body; after its last DATA frame or its trailers otherwise, so a streamed
  body still being written does not count) to the final response's HEADERS (interim 1xx
  responses do not stop it). Past it the stream is reset (`RST_STREAM CANCEL`) and the request
  fails with `ClientError::HeaderTimeout`.
- **`response_idle_timeout`** is the longest gap between the response's DATA frames from its head
  on; the time the stream's reads are held (`H2Stream::hold_reads`, ADR-110) does not count, and
  resuming starts it over. Past it the stream is reset and the request fails with
  `ClientError::IdleTimeout` (after `H2Event::Head` for a streamed request).
- **`cancel`**: a `CancelToken` cancels an `H2Client` request as `H2Stream::cancel` does: the
  stream is reset (`CANCEL`), or a request still waiting for a stream (the server's limit) is
  dropped unsent, and it fails with `ClientError::Cancelled`. A token cancelled already fails the
  request without sending it. One token may cover HTTP/1 and HTTP/2 requests alike.

Each fails the request once (a whole request's callback, or `H2Event::Error`), whichever of
them, `ClientRequest::timeout` and `H2Stream::cancel` comes first, and leaves the connection to
its other streams.

Mechanism:

- **`StreamCtl`** (ADR-110's per-request state) gains the two durations, a phase (none, waiting
  for the head, in the body, over) and the time of the response's last progress (milliseconds on
  a monotonic clock). Two more give-up reasons map to `HeaderTimeout` and `IdleTimeout` through
  the same compare-and-swap, so the first reason wins.
- **Timers.** The I/O thread arms a check on akio-http's timer thread (`crate::timer::after`, the
  one `ClientRequest::timeout` uses) when the phase starts: the header check when END_STREAM goes
  out (`send_upload` notes it; the frame's writer arms it), the idle check when the head comes.
  A DATA frame only stores the time of progress (one atomic store, when an idle timeout is set).
  The check, on the timer thread, does nothing if the phase changed or the stream was given up; an
  idle check whose stream progressed (or is held) re-arms itself for what is left (or the whole
  timeout), so one check is pending per stream at a time. A check that looks due posts to the
  connection's I/O thread, which decides: the phase there is exact (the head may have come
  meanwhile), and it gives the stream up through ADR-110's `stop`, which resets it.
- **The phase ends with the stream**: a stream's state sets the phase to over when it is dropped
  (ended, reset, failed, the connection lost), so a check finds nothing to do, even while an
  `H2Upload` keeps the `StreamCtl` alive.
- **`CancelToken`** keeps its requests as an enum: an HTTP/1 exchange (weak, as before) or an h2
  stream (its `StreamCtl`, weak, and the connection's handle, to post the reset). A token's
  finished requests are pruned as before; an h2 stream is finished once its `StreamCtl` is gone.

Rejected:

- **A timer per DATA frame** (re-arming the idle check on every frame): a heap push and a channel
  send per frame on the I/O thread. The stored time and the lazy re-arm cost one atomic store.
- **The engine's per-connection deadline** (ADR-108's `ConnTimer` for HTTP/1): one deadline per
  connection, and an h2 connection carries many streams with timeouts of their own.
- **Deciding on the timer thread**: the head may arrive between the check and the reset; the I/O
  thread is where the stream's state is exact.
- **The `StreamCtl` holding the connection's handle** (so a token would hold the `StreamCtl`
  alone): the connection's handler owns its streams' `StreamCtl`s, a cycle while a stream lives.
- **Defaults in `H2Options`** (as `ClientOptions::response_header_timeout`): not asked; a caller
  sets them per request. Can come when needed (`H2Options` is `#[non_exhaustive]`).

## Consequences

- akit's I18b drops the per-address tick that checked each h2 stream for its head, its silence
  and its token: a stream given up for one of them is reset, its connection left to the others.
- Costs: `StreamCtl` grows by two `Option<Duration>`s, a byte and a `u64`; a DATA frame reads one
  field and, with an idle timeout, reads the clock and stores it; a request with a header timeout
  arms one timer job, a streamed response with an idle timeout about one per timeout's length; a
  request with a token takes the token's lock once. Without the fields nothing is armed. Not
  measured (rule 20): a benchmark task should A/B h2c request rates with and without both
  timeouts set on the quiet host.
- Tests: `akio-http/tests/h2_client_frames.rs`, against a scripted server: a header timeout resets
  its stream alone (the connection's other request is answered) and does not run while a streamed
  body is still open; an idle timeout lets a response trickling within it through, resets a
  stalled one after its head, and does not fire while the reads are held; a token resets a whole
  request and a streamed one on the same connection once each, and a token cancelled already
  fails requests unsent.
