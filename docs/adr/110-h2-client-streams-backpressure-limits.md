# ADR-110: The HTTP/2 client's streamed requests reset, timed and ended with trailers; backpressure per stream; the server's stream limit, `GOAWAY`, the connect timeout and ALPN

English | [简体中文](110-h2-client-streams-backpressure-limits.zh-CN.md)

Status: accepted (2026-11-24)

## Context

akit, a reverse proxy built on akio, proxies to HTTP/2 upstreams (h2 and h2c) on akio's
`H2Client`, streaming each exchange as it streams an HTTP/1 one (ADR-101, ADR-108). Its I18 did it
with stopgaps; akit's requests A51, A52 and A53 name what `H2Client` lacked, checked against akio
main `4f7169c4` (`crates/akio-http/src/h2client.rs`):

- **A51.** A streamed request (`H2Client::open`) returned an `H2Upload` with `write` and `finish`
  alone: it could not be reset (`H2Conn::cancel` was private, reached by `request`'s timeout only),
  `open` ignored `ClientRequest::timeout`, and the body could not end with trailers (gRPC's). On a
  `GOAWAY`, the streams above its last stream id were dropped with a whole request's callback failed
  but a streamed request's `on_event` never told; and `is_open` stayed `true` while every new stream
  failed `Closed`.
- **A52.** Rule 8 links backpressure. The client gave each stream's receive window back as soon as
  DATA arrived (`window_update` on every frame), so a slow consumer could not slow the server; and
  `H2Upload::write` queued without bound and reported nothing.
- **A53.** The client ignored `SETTINGS_MAX_CONCURRENT_STREAMS` (setting 3), so a pool could not
  size a connection, and a request past the limit was refused by the server. `connect` raced
  addresses with `HappyEyeballs::default()` (a fixed 10 s connect timeout). Over TLS the client spoke
  h2 whatever ALPN chose.

Constraints: additive API (`docs/api-stability.md`: no signature changes; `H2Options` and
`ClientError` are `#[non_exhaustive]`); nothing new blocks an I/O thread; every queue is bounded.

## Decision

### A51: reset, timeout, trailers, `GOAWAY`

- **`H2Stream`** (`Clone`, `Send`, `Sync`), from **`H2Upload::stream()`**: `cancel()`,
  `hold_reads(bool)` (A52) and `id()`. **`H2Upload::cancel()`** is `stream().cancel()`.
- **Cancel**: the stream is reset (`RST_STREAM CANCEL`) and `on_event` gets
  `H2Event::Error(ClientError::Cancelled)`, once, on the connection's I/O thread, unless the stream
  was over or a timeout gave it up first. A request still waiting for a stream (A53) is dropped
  unsent. Later writes fail.
- **Timeout**: `open` arms `ClientRequest::timeout` as `request` does: past it the stream is reset
  (`CANCEL`) and `on_event` gets `Error(ClientError::Timeout)`, unless it was over. The timer holds
  the stream's state weakly.
- **Mechanism.** Each request (`request` and `open`) has a `StreamCtl` (`Arc`): its stream id (0
  until it starts), why it was given up (one compare-and-swap, so a cancel and a timeout fail it
  once) and the hold flag. The cancel or timeout sets the reason and posts to the I/O thread, which
  resets the stream if it is still the request's, or drops it from the waiting queue. The post and
  the request's start are separate `spawn_blocking` continuations, which are not ordered: a start
  that finds a reason already set fails the request without sending it. `request`'s timeout uses
  the same path, so a request timed out before it started is no longer sent afterwards.
- **Trailers**: **`H2Upload::finish_with_trailers(Headers)`** ends the body with a HEADERS frame
  carrying `END_STREAM` after the last DATA (none with `END_STREAM`). Names are lowercased;
  pseudo-fields and connection-specific fields are dropped; with none left it is `finish`. HPACK
  encodes them on the I/O thread when they are sent, in frame order.
- **`GOAWAY`**: the streams above its last stream id fail with the new **`ClientError::Refused`**
  (the server did not process them; they may be sent again elsewhere): a whole request's callback
  and a streamed request's `on_event` alike. Requests waiting for a stream, and requests made after
  the `GOAWAY`, fail `Refused` too. A stream reset with `REFUSED_STREAM` is `Refused` (was
  `Protocol("stream refused")`). **`H2Client::is_open`** is `false` once a `GOAWAY` came or
  `close` sent one.
- **A response that ends before its request body** (an early answer, a gRPC server's trailers): the
  stream is reset (`CANCEL`), as Go's transport does, rather than left half-open on the server, and
  the body's writes fail from then on. Writes already fail when `on_event` hears `End` or `Error`:
  the stream's hold on the body is dropped first.

### A52: backpressure per stream

- **Receiving**: `H2Stream::hold_reads(true)` stops giving the stream's receive window back: DATA
  frames add to what is owed instead of sending `WINDOW_UPDATE`. DATA already in flight still
  arrives and is handed over, at most one window (`H2Options::initial_window`, 1 MiB by default).
  `hold_reads(false)` gives back what is owed at once. The connection's window is still given back
  as DATA arrives, so the connection's other streams go on (as the server side, ADR-101).
- **Sending**: **`H2Upload::queued_bytes()`** (written, not yet in a DATA frame: in the shared queue
  or the stream's), **`H2Upload::on_drain(f)`** (`f` runs once that falls to 0 or the stream is
  over: at once on the calling thread when it already is, otherwise on the I/O thread; one waiter,
  replaced), and **`H2Upload::try_write(&[u8]) -> akio::Result<()>`**: `Err(Closed)` when the
  stream is over, the body finished or the connection gone, `Err(Overloaded)` past the new
  **`H2Options::max_queued_bytes`** (64 MiB; a write is taken whatever its size when nothing is
  queued, as the WebSocket link's). `write` stays `-> bool`, now `try_write(..).is_ok()`. Writes
  are batched: one post to the I/O thread per batch, not per write.

### A53: the server's stream limit, the connect timeout, ALPN

- **`H2Client::max_concurrent_streams()`** (the server's latest `SETTINGS_MAX_CONCURRENT_STREAMS`,
  `u32::MAX` until it says), **`open_streams()`** (streams this client opened that are not over:
  requests, streamed requests and WebSockets; not pushes) and **`waiting_streams()`**.
- **A request past the limit waits in the client**, in order, and starts as streams end or the
  limit rises; at most the new **`H2Options::max_pending_streams`** (1024) wait, and past it a
  request fails at once with the new **`ClientError::Busy`**. `0` makes every request past the
  limit fail `Busy` (the caller chooses: queue, or dial another connection). A waiting request's
  timeout and cancel apply. WebSockets count against the limit but do not wait.
- **The connect timeout**: the new **`H2Options::happy_eyeballs`** is what `connect` races with
  (its `connect_timeout`, 10 s by default), as `ClientOptions::happy_eyeballs` for HTTP/1 (A12).
  `dial` keeps the engine's.
- **ALPN**: over TLS, `dial` and `connect` call `ready` once the server's first bytes came (its
  SETTINGS: `max_concurrent_streams` is then known), after checking that ALPN chose `h2`. When it
  did not (another protocol, or none), the connection is closed and `ready` gets an `io::Error`
  (`Unsupported`) whose inner error is the new **`NotH2 { alpn }`** (`NotH2::of(&e)`); a caller
  falls back to HTTP/1.1 (`akio_http::client::Client`). A connection closed before that reports
  the handshake's failure, or `NotH2` when the handshake chose another protocol. Prior knowledge
  (no TLS) calls `ready` on connect, as before.

Rejected:

- **`connect_with(engine, host, port, tls, opts, HappyEyeballs, ready)`** (A53's suggestion): the
  race belongs in `H2Options`, as it is in `ClientOptions`; one entry point less.
- **`ready` given `enum { H2(H2Client), Http1(Conn) }`**: the connection's handler is the h2 one
  from `on_open` on, and akio-http's HTTP/1 client dials and pools its own connections. A fallback
  costs a second handshake, once per address a caller remembers.
- **`H2Stream::consume(n)`** (A52's option): a proxy holds and resumes; a window given back as bytes
  are handed on can come later if a caller needs it.
- **Leaving `write` unbounded and bounding `try_write` alone**: an unbounded queue breaks rule 4.
  The 64 MiB default is the buffered body limit's, so a producer that wrote whole bodies through
  `open` before keeps working.
- **Resetting the stream when an unfinished `H2Upload` is dropped** (as `RequestBody`'s drop
  closes its connection): a caller that drops it while the response still streams, without
  finishing, would see its request reset where it was not before. Left as it was; `cancel` resets.
- **`CancelToken` and the response header and idle timeouts (ADR-108) on `H2Client`**: not asked
  by A51–A53. `H2Stream::cancel` and `ClientRequest::timeout` cover akit's I18b; the others can
  reuse `StreamCtl` (a third reason) when needed. (Done since by ADR-111, for akit's A66.)
- **Holding the connection's window too**: one held stream would stop the connection's others.

## Consequences

- akit's I18b drops its stopgaps: a stream given up is reset instead of retiring its connection,
  `open`'s timeout replaces the per-address tick, request trailers go up, a `GOAWAY` fails its
  doomed streams `Refused` (502 or a retry) and retires the connection (`is_open`), downloads are
  held with `hold_reads` (no `HELD_LIMIT`), uploads paced by `queued_bytes` / `on_drain`,
  connections sized by `max_concurrent_streams`, dials bounded by `happy_eyeballs`, and `h2`
  upstreams fall back to HTTP/1.1 on `NotH2`.
- Behaviour changes, all for the better but visible: `REFUSED_STREAM` and `GOAWAY`'d requests fail
  `Refused` (not `Protocol` / `Closed`); requests after a `GOAWAY` fail `Refused`; `is_open` is
  `false` after a `GOAWAY`; requests past the server's limit wait instead of being refused by it;
  `H2Upload::write` and `finish` return `false` once the stream is over; a TLS dial's `ready` comes
  after the server's first frame.
- Costs: every request allocates a `StreamCtl` (it allocated an `Arc<AtomicU32>` before); a stream
  carries five more fields; a DATA frame reads one atomic; `on_data` ends with a check of an empty
  vector and of the waiting queue. Not measured (rule 20): a benchmark task should A/B h2c
  `client-bench`-style request rates and a streamed upload/download on the quiet host.
- Tests: `akio-http/tests/h2_client_frames.rs` (against a scripted server: cancel resets once, a
  cancel racing the start, a timeout, request trailers, a response before the body ends, `GOAWAY`
  refusing streamed requests, held reads keeping the stream's window closed while the connection's
  comes back, an upload queue bounded and drained, the server's stream limit with a request waiting
  and one refused `Busy`; the `REFUSED_STREAM` / `GOAWAY` test now expects `Refused`) and
  `akio-http/tests/h2.rs` (a TLS dial knows the server's limit; a TLS server choosing `http/1.1`
  fails the dial with `NotH2`).
