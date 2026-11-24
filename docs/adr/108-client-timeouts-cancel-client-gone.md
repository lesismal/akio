# ADR-108: The HTTP/1 client's response header and idle timeouts and its cancellation, a server request that hears its client go, and a write timeout changed at run time

English | [简体中文](108-client-timeouts-cancel-client-gone.zh-CN.md)

Status: accepted (2026-11-24)

## Context

akit, a reverse proxy built on akio, bounds an upstream exchange as fit does: how long the
upstream may take to begin its response (`response_header_timeout`, answered 504), how long it
may go silent mid-body (`response_idle_timeout`, the response cut short), the exchange in all
(`response_timeout`), and how long a client may leave a response unread (`write_stall_timeout`).
It also gives an upstream request up when its client goes (fit's `OnCancel`). akit's requests A36,
A37 and A38 name what akio lacked for that:

- **A36.** The HTTP/1 client had one timeout per request (`ClientRequest::timeout`, until the
  response's end). A proxy could not answer 504 for an upstream slow to begin while letting a long
  download run, nor cut off an upstream that stalls mid-body. ADR-101 left the idle gap out: it
  needs the clock to stop while the handler holds the reads.
- **A37.** A request whose body went whole had no handle before its response's head:
  `Client::request` and `request_with` return nothing, `ResponseBody::cancel` comes with the head.
  A client that went while the upstream thought left the upstream working, and a connection and a
  `max_conns` slot taken, until it answered or the request timeout passed.
- **A38.** A detached request (`Context::detach`) heard nothing of its client going until it
  wrote. On HTTP/1 a request whose body streams kept its body sink while the client went: the
  session held the context in its state, and the connection stayed open for the response owed
  (EOF only queues a close after the responses). And `Config::write_timeout` was fixed when the
  engine was built, so akit could not apply `write_stall_timeout` on reload.

Constraints: additive API (a function's return type is part of it, `docs/api-stability.md`); the
existing paths behave as before; nothing new blocks an I/O thread; nothing grows without a bound.

## Decision

### A36: response header and idle timeouts (akio-http client)

- **`ClientRequest::response_header_timeout` and `response_idle_timeout`** (`Option<Duration>`,
  builders of the same names), defaulting to the new **`ClientOptions::response_header_timeout`
  and `response_idle_timeout`** (`None`). fit's names: `ClientOptions::idle_timeout` is already the
  pool's.
- **The header timeout** runs from the request written whole (its last byte queued: with the head
  for a body given whole, at `RequestBody::finish` for a streamed one, so a long upload does not
  count) to the final response's head; interim 1xx responses do not stop it (Go's
  `ResponseHeaderTimeout` neither). Each redirect hop has its own.
- **The idle timeout** is the longest gap between two reads of the body, from its head on. While
  the handler holds the reads (`ResponseBody::hold_reads(true)`) it is stopped; resuming re-arms
  it, and reads delivered while held do not re-arm it.
- Past either, the request fails with the new **`ClientError::HeaderTimeout`** or
  **`ClientError::IdleTimeout`** (after `on_head` for a handler) and its connection is closed; a
  whole response's callback gets the error. `ClientError::is_timeout()` covers the three
  timeouts. The request timeout still runs as before.
- **Mechanism.** One deadline per connection, the server's (`deadline::Watch`: a relaxed store
  to arm, one sweeper thread, the expiry posted to the I/O thread), registered the first time a
  request on the connection has either timeout. The phases follow each other (head, then body), so
  one deadline serves both; an atomic phase written after the deadline when arming and before it
  when disarming tells a stale expiry (re-armed, disarmed, or left from the request before on a
  pooled connection) from a real one. The I/O thread re-arms on each body read; `finish` and
  `hold_reads` arm from their threads; the head's arrival and `finish` are ordered under the
  streamed body's lock.

### A37: cancelling a request at any point

- **`CancelToken`** (`Clone`, `Send`, `Sync`, `Default`): `new`, `cancel`, `is_cancelled`, given
  to a request with **`ClientRequest::cancel_with(&token)`** (field `ClientRequest::cancel`).
  `request`, `request_with`, `request_streamed` and `send` keep their signatures.
- Cancelling: a request not yet sent is dropped (a token already cancelled fails it at once, and
  nothing is dialed); one sent has its connection closed. It fails with the new
  **`ClientError::Cancelled`**, once, unless it was over: a whole response's callback is called on
  the cancelling thread (as the timeout's runs on the timer thread), a handler gets `on_error` on
  the connection's I/O thread, or, before there is a connection, where the resolve or dial ends.
- One token may serve several requests (a proxy's retries): cancelling it cancels each that is not
  over. The token keeps weak references, pruned of finished requests as it grows.
- Implemented on the exchange that already carried the request timeout: it now records why it
  gave up (timeout or cancel), and every place that checked the timeout reports that reason.

### A38: a server request that hears its client go; a write timeout changed at run time

- **`Context::on_gone(f)` and `Detached::on_gone(f)`**: `f` runs once if the client goes before
  the response is finished, on the connection's I/O thread, or at once on the calling thread when
  that already happened. It replaces an earlier `f`, carries over from the context to `detach` and
  to a streamed response (`BodyStream`), and is dropped unrun once the response is sent whole or
  finished (a `BodyStream` dropped unfinished closes the connection, which counts as gone).
  - **HTTP/1**: the connection closes or the client finishes sending (EOF). A client that
    half-closes after its request is taken as gone, as Go's server cancels a request's context on
    the read that ends. Mechanism: **`ConnInner::on_peer_gone(key, f) -> bool`** and
    **`forget_peer_gone(key)`** in akio-core, run when the peer's EOF is read
    (`close_after_responses`) or the connection is marked closed. The key is the response's slot
    number (`ResponseSlot::seq`), so the responder keeps a flag in its padding (`Option<Out>`
    stays 24 bytes, ADR-025) and forgets the callback when it sends.
  - **HTTP/2**: the stream is reset by the client or dropped with its connection before our
    END_STREAM went out. The callback is a drop-run waiter on the stream (as ADR-101's drain
    waiter), disarmed when the stream closes after our END_STREAM, so it runs outside the core's
    lock.
  - **HTTP/3** and other transports: the new **`ConnSink::on_gone(tag, f)`**, whose default drops
    `f` unrun (a transport that cannot tell never calls it). akio-h3 runs it on the client's
    RESET_STREAM of the request stream, its STOP_SENDING of the response, or the connection's
    close, and forgets it when the response is sent or finished (a map checked only once a
    callback was ever registered on the connection).
- **The HTTP/1 session drops a streamed request's context, and its sink, when the connection
  closes**, as HTTP/2 drops a closed connection's streams; and it closes the connection when the
  client's EOF comes mid-body (the body cannot complete, and a detached handler waiting on it
  would hold the connection until the body timeout).
- **`Live::set_write_timeout(Option<Duration>)`** and `Live::write_timeout()`, applied by
  `Telemetry::reload` / `Engine::reload` (now in `applied`, no longer in `ignored`). The epoll and
  io_uring loops read it where they read `Config::write_timeout`: a check already pending runs as
  armed and re-arms with the new value; `None` stops the checks at the next one; a value set again
  arms at the next write that queues output. A check that found the timeout off no longer leaves
  its timer marked pending.

Rejected:

- **`request` and `request_with` returning a handle.** A changed return type is a breaking change
  under `docs/api-stability.md` (`|| client.request(..)` as an `FnOnce()` would stop compiling),
  and a token handed in also covers retries and later transports without new entry points.
- **A timer job per arm on the client's timer thread** (`crate::timer`): re-arming the idle timeout
  per read would push a heap entry per read. The server's deadline costs a store.
- **Starting the header timeout when the head is queued for a streamed body.** A proxy streams an
  upload for as long as its client sends; most servers answer after the body.
- **`BodyEvent::Aborted`** for a cut HTTP/1 body: `BodyEvent` is not `#[non_exhaustive]`, so a
  variant would break exhaustive matches. The sink is dropped instead, as on HTTP/2.
- **`H2Client` in this change.** akit's I18 (h2 upstreams) is later; the same request fields apply
  to it then. `H2Client` ignores them, as it ignores `ClientRequest::streamed`. (Its streamed
  requests are reset and timed since by ADR-110; the header and idle timeouts and `CancelToken`
  are still not applied to it.)

## Consequences

- akit's I17b can set `response_header_timeout` and `response_idle_timeout` per proxied request
  (504 on `HeaderTimeout`, a cut response on `IdleTimeout`), give every upstream request a
  `CancelToken` cancelled from `on_gone` (and not count it against the upstream's health), and
  apply `limits.write_stall_timeout` with `Live::set_write_timeout` at start and on reload.
- Costs: `ClientConn` carries one more `Option<Arc>` and an `Option<Duration>`, and checks one
  branch per read; a request carries three more fields. HTTP/1's responder keeps its size, an
  HTTP/2 stream grows by one `Option<Waiter>`, akio-core's per-connection write state by a `Vec` and a
  counter; a streamed HTTP/1 request registers one peer-gone callback (a lock and a push), and an
  akio-h3 response reads one atomic. None of it was measured (rule 20): a benchmark task should
  A/B `client-bench`, HTTP/1 pipelined and streamed-body serving, h2c and h3 on the quiet host.
- Tests: `akio-http/tests/client_cancel.rs` (a head that never comes, a long body under a short
  header timeout, a stalled body, reads held past the idle timeout, a streamed body's header
  timeout from its finish, deadlines on a reused connection, cancels before sending, awaiting the
  head, mid-body, for several requests and after the end), `akio-http/tests/on_gone.rs` (HTTP/1:
  a detached request, answered and streamed responses, a callback registered after the client
  went, an upload cut short and its sink; HTTP/2: a stream reset and the connection closed),
  `akio-h3/tests/on_gone.rs` (the connection closed) and `akio/tests/reload.rs` (the write timeout
  turned on and off at run time).
