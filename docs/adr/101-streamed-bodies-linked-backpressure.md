# ADR-101: Streamed bodies with linked backpressure: client request bodies as produced, client responses as they arrive, a server request's hold on its reads and drain notice

English | [简体中文](101-streamed-bodies-linked-backpressure.zh-CN.md)

Status: accepted (2026-11-24)

## Context

akit, a reverse proxy built on akio, must forward bodies as they arrive and link the two sides'
backpressure (rules 4 and 8): while the upstream is behind, stop reading the client; while the
client is behind, stop reading the upstream. akit's requests A19, A20 and A21 name what akio-http
lacked for that:

- **A19.** The HTTP/1 client took a request body only whole (`ClientRequest::body: Vec<u8>`,
  encoded with the head and sent with one `send_owned`). A proxy had to hold each upload whole
  before the upstream saw a byte.
- **A20.** The client collected each response body whole, up to `ClientOptions::max_body_bytes`
  (64 MiB), and called back once. A download was held whole, one past 64 MiB failed, and a slow
  client could not slow the upstream down: the connection's reads were never held.
- **A21.** A server handler that streams a request body (`BodyMode::Stream`) got it as fast as
  the client sent it, and a streamed response (`BodyStream`) could only be polled
  (`queued_bytes`). Neither reached the connection's `hold_reads` or `on_drain`. HTTP/2 gave a
  stream's receive window back as DATA arrived, whatever the handler did with it.

akio-core already has both halves per connection (`ConnInner::hold_reads`, `on_drain`, the write
watermarks, `set_relayed`), and akio-quic per stream (`Connection::hold_reads`,
`send_capacity` with `StreamWritable`). Only akio-http's raw connections exposed them.

Constraints: additive API; the whole-body paths behave as before; nothing new blocks an I/O
thread; every queue stays bounded.

## Decision

### A19: a client request body written as it is produced

- **`ClientRequest::streamed: Option<StreamedBody>`**, set by `ClientRequest::streamed(len)`:
  `StreamedBody::Length(n)` sends `Content-Length: n`, `StreamedBody::Chunked`
  `Transfer-Encoding: chunked`. `body` is then not sent, and the request's own
  `Transfer-Encoding` field is dropped. `Client::request` and `Client::send` ignore it.
- **`Client::request_streamed(req, on_ready, done)`**: `on_ready(RequestBody)` runs on the
  connection's I/O thread once the head is queued, after a connect or on a reused connection.
  `done` gets the response whole, as `request` gives it.
- **`RequestBody`** (`Send`): `write(&[u8])` copies into the connection's send queue (a chunk of
  its own when chunked); `queued_bytes()`; `on_drain(f)` (the connection's `on_drain`: `f` runs
  once the queue is empty, or when the connection closes, at once when nothing is queued);
  `finish()` (the last chunk, or a check that the length was written in full) and
  `finish_with_trailers(Headers)` (trailers after a chunked body). Writing past the length, or
  finishing short of it, fails the request. Dropping it unfinished closes the connection.
- While a streamed body is written, the connection is marked a relay end (`set_relayed`): its
  reads do not pause on its own queued output, so an early response (a 413) is still read. The
  producer paces the queue; `Config::max_queued_bytes` refuses writes past it.
- **A response may come before the body is finished**, whole too: `done` (or the handler) gets it,
  the connection is closed once the response is in rather than pooled, and later writes fail.
- **Never retried, never redirected**: the body cannot be sent again. On a reused connection the
  server had closed, the request fails with `Closed` or `Io`, as Go's client does for a body it
  cannot rewind. A 3xx goes to the caller.

### A20: a client response delivered as it arrives

- **`Client::request_with(req, handler: impl ResponseHandler)`**. The trait:
  - `on_request_body(RequestBody)`: the streamed request body, if any (the default drops it, which
    fails the request);
  - `on_head(ResponseHead, ResponseBody)`: status, reason, fields and version, interim 1xx
    responses skipped;
  - `on_data(&[u8])`: each piece of the body as read, dechunked, valid for the call (rule 5);
  - `on_end(&Headers)` with a chunked body's trailers, or `on_error(ClientError)`. After the head
    exactly one of them follows.
- **`ResponseBody`** (`Clone`, `Send`): `hold_reads(bool)` holds and resumes the connection's
  reads; `cancel()` closes it (the handler then gets `on_error(Closed)`). Both do nothing once the
  response is over, and the hold is released before the connection goes back to the pool.
- `ClientOptions::max_body_bytes` does not apply; the handler decides. Redirects are not
  followed. The request timeout runs until `on_end`. Cookies are stored from the head when the
  client has a jar. A retry on a fresh connection happens as for `request`: only for `GET`,
  `HEAD` or `OPTIONS` without a streamed body, before any response byte.
- `request_streamed` is `request_with` with a handler that collects the response whole within
  `max_body_bytes`; `request` and `send` keep their own path, unchanged.

### A21: a server request's hold on its reads, and a streamed response's drain notice

- **`Context::body_reads() -> Option<BodyReads>`**, for a request whose body is streamed
  (`BodyMode::Stream`, HTTP/1.1, HTTP/2 and HTTP/3 alike). It reads the responder, so it is taken
  before `detach` or `stream_response`; the handle is `Clone`, `Send` and works after them.
  `BodyReads::hold(bool)`:
  - **HTTP/1.1** holds the connection's reads, and so the pipelined requests behind, as it must.
    The hold ends with the body (the next request's reads are not the handler's), and the body
    timeout does not fire while reads are held: the client is not the slow one.
  - **HTTP/2** stops giving the stream's receive window back (what is owed is given back on
    resume), so the client stops once the window it has (1 MiB by default) is used while the
    other streams go on.
  - **HTTP/3** goes through a new `ConnSink::hold_reads(tag, hold)` (default: nothing); akio-h3
    holds the QUIC stream (`Connection::hold_reads`).
  - Bytes already read are still delivered: at most one read's worth on HTTP/1.1, what is in
    flight within the window on HTTP/2 and HTTP/3.
- **`BodyStream::on_drain(f)`**: `f` runs once the response's queued bytes are out of the way, or
  when the connection or stream is gone, at once (on the calling thread) when they already are,
  otherwise on the connection's I/O thread. It replaces an earlier waiter.
  - **HTTP/1.1**: the connection's send queue is empty (akio-core's single `on_drain` waiter per
    connection, which one streamed response at a time owns).
  - **HTTP/2**: the stream's queued bytes were all framed, as its flow-control window let them;
    the peer's window bounds the rest. The waiter is run outside the core's lock: a waiter is
    dropped, and a drop runs it, only where streams are dropped (`Locked`).
  - **HTTP/3**: a new `BodySink::on_drain` (default: run at once); akio-h3 runs it when the
    stream's send buffer has room again (`send_capacity`, `StreamWritable` at three quarters of
    the buffer), when the stream is stopped, or when the connection closes.

Rejected:

- **A low-watermark `on_drain` on the client or HTTP/1.1.** akio-core's `on_drain` fires on an
  empty queue; a second, lower threshold would be a core change for no measured gain. A producer
  pauses above its own watermark and resumes on the drain.
- **Retrying a streamed request on a fresh connection by holding its body until the response
  head.** Servers that read the body before answering would deadlock; Go does not either.
- **Holding the rest of a read on HTTP/1.1** (keeping already-read bytes until resume): a resume
  with nothing new to read would never deliver them. One read is bounded by the read buffer.
- **`H2Client` streaming in this change.** akit's I18 (h2 upstreams) is later; the same handler
  trait can be added to `H2Client` then.
- **An idle timeout between response reads** (fit's `response_idle_timeout`, A20's last point).
  It belongs with akit's I17, and needs the read-gap clock to stop while the handler holds reads.

## Consequences

- akit's I16 can forward bodies as they arrive with linked backpressure on HTTP/1 upstreams:
  client body → `RequestBody` paced by `queued_bytes` / `on_drain`, the client's reads held with
  `BodyReads`; upstream response → `ResponseHandler`, the upstream's reads held with
  `ResponseBody::hold_reads` while the client's `BodyStream::queued_bytes` is high, resumed from
  `BodyStream::on_drain`.
- The whole-body client paths are unchanged in behaviour. `ClientConn` carries three more
  fields per request; HTTP/2's lock release checks one more vector. Neither was measured (rule
  20): a benchmark task should A/B `client-bench` and h2c on the quiet host, and measure a
  proxy-style relay with streamed bodies against whole ones (DEV-PLAN section 4).
- Tests: `akio-http/tests/stream_bodies.rs` (chunked and length request bodies paced by drains,
  trailers, too long, too short and dropped bodies, an early 413 while the body is written,
  responses delivered as they arrive with reads held and resumed past the client's body limit,
  trailers, cancel, connection reuse, both ways at once; the server's held body on HTTP/1.1 with
  a body timeout shorter than the hold and on HTTP/2 with another stream going on, paced
  downloads on both) and `akio-h3/tests/body_reads.rs` (a held body bounded by the stream window,
  a download paced by drain notices).
