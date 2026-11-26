# ADR-157: Responses that close their connection or carry their length, request bodies a middleware bounds

English | [简体中文](157-http1-close-length-body-limit.zh-CN.md)

Status: accepted (2026-11-26)

## Context

Four of akit's requests ask akio-http for what fit's Go server gives its handlers:

- **A24.** A service that refuses a request before reading its body (a `413` for a body past a
  limit, a `401` without the token) cannot close the HTTP/1 connection after its answer: keep-alive
  was decided from the request alone, a `Connection: close` the service set was sent but not
  honoured, and the rest of the body was read (to a sink no one reads, or discarded) until the
  body timeout. A fast client could make the server read an unbounded body it had refused, and
  try again on the same connection.
- **A49.** fit's `body_limit` bounds a body for whatever handler reads it. In akio-http only the
  listener's `max_body_bytes` bounded a buffered body; a streamed one (`BodyMode::Stream`) went to
  the handler's sink unbounded, and a middleware could neither see nor wrap that sink.
- **A35.** A streamed HTTP/1.1 response was always chunked on a keep-alive connection; a
  `Content-Length` given with it went out beside `Transfer-Encoding: chunked` (invalid), so akit
  dropped it: a proxied download lost its length, and its client could not tell a body cut short.
- **A148.** A handler saw the request's peer but not the address it came to (CGI's `SERVER_ADDR`
  and `SERVER_PORT`, for akit's FastCGI handler).

## Decision

**A response's `Connection: close` is honoured on HTTP/1 (A24).** `Response::encode` reports
whether the response's own `Connection` field holds the `close` token (it already scans the
fields; no extra pass on the hot path). Such a response, from `respond`, a `Detached`, a held head
or a streamed head, closes the connection once it is written, whatever the request asked, and the
connection's reads are held (`hold_reads`): the rest of a body the service refused is not read.
A whole response holds the reads as it is sent; a streamed one when it finishes, so a handler that
streams its answer while it still reads the request (a relay) keeps its body until then. When the
response was sent inline from the handler, the session also stops: a request whose body was
streaming drops its context and sink (no more delivery), and the requests pipelined behind it are
not parsed. There is no separate `close_after_response()`: the field is how HTTP says it, the
encoder sees it, and HTTP/2 and HTTP/3 already drop it as a connection-specific field.

**`Context::limit_body(&mut self, max: u64) -> bool` (A49).** It lowers the request's body bound
(a second call keeps the lower). A body already here (buffered, or none) longer than `max` is
answered `413` at once, the connection kept. For a streamed body the context counts the bytes it
delivers to the sink; a declared `Content-Length` over `max`, or more than `max` delivered, refuses
the body now, and a body that grows past it later is refused then. Refused:

- the sink gets the new `BodyEvent::TooLarge` and is dropped (nothing more, not `End`);
- the request is answered `413` when the context still holds its response; a handler that took it
  (`detach`, `stream_response`) answers itself, as its sink tells it;
- HTTP/1: the `413` says `Connection: close` (so A24 applies); the session drops the context, holds
  the reads, and reserves a close after the responses before (the handler's own answer included);
- HTTP/2: the stream's context is not parked again (later DATA goes nowhere) and the stream gives
  no more window; once the response is done the stream is reset with `NO_ERROR`, as for any
  response sent before its request ended;
- HTTP/3: `Started::body_refused` tells the transport, which sends `STOP_SENDING` with
  `H3_NO_ERROR` and discards what still arrives.

`limit_body` returns `false` when the request was refused: the middleware does not call the
handler. The error is a new variant rather than an `Err` beside `Chunk` and `End` because a sink
already matches on the event; `BodyEvent` stays exhaustive (an event enum, docs/api-stability.md),
so adding the variant breaks exhaustive matches, which is allowed before 1.0.0 and noted in the
changelog.

**A streamed HTTP/1 response framed by its length (A35).** `stream_response` takes the
`Content-Length` its head gives (every value parsing and agreeing, a status with a body, no
`Transfer-Encoding`) as the body's framing. The framing settles in `open_stream`, after the
response filters ran: a stream coding a filter set (`Response::set_stream_coding`) drops the field
(the encoded body is not that length), as do body filters (ADR-128), which change the body; without
a length the body is chunked on keep-alive HTTP/1.1, close-delimited otherwise, as before. A sized
body is written as it comes, its remaining length counted atomically (writes may come from any
thread): a write past it is refused whole with `Error::Io(InvalidInput)`, nothing of it written;
`finish` on a body short of its length closes the connection (a body cut short must), and the
request ends `End::Gone` with its tap told `TapEnd::Cut`. `HEAD` answers keep the field and send
no body. HTTP/2 and HTTP/3 frame the body themselves and keep the field. A separate
`stream_response_sized(status, headers, len)` was considered; the field in the head is what is
sent and what filters see, so reading it there needs no second way to say the same.

**`Request::local: SocketAddr` and `Context::local_addr()` (A148).** Filled as `peer` is: the
connection's local address on HTTP/1.1 and HTTP/2, the UDP socket's on HTTP/3 (a new
`akio_quic::Connection::local_addr`, recorded when the server accepts the connection), unspecified
where there is none. It is the socket's address, not a PROXY header's destination.

## Consequences

- A refused body is no longer read: under the old behaviour only the body timeout bounded it.
  Closing with unread bytes in the receive buffer may make the kernel send a reset that the client
  sees before the answer; the server does not linger (Go waits half a second): a client that keeps
  sending without reading may miss the `413`. Clients that send the head and wait (or use
  `Expect: 100-continue`) get it.
- A `Detached` that answers `Connection: close` while its request's body still streams holds the
  connection's reads; the handler's `BodyReads::hold(false)` could resume them before the close.
- Every `match` on `BodyEvent` outside akio-http needs a `TooLarge` arm (akit: its sinks).
- `Context` grows by two `u64` and three flags, `Request` by a `SocketAddr`; `Out` stays 24
  bytes. The per-chunk cost is one add and one compare. Not measured yet: DEV-PLAN section 4 has
  the row and what to measure.
- Tests: `akio-http/tests/body_limit.rs` (A24, A49 on HTTP/1 and HTTP/2, A148),
  `akio-http/tests/sized_stream.rs` (A35), `akio-h3/tests/limit_body.rs` (A49, A148 on HTTP/3),
  on kqueue, epoll, io_uring and work stealing.
