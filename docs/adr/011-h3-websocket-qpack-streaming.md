# ADR-011: HTTP/3 WebSocket (RFC 9220), QPACK dynamic table and streamed request bodies

English | [简体中文](011-h3-websocket-qpack-streaming.zh-CN.md)

Status: accepted (2026-11-16)

## Context

`akio-h3` served akio-http services over HTTP/3 with three gaps against HTTP/1.1 and HTTP/2
in the same stack and against other HTTP/3 implementations: no WebSocket (RFC 9220 extended
CONNECT), QPACK without a dynamic table (capacity 0 advertised, so peers such as nghttp3
could not compress repeated fields), and request bodies always buffered (a service in
`BodyMode::Stream` worked on HTTP/1 and HTTP/2 but not on HTTP/3, and uploads were bounded by
`max_body_bytes`). The client had no way to stream an upload or open a WebSocket. Closing them
touches the public API of akio-h3, akio-http and akio-ws.

## Decision

1. **WebSocket over HTTP/3, server side, through the existing API.**
   `Context::upgrade_websocket(handler, &WsOptions)` accepts an extended CONNECT with
   `:protocol websocket` on HTTP/3: version 13 and the origin policy are checked as on
   HTTP/1.1, subprotocol and `permessage-deflate` are negotiated the same way, the answer is
   `200` (head only) and the request stream carries the WebSocket from then on, framed by
   akio-ws, with the same `WsHandler` / `WsSender` model. The server always advertises
   `SETTINGS_ENABLE_CONNECT_PROTOCOL`: a request for an unknown protocol is just a request the
   service answers. `Router` answers an extended CONNECT for `websocket` with the path's **GET
   route** (as it answers HEAD with it), so one `.get("/ws", ...)` serves WebSocket over
   HTTP/1.1 and HTTP/3. HTTP/2 (RFC 8441) stays unsupported (400), as before.
   - `Request::protocol: Option<String>` carries `:protocol` (the struct is
     `#[non_exhaustive]`; 24 bytes more per request, see Consequences).
2. **WebSocket over HTTP/3, client side:** `H3Client::websocket(path, &H3WsOptions, handler,
   done)` and `websocket_blocking(..)`. They wait for the server's SETTINGS (RFC 8441 §3),
   fail with `H3Error::Protocol` when extended CONNECT is not allowed and with the new
   `H3Error::Status(u16)` when the server refuses. `H3WsOptions` mirrors
   `akio_ws::client::DialOptions` (config, deflate offer, subprotocols, origin, headers, close
   timeout).
3. **akio-ws gets a transport seam:** `WsSender` writes through either a TCP connection (as
   before) or a `WsLink` trait object (`#[doc(hidden)]`, outside the semver promise like
   `WsSession`), with `WsSession::with_link` / `client_with_link`. The TCP path is an enum
   match, not a virtual call.
4. **QPACK dynamic table (RFC 9204), both directions, settings in `H3Config`** (servers) and
   in `H3ClientOptions` (clients: `H3Client::dial_with(.., H3ClientOptions)`, next to the response limits and the
   request timeout):
   - `qpack_max_table_capacity` (default **4096**) and `qpack_blocked_streams` (default
     **16**) bound what the peer's encoder may do to our decoder: inserts arrive on its encoder
     stream; a field section that needs inserts not yet received waits (its stream's later bytes
     held, re-encoded, in order) up to the blocked-streams limit, beyond which the connection
     fails with `QPACK_DECOMPRESSION_FAILED`. Our decoder stream sends Section
     Acknowledgements, Insert Count Increments and Stream Cancellations. Memory is bounded by
     the capacity per connection plus, for blocked streams, what QUIC flow control lets in.
   - `qpack_encoder_capacity` (default **0**: off) enables this side's encoder table, at most
     what the peer allows. The encoder is conservative: it references only entries the peer
     has acknowledged (Known Received Count), so it never blocks the peer and never uses the
     peer's blocked-streams budget; it inserts fields that repeat (not `:path`, `date`,
     `content-length`, validators, ranges, credentials or cookies), at most a quarter of the
     table per entry, and evicts only entries no unacknowledged section references; it tracks
     at most 1024 unacknowledged sections (past that it stops referencing, so a peer that never
     acknowledges cannot grow its memory). Responses can be sent from any thread, so the
     encoder sits behind a mutex; with the encoder off nothing is locked.
   - **Why the encoder is off by default.** With the decoder on by default, peers that compress
     (nghttp3 in curl, OpenSSL's stack) already save their bytes against us. Turning our
     encoder on saves our bytes (over 20 % of request bytes for repeated custom headers in the
     end-to-end test), but every section that uses the table must be acknowledged on the
     decoder stream (RFC 9204), and every message takes the encoder's mutex: on `quic-bench h3`
     (tiny requests) both encoders on run at 0.82x of the default. It only pays where the
     peer's decoder allows a table, and quic-go, fib and curl advertise 0. A per-connection
     cost for a benefit most peers cannot take is not a good default; it is one setting.
5. **Streamed request bodies, server side, as on HTTP/2.** Request streams are read with a
   reader that never buffers DATA payloads (only an incomplete frame header or HEADERS frame
   is held). A service whose `body_mode` is `Stream` is dispatched at the request's first body
   bytes (so requests without a body never ask) and gets them through `Context::on_body`;
   `max_body_bytes` does not apply to it; `content-length` is still checked (a mismatch resets
   the stream with `H3_MESSAGE_ERROR`). Buffered services keep the previous behaviour. The
   hook is `akio_http::transport::start` / `Started` (the transport module is
   `#[doc(hidden)]`), which also hands the transport the accepted WebSocket.
6. **Streamed uploads, client side:** `H3Client::upload(method, path, headers, cb) ->
   H3Upload` with `write`, `finish` and `queued_bytes` (for pacing), like `H2Client::open`'s
   `H2Upload`; the response is reported to `cb` as for `request`.
7. **New HTTP/3 error codes** in `akio_h3::code`: `QPACK_ENCODER_STREAM_ERROR`,
   `QPACK_DECODER_STREAM_ERROR`.

## Consequences

- `Request` grows by 24 bytes (`protocol`). With the encoder off, `quic-bench h3` runs at the
  previous release's speed: two same-run A/Bs of 7 alternating rounds each on gpu51 (CPUs
  2-5) gave 0.998x and 1.003x, 1.001x over all 14 rounds (883.2k vs 882.7k req/s); cycles
  per request are equal and instructions per request +0.8%. The first complete version
  measured 0.956x. Getting back to parity took static-only decoding for sections without
  dynamic references; whole frames read in place for requests that arrive whole; boxed side
  state for uploads, WebSockets, blocked sections and queued requests that need more than
  their bytes; and keeping the per-request calls inlined (the request is 232 bytes and was
  being copied through every out-of-line call). Exact per-function instruction counts came
  from callgrind (arm64, Docker).
- Against main 2d1f5720, which added the client bounds (response limits, request deadlines) and
  QUIC send caps, the merged branch first measured 0.980x on the same benchmark (842.5k vs
  859.6k req/s), +252 instructions per request on x86 spread over the request path. Four changes
  then took it to 1.025x of main (881.3k vs 859.6k; 1.024x and 1.027x, faster in all 14 rounds;
  x86 callgrind 18525 vs 18826 instructions per request): a request (server) or response
  (client) that arrives whole, as one HEADERS frame and at most one DATA frame, is read without
  the frame reader or per-stream state, falling back to the general path for anything else; the
  client decodes such a response before taking its state lock, then only removes the request;
  request deadlines are kept for consecutive tokens, so finishing one indexes the queue instead
  of a hash set; and a plain request opens its stream under the lock it already holds instead of
  queueing and locking again.
- The server's SETTINGS now carry a 4 KiB table, 16 blocked streams and extended CONNECT, and
  it opens a QPACK decoder stream; peers that compress use the table at once. Interop: quic-go
  (WebSocket over HTTP/3 both ways, streamed uploads both ways; its QPACK has no dynamic table)
  and, in Docker, ngtcp2/nghttp3 and OpenSSL's QUIC through libcurl, whose nghttp3 encoder
  fills our table, against servers with our encoder off and on.
- A fuzz target `qpack_dynamic` covers encoder stream parsing (split-independent), dynamic
  field sections and our encoder against our decoder; `h3_frame` and `h3_request` cover the
  streaming reader, the QPACK streams, blocked sections and extended CONNECT.
- Not done: WebSocket over HTTP/2 (RFC 8441), the Duplicate instruction and dynamic name
  references in our encoder, a streamed response API on the client (`H3Client` still buffers
  responses), server push.
