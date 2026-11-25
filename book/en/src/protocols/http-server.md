# HTTP/1.1 and HTTP/2 servers

`akio-http` serves HTTP/1.0, HTTP/1.1 and HTTP/2 with one programming model: a `Service` gets a
`&mut Context` for each request, on the connection's I/O thread.

## Serving

```rust,ignore
{{#include ../../../../crates/akio-http/examples/guide-http.rs:serve}}
```

`serve(service)` / `serve_with(HttpConfig, service)` return an `HttpAcceptor`: serve it on a
listener directly, or wrap it in `Tls::server` for HTTPS. `HttpConfig`:

| Field | Default | Meaning |
|---|---|---|
| `max_header_bytes` | 64 KiB | request line + headers; larger gets 431 |
| `max_body_bytes` | 1 MiB | buffered request body; larger gets 413 |
| `h2` | `Some(H2Config::default())` | HTTP/2 settings, `None` for HTTP/1 only |
| `head_timeout` | 10 s | from the first byte of a request head to its end (from the connection start for the first one), so a peer trickling bytes cannot hold a half-received head (slowloris); 408 and close. HTTP/2: until the client's `SETTINGS` (GOAWAY `SETTINGS_TIMEOUT`) |
| `keep_alive_timeout` | 75 s | wait for the next request; responses still being prepared are sent before the close. HTTP/2: no frame for this long and no open stream, then GOAWAY |
| `body_timeout` | 60 s | no progress on a request body for this long: 408 (a streamed HTTP/1 body is cut). HTTP/2: buffered uploads only (streamed ones, gRPC streams say, are paced by their service) |
| `idle_drain_grace` | 250 ms | on a drain (`shutdown_listener`, `shutdown`), an idle HTTP/1 connection stays open this long for a request its client may have sent already, answered with `Connection: close`; capped by the drain's deadline. `Duration::ZERO` closes it at once |

Each timeout is `None` to disable it. They are checked by one sweeper thread per process at a
fraction of the shortest timeout (5 ms to 1 s), so they fire between the timeout and two ticks
after it, never early.

`H2Config`: `max_concurrent_streams` (128), `initial_window` (1 MiB per stream),
`conn_window` (16 MiB), `max_header_list` (64 KiB), `max_body_bytes` (1 MiB, buffered bodies),
`max_pending_bytes` (8 MiB a response may hold back for a slow peer before writers get
`Overloaded`), `max_conn_pending_bytes` (32 MiB of response bodies held in memory over all the
connection's streams; past it a response is reset with `ENHANCE_YOUR_CALM` and streamed writes
get `Overloaded`), `max_resets` (100 streams reset by the peer, or reset by the server because
of the peer's frames, per `reset_window`: Rapid Reset, CVE-2023-44487), `max_control_frames`
(1000 `PRIORITY`, extra `SETTINGS`, empty `DATA` or `CONTINUATION` frames per `reset_window`)
and `reset_window` (30 s). Past either budget the connection gets `GOAWAY ENHANCE_YOUR_CALM`.

HTTP/2 is selected per connection: the client preface (prior knowledge, and TLS with ALPN `h2`)
or an `Upgrade: h2c` request. The same service and middleware serve both versions; HTTP/3 reuses
them too ([QUIC and HTTP/3](quic-h3.md)).

## Services and the `Context`

Any `Fn(&mut Context) + Send + Sync + 'static` is a `Service`, as is a `Router`. A service must
**respond** or **detach**; if it does neither the client gets a 500.

```rust,ignore
{{#include ../../../../crates/akio-http/examples/guide-http.rs:handlers}}
```

Reading the request:

| Call | Returns |
|---|---|
| `ctx.method()`, `ctx.path()`, `ctx.header(name)`, `ctx.body()`, `ctx.peer()` | the basics |
| `ctx.req()` | the whole `Request` (`target`, `version`, `headers`, `trailers`, `body`, `query_param`) |
| `ctx.param(name)` / `ctx.param_raw(name)` | route parameter, percent-decoded / as sent |
| `ctx.local(key)` | a value stored by middleware with `set_local` |

Responding:

| Call | Effect |
|---|---|
| `ctx.text(status, body)` / `ctx.bytes(status, type, body)` | a complete response |
| `ctx.respond(Response)` | any response; `Response::from_file` for a file range (`sendfile` on plain TCP) |
| `ctx.detach()` → `Detached` | answer later from any thread: `respond`, `stream_response` |
| `ctx.stream_response(status, headers)` → `BodyStream` | chunked (HTTP/1.1) or DATA frames (HTTP/2); `write`, `queued_bytes`, `finish`, `finish_with_trailers` |
| `ctx.push(path)` | HTTP/2 server push of `GET path` |
| `ctx.upgrade_websocket(handler, &opts)` | switch to WebSocket ([chapter](websocket.md)) |
| `ctx.upgrade_raw(handler)` | take the raw connection (`RawHandler`), as the HTTP CONNECT proxy does |

Only the first response counts. `Response::header` sets a header; `Content-Length`, `Date` and
`Connection` are added when missing.

What a request costs: on HTTP/1.1, HTTP/2 and HTTP/3 the server itself allocates nothing per
request in the steady state. A request's target and header storage, and a response's header
storage, are reused from the thread's last request and response. The response head goes into a
pooled buffer, and an HTTP/2 request runs in a `Context` on the stack. `ctx.text(200, "...")`
with a `&str` copies it into a pooled buffer that goes back once the body is written, so a
hello-world handler allocates nothing either (ADR-025, ADR-081). What your handler hands over in
its own type is its own: a `String` or `Vec<u8>` body is the handler's allocation. A request the
handler keeps (`detach`, a WebSocket upgrade) keeps its own storage.

## Detaching: never block a handler

`ctx.detach()` hands the right to respond to a `Detached` value you can move to any thread.
Responses to pipelined HTTP/1.1 requests still leave in request order (akio-http reserves an
ordered response slot per request), and HTTP/2 streams are independent. The I/O thread is free
the moment your handler returns.

Where to run the slow part: a thread of your own, your own pool, or another runtime; see
[Blocking work](../concepts/blocking.md) and [Migrating from tokio](../migration/from-tokio.md).

## Streaming

Response bodies: `ctx.stream_response(..)` (or `Detached::stream_response`) returns a
`BodyStream` writable from any thread. On keep-alive HTTP/1.1 it is chunked, otherwise
close-delimited; behind earlier pipelined responses it is held back in order. Response filters
(compression, ETag) do not apply to streamed bodies. Dropping the stream without `finish` closes
the connection.

Request bodies: by default bodies are buffered (up to `max_body_bytes`) before the service runs.
Wrap a service in `Streaming(svc)` (or override `Service::body_mode`) to run it as soon as the
head is parsed and receive the body with `ctx.on_body`, chunk by chunk, then `BodyEvent::End`
with any trailers. No size limit applies to streamed bodies: the sink decides.

A middleware may `ctx.suspend()` a request whose body streams (ADR-159), to check something
first: the body's reads are held meanwhile (what one read brought, or a stream's window, is kept),
and once `Suspended::resume`'s closure returns, the `on_body` sink it registered gets the whole
body in order.

## Observing responses

`serve_with(cfg, svc).observer(Arc<dyn ResponseObserver>)` sets a listener's response observer
(ADR-158): each request that calls `ctx.set_observed([u64; 2])` has it told of its response, once,
when the response goes, on the thread that sends it, with the two words it stored (a metrics
slot, a log shard) and the time it stored them. No allocation per request, where a response
filter carrying the same costs one. HTTP/3: `akio_h3::serve_with_observer`.

## Protocol details handled for you

- Keep-alive, `Connection: close`, HTTP/1.0; pipelining with in-order responses.
- `Expect: 100-continue`.
- Chunked bodies with extensions and trailers, split anywhere.
- Request smuggling guards: `Content-Length` together with `Transfer-Encoding`, duplicate
  `Content-Length`.
- HEAD answered from GET routes without a body.
- HTTP/2: HPACK, flow control in both directions, h2c upgrade, server push, `GOAWAY` on
  shutdown; h2spec strict 147/147.
- Graceful shutdown: in-flight responses finish, then HTTP/1 connections close (an idle one after
  `idle_drain_grace`, answering a request that arrives meanwhile with `Connection: close`); HTTP/2
  sends `GOAWAY`.

## Comparison

HTTP/1.1, pipelined HTTP/1.1, h2c and HTTP/2 over TLS against hyper and fib, on epoll and
io_uring, are in [docs/BENCHMARKS.md](https://github.com/lesismal/akio/blob/main/docs/BENCHMARKS.md)
(the comparison report this section once listed as not done).
