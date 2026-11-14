# HTTP/1.1 and HTTP/2 servers

`flash-http` serves HTTP/1.0, HTTP/1.1 and HTTP/2 with one programming model: a `Service` gets a
`&mut Context` for each request, on the connection's I/O thread.

## Serving

```rust,ignore
{{#include ../../../../crates/flash-http/examples/guide-http.rs:serve}}
```

`serve(service)` / `serve_with(HttpConfig, service)` return an `HttpAcceptor`: serve it on a
listener directly, or wrap it in `Tls::server` for HTTPS. `HttpConfig`:

| Field | Default | Meaning |
|---|---|---|
| `max_header_bytes` | 64 KiB | request line + headers; larger gets 431 |
| `max_body_bytes` | 1 MiB | buffered request body; larger gets 413 |
| `h2` | `Some(H2Config::default())` | HTTP/2 settings, `None` for HTTP/1 only |

`H2Config`: `max_concurrent_streams` (128), `initial_window` (1 MiB per stream),
`conn_window` (16 MiB), `max_header_list` (64 KiB), `max_body_bytes` (1 MiB, buffered bodies),
`max_pending_bytes` (8 MiB a response may hold back for a slow peer before writers get
`Overloaded`).

HTTP/2 is selected per connection: the client preface (prior knowledge, and TLS with ALPN `h2`)
or an `Upgrade: h2c` request. The same service and middleware serve both versions; HTTP/3 reuses
them too ([QUIC and HTTP/3](quic-h3.md)).

## Services and the `Context`

Any `Fn(&mut Context) + Send + Sync + 'static` is a `Service`, as is a `Router`. A service must
**respond** or **detach**; if it does neither the client gets a 500.

```rust,ignore
{{#include ../../../../crates/flash-http/examples/guide-http.rs:handlers}}
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

## Detaching: never block a handler

`ctx.detach()` hands the right to respond to a `Detached` value you can move to any thread.
Responses to pipelined HTTP/1.1 requests still leave in request order (flash-http reserves an
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

## Protocol details handled for you

- Keep-alive, `Connection: close`, HTTP/1.0; pipelining with in-order responses.
- `Expect: 100-continue`.
- Chunked bodies with extensions and trailers, split anywhere.
- Request smuggling guards: `Content-Length` together with `Transfer-Encoding`, duplicate
  `Content-Length`.
- HEAD answered from GET routes without a body.
- HTTP/2: HPACK, flow control in both directions, h2c upgrade, server push, `GOAWAY` on
  shutdown; h2spec strict 147/147.
- Graceful shutdown: in-flight responses finish, then HTTP/1 connections close; HTTP/2 sends
  `GOAWAY`.

## Not done

Multi-range responses; partial-segment route patterns such as `/{name}.txt`; an HTTP/1
comparison report against hyper and fib (planned for the benchmark pass).
