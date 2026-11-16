# HTTP clients

Both clients run their connections on a `only` `Engine` (give it `client_threads(n)` and
`start()` it). Results arrive in a callback on an I/O thread (which must not block), or through a
`ResponseFuture` you can `wait()`, `wait_timeout(d)` or `.await`.

## HTTP/1.1: `client::Client`

```rust,ignore
{{#include ../../../../crates/only-http/examples/guide-http.rs:client}}
```

- `Client::new(Arc<Engine>)`, cheap to clone. `with_tls(only::tls::ClientConfig)` enables
  `https://`.
- `ClientRequest::get(url)`, `ClientRequest::post(url, body)`, `.header(name, value)`; or fill
  `method`, `url`, `headers`, `body` yourself. `Host`, `Content-Length` and `Connection` are added.
- `client.send(req)` returns a `ResponseFuture`; `client.request(req, callback)` calls back.
- `ClientResponse` has `status`, `reason`, `headers`, `body` (de-chunked), `trailers`.
- Keep-alive connections are reused per host; a request on a reused connection that turns out to
  be dead is retried once on a new one.
- Limits (`Client::with_options(ClientOptions)`), each with a safe default:

  | Field | Default | What happens past it |
  |---|---|---|
  | `max_head_bytes` | 64 KiB | response head (1xx heads included) → `ClientError::TooLarge` |
  | `max_body_bytes` | 64 MiB | any framing; a larger `Content-Length` fails at once → `TooLarge` (`usize::MAX` opts out) |
  | `request_timeout` | 30 s | total, dial to last byte → `ClientError::TimedOut`, connection closed; `ClientRequest::timeout(d)` overrides it |
  | `idle_timeout` | 90 s | pooled connections unused this long are closed |
  | `max_idle_per_host` | 32 | further idle connections to the host are closed (0: no reuse) |
  | `max_idle` | 256 | idle connections in all |
- Address fallback: every resolved address is tried in turn (`localhost` is often `::1` first).
- `ClientError`: `InvalidUrl`, `Io`, `Protocol`, `Closed`, `TimedOut`, `TooLarge`.

Not done: redirects, name resolution off the calling thread (resolution happens in `send`/`request` and may block).

## HTTP/2: `h2client::H2Client`

```rust,ignore
{{#include ../../../../crates/only-http/examples/guide-http.rs:h2client}}
```

- `H2Client::dial(engine, addr, tls, opts, ready)` or `dial_blocking(engine, addr, tls,
  opts)`. `tls = None` is prior-knowledge cleartext HTTP/2; `Some((cfg, server_name))` uses TLS
  and needs `h2` in `cfg.alpn_protocols`.
- One connection multiplexes every request; `H2Client` is cheap to clone and usable from any
  thread. `send(req)` → `ResponseFuture`, `request(req, callback)`.
- `H2Options`: `initial_window` (1 MiB), `conn_window` (16 MiB), `enable_push` (false; when on,
  `ClientResponse::pushed` carries pushed responses, at most 32 outstanding per request).
- Limits: frames above the default `SETTINGS_MAX_FRAME_SIZE` (16 KiB) and header blocks
  (HEADERS + CONTINUATION) above twice `max_header_list` end the connection; a decoded header
  list above `max_header_list` (64 KiB, advertised) or a buffered body above `max_body_bytes`
  (64 MiB) resets the stream (`CANCEL`) and fails the request with `TooLarge`;
  `request_timeout` (30 s) resets a buffered request's stream and fails it with `TimedOut`.
  Streamed requests (`open`) are not limited in body size and time out only with their own
  `ClientRequest::timeout`, since they may be long-lived (gRPC streams).
- Streaming both ways: `open(req, on_event)` returns an `H2Upload` (`write`, `finish`) for the
  request body, and reports `H2Event::Head`, `Data`, `Trailers`, `End` or `Error` as the response
  arrives. only-grpc's client is built on it.
- `is_open()`, `close()`.

## HTTP/3

`only_h3::H3Client` is covered in [QUIC and HTTP/3](quic-h3.md).

## Awaiting from async code

`ResponseFuture` implements `Future`, so async code (tokio included) can `.await` it; the
connection still runs on `only`'s I/O threads. See
[Migrating from tokio](../migration/from-tokio.md).
