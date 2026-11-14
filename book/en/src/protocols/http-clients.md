# HTTP clients

Both clients run their connections on a flash `Engine` (give it `client_threads(n)` and
`start()` it). Results arrive in a callback on an I/O thread (which must not block), or through a
`ResponseFuture` you can `wait()`, `wait_timeout(d)` or `.await`.

## HTTP/1.1: `client::Client`

```rust,ignore
{{#include ../../../../crates/flash-http/examples/guide-http.rs:client}}
```

- `Client::new(Arc<Engine>)`, cheap to clone. `with_tls(Arc<rustls::ClientConfig>)` enables
  `https://`.
- `ClientRequest::get(url)`, `ClientRequest::post(url, body)`, `.header(name, value)`; or fill
  `method`, `url`, `headers`, `body` yourself. `Host`, `Content-Length` and `Connection` are added.
- `client.send(req)` returns a `ResponseFuture`; `client.request(req, callback)` calls back.
- `ClientResponse` has `status`, `reason`, `headers`, `body` (de-chunked), `trailers`.
- Keep-alive connections are reused per host; a request on a reused connection that turns out to
  be dead is retried once on a new one.
- Address fallback: every resolved address is tried in turn (`localhost` is often `::1` first).
- `ClientError`: `InvalidUrl`, `Io`, `Protocol`, `Closed`.

Not done: redirects, per-request timeouts (use `wait_timeout`, or the engine's idle timeout),
name resolution off the calling thread (resolution happens in `send`/`request` and may block).

## HTTP/2: `h2client::H2Client`

```rust,ignore
{{#include ../../../../crates/flash-http/examples/guide-http.rs:h2client}}
```

- `H2Client::dial(engine, addr, tls, opts, ready)` or `dial_blocking(engine, addr, tls,
  opts)`. `tls = None` is prior-knowledge cleartext HTTP/2; `Some((cfg, server_name))` uses TLS
  and needs `h2` in `cfg.alpn_protocols`.
- One connection multiplexes every request; `H2Client` is cheap to clone and usable from any
  thread. `send(req)` → `ResponseFuture`, `request(req, callback)`.
- `H2Options`: `initial_window` (1 MiB), `conn_window` (16 MiB), `enable_push` (false; when on,
  `ClientResponse::pushed` carries pushed responses).
- Streaming both ways: `open(req, on_event)` returns an `H2Upload` (`write`, `finish`) for the
  request body, and reports `H2Event::Head`, `Data`, `Trailers`, `End` or `Error` as the response
  arrives. flash-grpc's client is built on it.
- `is_open()`, `close()`.

## HTTP/3

`flash_h3::H3Client` is covered in [QUIC and HTTP/3](quic-h3.md).

## Awaiting from async code

`ResponseFuture` implements `Future`, so async code (tokio included) can `.await` it; the
connection still runs on flash's I/O threads. See
[Migrating from tokio](../migration/from-tokio.md).
