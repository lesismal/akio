# HTTP clients

Both clients run their connections on a `only` `Engine` (give it `client_threads(n)` and
`start()` it). Results arrive in a callback on an I/O thread (which must not block), or through a
`ResponseFuture` you can `wait()`, `wait_timeout(d)` or `.await`.

## HTTP/1.1: `client::Client`

```rust,ignore
{{#include ../../../../crates/only-http/examples/guide-http.rs:client}}
```

- `Client::new(Arc<Engine>)`, cheap to clone. `https://` uses the system's CAs
  (`only::tls::RootCerts::system()`); `with_tls(only::tls::ClientConfig)` replaces them (your own
  roots, client certificates, ALPN).
- `ClientRequest::get(url)`, `ClientRequest::post(url, body)`, `.header(name, value)`,
  `.timeout(d)`; or fill `method`, `url`, `headers`, `body`, `timeout` yourself. `Host`,
  `Content-Length` and `Connection` are added.
- `client.send(req)` returns a `ResponseFuture`; `client.request(req, callback)` calls back.
- `ClientResponse` has `status`, `reason`, `headers`, `body` (de-chunked), `trailers` and `url`
  (the URL that answered, after redirects).
- Keep-alive connections are reused per host (and per proxy); a request on a reused connection
  that turns out to be dead is retried once on a new one.
- Names are resolved off the calling thread, on `only::dns`'s resolver threads (at most four,
  started on demand); IP literals need no lookup. Every resolved address is tried in turn
  (`localhost` is often `::1` first).
- `ClientError`: `InvalidUrl`, `Io`, `Protocol`, `Closed`, `Timeout`, `TooManyRedirects`,
  `TooLarge`.
- Limits (`Client::with_options(ClientOptions)`), each with a safe default:

  | Field | Default | What happens past it |
  |---|---|---|
  | `max_head_bytes` | 64 KiB | response head (1xx heads included) → `ClientError::TooLarge` |
  | `max_body_bytes` | 64 MiB | any framing; a larger `Content-Length` fails at once → `TooLarge` (`usize::MAX` opts out) |
  | `idle_timeout` | 90 s | pooled connections unused this long are closed |
  | `max_idle_per_host` | 32 | further idle connections to the route are closed (0: no reuse) |
  | `max_idle` | 256 | idle connections in all |

Each `with_*` returns a new client with its own connection pool; configure once and clone.

### Redirects

Off by default: a 3xx response is returned as it is. `with_redirects(RedirectPolicy::limit(n))`
follows 301, 302, 303, 307 and 308 responses that carry a `Location` (relative ones resolved
against the request URL), following RFC 9110 section 15.4:

| Status | Method and body |
|---|---|
| 303 | `GET` without a body (`HEAD` stays `HEAD`) |
| 301, 302 | `POST` becomes `GET` without a body; other methods kept with their body |
| 307, 308 | method and body kept |

When the body is dropped, its `Content-*` fields go too. A redirect to another origin (scheme,
host or port) drops `Authorization`, `Cookie` and `Proxy-Authorization`, for the rest of the
chain. `https://` to `http://` is not followed (the 3xx is returned) unless
`RedirectPolicy::limit(n).allow_https_downgrade(true)`. More than `n` redirects (a loop, for
instance) fails with `ClientError::TooManyRedirects`. There is no cookie jar.

### Timeouts

`ClientRequest::timeout(d)`, or `Client::with_timeout(d)` for every request, limits the whole
exchange: resolution, connecting, TLS, sending, the complete response and all redirects. When it
passes the request fails with `ClientError::Timeout` and its connection is closed (never reused
or retried). `ResponseFuture::wait_timeout` only stops waiting; the request goes on.

### Proxies

```rust,ignore
use only_http::client::{Client, Proxy};
let client = Client::new(engine)
    .with_proxy(Proxy::all("http://user:pass@proxy.internal:3128")?.no_proxy("localhost,.corp"));
// or, opting in to the environment (http_proxy, https_proxy, all_proxy, no_proxy, upper case
// too):
let client = Client::new(engine).with_proxy(Proxy::from_env()?);
// or a SOCKS proxy (host names resolved by the proxy):
let client = Client::new(engine).with_proxy(Proxy::all("socks5h://user:pass@proxy.internal")?);
```

`http://` requests go to the proxy in absolute form (`GET http://host/path HTTP/1.1`);
`https://` goes through a `CONNECT host:port` tunnel with TLS to the target inside it.
Credentials in the proxy URL become `Proxy-Authorization: Basic`. A proxy that refuses the
tunnel fails the request with `ClientError::Io` whose error is an `only_http::client::ProxyRefused`
(`status()`, `reason()`). `NO_PROXY` entries: `*`, host names (and their subdomains), IP
addresses, CIDR blocks, each optionally with `:port`. TLS to the proxy itself is not supported.
Nothing reads the environment unless you call `Proxy::from_env()`; `all_proxy` / `ALL_PROXY`
covers the schemes the specific variables leave unset.

SOCKS proxies (`socks5://`, `socks5h://`, `socks4://`, `socks4a://`, port 1080 by default):
every request, `http://` too, goes through a SOCKS tunnel to the target. `socks5h` and
`socks4a` send host names to the proxy; `socks5` and `socks4` resolve the target first and ask
for its first IPv4 address (curl's convention). Credentials in the URL are SOCKS5
username/password (RFC 1929), or the SOCKS4 user id. A refusal is the same `ProxyRefused`, with
the closest HTTP status (407 for authentication, 403 for "not allowed", 502 for an unreachable
target) and `socks_reply()` giving the SOCKS code. For SOCKS beyond these clients (BIND, UDP,
blocking sockets) see the [SOCKS client](socks.md#socks-client).

See [ADR-010](https://github.com/lesismal/only/blob/main/docs/adr/010-http-client-gaps.md) and
[ADR-019](https://github.com/lesismal/only/blob/main/docs/adr/019-socks-client-fragments-socks4-bind.md)
for the reasoning behind these rules.

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
  (64 MiB) resets the stream (`CANCEL`) and fails the request with `TooLarge`. Streamed
  requests (`open`) are handed their body as it arrives and are not limited in size.
- Streaming both ways: `open(req, on_event)` returns an `H2Upload` (`write`, `finish`) for the
  request body, and reports `H2Event::Head`, `Data`, `Trailers`, `End` or `Error` as the response
  arrives. only-grpc's client is built on it.
- `is_open()`, `close()`.
- `ClientRequest::timeout` applies: the stream is reset (`CANCEL`) and the request fails with
  `ClientError::Timeout`; the connection stays usable. One connection to one origin: no redirects
  or proxies.

## HTTP/3

`only_h3::H3Client` is covered in [QUIC and HTTP/3](quic-h3.md).

## Awaiting from async code

`ResponseFuture` implements `Future`, so async code (tokio included) can `.await` it; the
connection still runs on `only`'s I/O threads. See
[Migrating from tokio](../migration/from-tokio.md).
