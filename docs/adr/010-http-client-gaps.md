# ADR-010: HTTP and WebSocket client: redirects, timeouts, resolution, system roots, proxies

English | [简体中文](010-http-client-gaps.zh-CN.md)

Status: accepted (2026-11-16)

## Context

akio-http's HTTP/1 client (`client::Client`), its HTTP/2 client (`h2client::H2Client`) and
akio-ws's WebSocket client (`client::dial`) were usable but left gaps that every real deployment
hits: no redirects, no per-request timeout, `getaddrinfo` on the calling thread (from a
callback, that blocked an I/O thread), no default trust store (callers had to find CA files
themselves), no proxy support, and a WebSocket client that dropped its connections without a
close frame when the engine shut down. Closing them adds public API in four crates and needs a
few product decisions, recorded here. The project rule stands: no third-party dependency.

## Decision

1. **Name resolution off the calling thread: `akio::dns`.** `akio::dns::resolve(host, port,
   done)` answers IP literals inline and hands names to a process-wide pool of at most four
   `akio-dns` threads, started on demand and leaving after 10 s idle; `done` runs on the
   resolver thread with every address in system order (an empty answer is `NotFound`). Not the
   engine's logical pool: lookups can take seconds and must not delay application blocking
   work, and the clients need it before a connection (and so a `Conn`) exists. Lookups cannot be
   cancelled; a request that timed out ignores the late answer. The HTTP/1 client resolves only
   when it has no idle keep-alive connection for the route; the WebSocket client always does.
   `H2Client::dial` keeps taking a `SocketAddr`.
2. **System root certificates: `akio::tls::RootCerts::system()`.** Read once per process and
   cached. `SSL_CERT_FILE` / `SSL_CERT_DIR` win when set (the OpenSSL convention, so a deployment
   can point every client at its own store). macOS: the system keychains exported by
   `/usr/bin/security find-certificate -a -p` (`SystemRootCertificates.keychain` and
   `/Library/Keychains/System.keychain`), falling back to `/etc/ssl/cert.pem`; keychain trust
   settings (a CA an administrator distrusted) are **not** applied, which is the documented
   price of not linking Security.framework. Other Unix: the first existing bundle of the usual
   distribution paths (Debian/Ubuntu/Alpine/Arch `ca-certificates.crt`, Fedora/RHEL, openSUSE,
   FreeBSD ...), else the certificate directories. Certificates akio-x509 cannot parse are
   skipped; no certificate at all is an error. **Clients default to it**: `Client` without
   `with_tls` and `DialOptions::tls = None` now use the system's CAs for `https://` / `wss://`
   (before, they failed with "needs Client::with_tls" / "needs DialOptions::tls"). This turns an
   error into the expected behaviour and changes nothing for callers that pass a configuration.
3. **Redirects: opt-in, `client::RedirectPolicy`.** `Client::with_redirects(policy)`;
   `RedirectPolicy::none()` (the default, so existing callers see 3xx responses as before) or
   `RedirectPolicy::limit(n)`. Followed: 301, 302, 303, 307 and 308 with a `Location`, resolved
   against the request URL (RFC 3986 section 5, fragment dropped); 300, 304 and 305 never.
   Method and body per RFC 9110 section 15.4: 303 turns every method but `HEAD` into `GET`
   without a body; 301 and 302 turn `POST` into `GET` without a body (what every browser and
   curl do) and keep other methods; 307 and 308 keep method and body. A dropped body takes its
   describing fields with it (`Content-Type`, `Content-Length`, `Content-Encoding`,
   `Content-Language`, `Content-Location`, `Transfer-Encoding`). **No credential leakage across
   origins**: when scheme, host (case-insensitive) or port changes, `Authorization`, `Cookie`
   and `Proxy-Authorization` are removed and stay removed for the rest of the chain, even if it
   comes back. **https → http is not followed** unless `allow_https_downgrade(true)`; the 3xx
   response is returned instead (an error would hide the `Location` the caller may want to
   inspect). Passing the limit, which is also how loops end, is `ClientError::TooManyRedirects`;
   a `Location` that is not an `http(s)` URL is `ClientError::InvalidUrl`. No cookie jar: a
   client that needs cookies across redirects follows them itself. `ClientResponse::url` reports
   the URL that answered. The WebSocket client gets the same rules for its handshake through
   `DialOptions::max_redirects` (default 0): `http`/`https` locations map to `ws`/`wss`,
   `wss → ws` is never followed, cross-origin hops drop the same fields from
   `DialOptions::headers` and the `server_name` override, and `WsClientError::TooManyRedirects`
   ends loops. Browsers do not follow WebSocket redirects; RFC 6455 section 4.1 allows it, hence
   opt-in. `H2Client` is one connection to one origin and does not follow redirects.
4. **Per-request timeout.** `ClientRequest::timeout: Option<Duration>` (+ `.timeout(d)`) and
   `Client::with_timeout(d)` as the default. It covers the whole exchange: resolution,
   connecting, TLS, the request, the full response and every redirect (what Go's
   `Client.Timeout` does; one budget is what callers reason about). On expiry the request fails
   with `ClientError::Timeout` (on the timer thread) and its connection is closed, never
   returned to the pool and never retried. `H2Client` honours `ClientRequest::timeout` too: the
   stream is reset with `CANCEL`, the connection stays usable. A dial that is still connecting
   when the timeout passes runs to its end and is closed then. The WebSocket client keeps its
   `handshake_timeout`, which now spans redirects.
5. **HTTP proxies: `akio_ws::proxy::Proxy`, re-exported as `akio_http::client::Proxy`.** It
   lives in akio-ws because both clients need it and akio-http already depends on akio-ws.
   `Proxy::all(url)`, `.http(url)`, `.https(url)`, `.no_proxy(list)`, `Proxy::from_env()`,
   `is_empty()`, `applies(secure, host, port)`. **The environment is opt-in**: nothing reads it
   unless the caller passes `Proxy::from_env()` (`http_proxy`/`HTTP_PROXY`,
   `https_proxy`/`HTTPS_PROXY`, `no_proxy`/`NO_PROXY`, lower case first; `HTTP_PROXY` ignored when
   `REQUEST_METHOD` is set, against "httpoxy"); an unusable value is an error rather than a
   silent bypass. Only plain-HTTP proxies (`http://[user:pass@]host[:port]`, port 80 by default;
   credentials become `Proxy-Authorization: Basic`); TLS to the proxy and SOCKS are not
   supported (akio-socks is separate). `NO_PROXY` entries: `*`, host names matching themselves
   and their subdomains (leading `.`/`*.` optional), IP addresses, CIDR blocks, any with
   `:port`; loopback is not special-cased (list it if wanted). Routing: `http://` targets go to
   the proxy as absolute-form requests (keep-alive connections pooled per proxy); `https://`,
   `ws://` and `wss://` go through a `CONNECT host:port` tunnel. The tunnel is a `Transport`
   layered under the TLS transport (hidden `akio_ws::proxy::Connect` acceptor wrapper): it sends
   the `CONNECT`, holds the TLS first flight and any application bytes until a 2xx, then gets out
   of the way (`tls_info` still sees the TLS transport). A non-2xx answer fails the connection
   with an `io::Error` carrying `akio_ws::proxy::ProxyRefused` (status and reason; kind
   `PermissionDenied` for 401/403/407), reported as `ClientError::Io` / `WsClientError::Io`; the
   proxy's response body is never shown as if it came from the target.
6. **WebSocket close 1001 on engine shutdown.** The client acceptor's `on_shutdown` starts the
   close handshake with 1001 ("going away") on open connections (the server answers, the TCP
   connection ends within `close_timeout`), and drops connections still handshaking.
7. **API summary** (all additive; enums and structs touched are `#[non_exhaustive]`):
   - `akio`: module `dns` (`resolve`, `literal`, `MAX_THREADS`, `IDLE`).
   - `akio-tls`: `RootCerts::system()`.
   - `akio-ws`: module `proxy` (`Proxy`, `ProxyRefused`); `DialOptions::{proxy, max_redirects}`;
     `WsClientError::TooManyRedirects`.
   - `akio-http`: `client::{RedirectPolicy, Proxy, ProxyRefused}`;
     `Client::{with_redirects, with_timeout, with_proxy}`; `ClientRequest::timeout` (field and
     builder); `ClientResponse::url`; `ClientError::{Timeout, TooManyRedirects}`.

## Consequences

- No blocking call is left on the clients' request paths; a redirect issued from an I/O-thread
  callback no longer resolves on that thread.
- `https://` and `wss://` work without configuration on Linux and macOS; a host without a CA
  store reports where it looked. macOS keychain trust settings are not honoured; a deployment
  that needs them sets `SSL_CERT_FILE` or passes its own `RootCerts`.
- Each `Client::with_*` returns a client with its own keep-alive pool, as `with_tls` always did.
- Not done, additive later: a cookie jar, HTTPS (TLS) and SOCKS proxies, proxy auto-config,
  `Proxy-Authenticate` challenges other than Basic-in-the-URL, Happy Eyeballs (addresses are
  tried in order), a DNS cache, Windows' certificate store.
