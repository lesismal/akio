# Routing, middleware and static files

## Router

```rust,ignore
{{#include ../../../../crates/only-http/examples/guide-http.rs:router}}
```

Path segments:

| Pattern | Matches | Parameter |
|---|---|---|
| `users` | exactly that segment | – |
| `{id:[0-9]+}` | one whole segment matching the regexp | `id` |
| `:id` or `{id}` | any one segment | `id` |
| `*rest` or `{*rest}` | everything after, last segment only | `rest` |

Precedence is **static > regexp > parameter > wildcard**, with backtracking: if a static branch
fails further down, the parameter branch is tried. Lookups are allocation-free (about 30 ns for a
52-route GitHub-style table in `examples/router-bench.rs`). `Router::lookup(method, path)` gives
the match without dispatching.

Regexp parameters use a small built-in engine: the expression must match the whole segment, and
matching takes time linear in the segment length (no backtracking, so no pathological patterns).
Supported syntax, with the meaning it has in the `regex` crate:

- literals (any Unicode character), `.` (any character but newline), `^` / `$`;
- classes `[a-z0-9_]`, `[^/]` with ranges, negation and escapes; `]` first and `-` first or last
  are literal;
- `\d`, `\w`, `\s` and `\D`, `\W`, `\S`, **ASCII only** (`[0-9]`, `[0-9A-Za-z_]`,
  `[\t\n\x0B\x0C\r ]`: segments are matched as sent, percent-encoded);
- escapes `\n \t \r \f \v \a`, `\x41`, `\x{1F600}`, `\u0041`, `\u{41}`, `\U0001F600`, and any escaped
  ASCII punctuation (`\.`, `\-`, `\{` ...);
- groups `(...)`, `(?:...)`, `(?P<name>...)`, `(?<name>...)` (nothing is captured), alternation
  `|`, quantifiers `*`, `+`, `?`, `{m}`, `{m,}`, `{m,n}` (counts up to 1000) and their lazy forms.

Anything else (flags such as `(?i)`, `\b` and other assertions, `\p{L}`, backreferences, POSIX
classes `[[:alpha:]]`, class set operations `&&` `--` `~~`) is refused at registration with a
message naming the problem. The `regex` cargo feature of earlier versions no longer does anything.

Behaviour:

- Methods: `get`, `post`, `put`, `delete`, `patch`, `options`, or `route(Method, path, svc)`.
- A path that exists with another method answers **405** with an `Allow` header; an unknown path
  answers **404**. `fallback(svc)` replaces both (the `Allow` list is in
  `ctx.local("only.allow")`).
- `HEAD` is answered by the `GET` route, without a body.
- Duplicate or conflicting routes, a wildcard that is not last and invalid regexps **panic at
  registration**: you find out at startup, not in production.
- `nest(prefix, router)` mounts another router; its own layers stay in effect for its routes.
- Parameters are percent-decoded once at dispatch (`ctx.param`); `ctx.param_raw` has the text as
  sent.

## Middleware

A middleware is any `Fn(&mut Context, &dyn Service) + Send + Sync + 'static` (or a type
implementing `Middleware::handle`). Call `next.call(ctx)` to continue, or answer without calling
it:

```rust,ignore
{{#include ../../../../crates/only-http/examples/guide-http.rs:middleware}}
```

In the router above it guards only the nested `/admin` router:
`Router::new().get("/stats", hello).layer(auth)` mounted with `.nest("/admin", admin)`.

`Router::layer(mw)` wraps every route registered **so far** and the fallback; the last layer
added runs first (outermost). Routes added after a `layer` call are not wrapped by it, which lets
you scope middleware by ordering.

Because handlers may detach, middleware that needs the final response registers a filter
instead of inspecting it after `next.call` returns: `ctx.add_response_filter(|resp, req| ..)`
runs just before the response is sent, on whichever thread sends it. `ctx.add_response_header`
adds a header unless the response sets it.

Built-in middleware (`only_http::middleware` and `only_http::observe`):

| Middleware | What it does |
|---|---|
| `recover()` | a panic in the wrapped service becomes a 500 instead of closing the connection |
| `request_id()` | uses the incoming `X-Request-Id` or makes one; `ctx.local("request_id")`, echoed in the response |
| `cors(Cors { allow_origin, allow_methods, allow_headers, max_age })` | answers preflights with 204, adds `Access-Control-Allow-Origin` |
| `logger(fn(&LogRecord))` | calls your function after each request (method, target, peer, status, elapsed) |
| `response_time()` | adds an `X-Response-Time` header |
| `compress(Compress { min_bytes, level })` | gzip/deflate for text-like bodies the client accepts |
| `etag()` | adds an `ETag`, answers `If-None-Match` with 304 |
| `csrf()` | double-submit cookie: `csrf_token` cookie, checked against the `X-CSRF-Token` header on unsafe methods |
| `limiter(rate, burst)` | per-client-IP token bucket, 429 with `Retry-After` |
| `observe::HttpMetrics::middleware()` | request counters and latency histogram ([Observability](../observability.md)) |
| `observe::access_log()` | structured access log through the `log` facade |

Brotli compression is not offered (no brotli dependency yet); pre-compressed `.br` files are
served by `Files`.

## Static files

`files::Files::new(root)` is a service. Mount it on a wildcard route whose parameter is named
`path` (`/static/*path`), or use it as the fallback (then the request path is used).

| Builder | Default | Meaning |
|---|---|---|
| `index(name)` | `index.html` | file served for a directory |
| `max_cached_bytes(n)` | 256 KiB | files up to this size are kept in memory (0 disables) |
| `max_open_files(n)` | 64 | larger files keep an open handle and metadata cached |
| `check_interval(d)` | 5 s | how long a cached entry is trusted before re-checking the disk |
| `cache_control(v)` | none | `Cache-Control` header on every file response |

Features: `GET`/`HEAD`; `ETag` and `Last-Modified`; `If-None-Match` / `If-Modified-Since` (304),
`If-Match` / `If-Unmodified-Since` (412); single `Range` requests (206/416) guarded by
`If-Range`; `..` and other escapes refused (symlinks are followed); `file.ext.br` /
`file.ext.gz` served to clients that accept them; large files sent with `sendfile(2)` on plain
TCP (read through memory under TLS).

A cache miss reads the file on the I/O thread, so keep cached files small and the check interval
reasonable. Not done: multi-range responses, inotify-based invalidation (the stat interval is used
instead), eviction in the open-file cache.
