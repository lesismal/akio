# Routing, middleware and static files

## Router

```rust,ignore
{{#include ../../../../crates/only-http/examples/guide-http.rs:router}}
```

Path segments:

| Pattern | Matches | Parameter |
|---|---|---|
| `users` | exactly that segment | – |
| `{name}.txt`, `v{major}.{minor}`, `{id:[0-9]+}.json` | literal text and parameters in one segment | `name`, … |
| `{id:[0-9]+}` | one whole segment matching the regexp | `id` |
| `:id` or `{id}` | any one segment | `id` |
| `*rest` or `{*rest}` | everything after, last segment only | `rest` |

Precedence is **static > partial segment > regexp > parameter > wildcard**, with backtracking:
if a static branch fails further down, the next kind is tried. Lookups are allocation-free (about
30 ns for a 52-route GitHub-style table in `examples/router-bench.rs`, with or without regexp or
partial segments). `Router::lookup(method, path)` gives the match without dispatching.

Partial segments ([ADR-007](https://github.com/lesismal/only/blob/main/docs/adr/007-partial-segment-routes.md))
mix literal text with `{name}` or `{name:regexp}` groups. A literal at the start or the end of the
segment is matched there; in between, each parameter is non-empty and ends at the **first**
occurrence of the text that follows it; a regexp parameter must also match its whole value. No
other split is tried, so matching stays linear:

| Pattern | Path segment | Parameters |
|---|---|---|
| `{name}.txt` | `a.b.txt` | `name = a.b` |
| `{name}.{ext}` | `a.b.c` | `name = a`, `ext = b.c` |
| `v{major:[0-9]+}.{minor}` | `v1.10` | `major = 1`, `minor = 10` |
| `pre-{mid}-post` | `pre-a-b-post` | `mid = a-b` |

Among partial segments, more literal text is tried first (`{name}.tar.gz` before `{name}.gz`),
then registration order. Two parameters need literal text between them, and a wildcard cannot
share a segment; both panic at registration.

Regexp parameters use `only-regex`, the workspace's linear-time engine (ADR-051): the expression
must match the whole segment, and matching takes time linear in the segment length (no
backtracking, so no pathological patterns; a DFA built at registration, about one nanosecond per
character). Supported syntax, with the meaning it has in the `regex` crate:

- literals (any Unicode character), `.` (any character but newline), `^` / `$` (and `\A` / `\z`);
- classes `[a-z0-9_]`, `[^.]` with ranges, negation and escapes; `]` first and `-` first or last
  are literal;
- `\d`, `\w`, `\s` and `\D`, `\W`, `\S`, **ASCII only** (`[0-9]`, `[0-9A-Za-z_]`,
  `[\t\n\x0B\x0C\r ]`: segments are matched as sent, percent-encoded), and `\b` / `\B` (ASCII
  word boundaries);
- escapes `\n \t \r \f \v \a`, `\x41`, `\x{1F600}`, `\u0041`, `\u{41}`, `\U0001F600`, and any escaped
  ASCII punctuation (`\.`, `\-`, `\{` ...);
- groups `(...)`, `(?:...)`, `(?P<name>...)`, `(?<name>...)` (nothing is captured; names must be
  distinct), alternation `|`, quantifiers `*`, `+`, `?`, `{m}`, `{m,}`, `{m,n}` (counts up to 1000)
  and their lazy forms;
- flags `(?i)` (case-insensitive, Unicode simple case folding: `{name:(?i)[a-z]+}`), `(?m)`,
  `(?s)`, `(?U)`, negated (`(?-i)`) and scoped (`(?i:...)`).

Anything else (`\p{L}`, backreferences, look-around, POSIX classes `[[:alpha:]]`, class set
operations `&&` `--` `~~`) is refused at registration with a message naming the problem. Before
ADR-051 the router had an engine of its own, which also refused flags, `\b \B \A \z` and
non-ASCII group names, and accepted two groups with the same name; every other pattern matches
exactly as before. The `regex` cargo feature of earlier versions no longer does anything.

Behaviour:

- Methods: `get`, `post`, `put`, `delete`, `patch`, `options`, or `route(Method, path, svc)`.
- A path that exists with another method answers **405** with an `Allow` header; an unknown path
  answers **404**. `fallback(svc)` replaces both (the `Allow` list is in
  `ctx.local("only.allow")`).
- `HEAD` is answered by the `GET` route, without a body.
- Duplicate or conflicting routes, a wildcard that is not last, unbalanced braces and invalid
  regexps **panic at registration**: you find out at startup, not in production.
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
| `compress(Compress { min_bytes, level, brotli, zstd, stream })` | br/zstd (when set)/gzip/deflate for text-like bodies the client accepts |
| `etag()` | adds an `ETag`, answers `If-None-Match` with 304 |
| `csrf()` | double-submit cookie: `csrf_token` cookie, checked against the `X-CSRF-Token` header on unsafe methods |
| `limiter(rate, burst)` | per-client-IP token bucket, 429 with `Retry-After` |
| `observe::HttpMetrics::middleware()` | request counters and latency histogram ([Observability](../observability.md)) |
| `observe::access_log()` | structured access log through `only::log` |

`br` and `zstd` (the in-house `only-brotli` and `only-zstd`, ADR-041) are off by default: set
`Compress::brotli` / `Compress::zstd` to a level to answer clients that accept them, preferred in
the order br, zstd, gzip, deflate. Pre-compressed `.br`, `.zst` and `.gz` files are served by
`Files`. The middleware compresses whole buffered bodies. Streamed responses
(`Context::stream_response`) are sent as written unless `Compress::stream` is set
(ADR-074): then they are compressed write by write, the encoder flushed after every write so
that each server-sent event still reaches the client at once, with small per-stream defaults
(`StreamCompress`: gzip 1, zstd 1 with a 128 KiB window, brotli 4 with a 256 KiB window; about
0.3, 0.5 and 1.3 MiB per open stream once a window of output has gone through; brotli's match
tables grow with the stream, so a stream that has sent a few events holds a few KiB). Brotli
still costs the most CPU per small write (about 2 us per flushed event, zstd 0.3 us), so for
high-rate event streams offer zstd or let gzip serve them.

```rust,ignore
{{#include ../../../../crates/only-http/examples/guide-http.rs:compression}}
```

## Static files

`files::Files::new(root)` is a service. Mount it on a wildcard route whose parameter is named
`path` (`/static/*path`), or use it as the fallback (then the request path is used).

| Builder | Default | Meaning |
|---|---|---|
| `index(name)` | `index.html` | file served for a directory |
| `max_cached_bytes(n)` | 256 KiB | files up to this size are kept in memory (0 disables) |
| `max_open_files(n)` | 64 | larger files keep an open handle and metadata cached; least recently used evicted first (CLOCK) |
| `check_interval(d)` | 5 s | how long a cached entry is trusted before re-checking the disk |
| `watch(on)` | off | follow changes through inotify (Linux) / kqueue (macOS): watched entries are trusted until a change drops them (not for network or FUSE file systems) |
| `max_watches(n)` | 1024 | most watches `watch` sets up (directories; plus one file descriptor per cached file on macOS); past it, the `check_interval` rule |
| `cache_control(v)` | none | `Cache-Control` header on every file response |

Features: `GET`/`HEAD`; `ETag` and `Last-Modified`; `If-None-Match` / `If-Modified-Since` (304),
`If-Match` / `If-Unmodified-Since` (412); `Range` requests (206/416) guarded by `If-Range`;
`..` and other escapes refused (symlinks are followed); `file.ext.br` / `file.ext.zst` / `file.ext.gz` served to
clients that accept them; large files sent with `sendfile(2)` on plain TCP (read through memory
under TLS).

Several ranges (`Range: bytes=0-9,500-599,-10`) get a `206` with a `multipart/byteranges` body
(RFC 9110 section 14.6), one part per range with its own `Content-Type` and `Content-Range`, in
the order asked. Following RFC 9110 section 14.2, overlapping ranges and ranges less than 80 bytes
apart are coalesced (a merged part takes the place of its first member, and a request that comes
down to one range gets a plain `206` with `Content-Range`); ranges past the end are dropped, and
`416` comes only when none is left. As a guard against abuse, a header with more than 32 ranges,
or whose parts add up to more than 1 MiB, is ignored and the whole file is sent: a multipart body
is assembled in memory (`sendfile` is used for single ranges only).

The open-file cache holds at most `max_open_files` handles. When they are all taken, a new large
file replaces the least recently used one (CLOCK: an entry used since the hand last passed gets a
second chance). An entry is replaced when its file's size, modification time or inode change, so
an atomic `rename` over a file is noticed even with the same size and time, and dropped when the
file is deleted (after the check interval). A response being sent keeps its own handle, so an
evicted file is closed when its last response finishes.

Only a cache hit inside its trust window is answered on the I/O thread. A miss, a re-check and
anything else that touches the disk (`stat`, `open`, reading a small file into the cache, the
parts of a multi-range response from a large file) is detached to a small disk pool shared by
every `Files` (up to 16 threads and 4096 queued requests; past that the answer is `503` with
`Retry-After: 1`), and the response is sent from there. Whether `file.br` / `file.zst` / `file.gz` exist is
cached with the file, and the validators and fixed headers are formatted once per entry. Not
done: inotify-based invalidation (the stat interval is used instead); the
in-memory cache of small files is bounded by the files that exist, not by a byte budget.
