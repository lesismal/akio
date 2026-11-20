# Observability and hot reload

Every engine owns a **telemetry hub** (`only::Telemetry`): per-thread counters, the connection
table, slow-callback records and the live (reloadable) settings. It is reachable as
`Config::telemetry` before the engine is built and as `Engine::telemetry()` afterwards. The I/O
threads update plain per-thread counters with relaxed atomics (cache-line aligned, nothing
locked or allocated per event); snapshots are assembled on demand.

## From code

```rust,ignore
{{#include ../../../crates/only/examples/guide-config.rs:observe}}
```

| Call | Returns |
|---|---|
| `Engine::metrics()` | `Metrics`: per-thread `LoopMetrics` (owner, running, counters), `total`, `open_connections`, `pool`, `uptime`; `to_prometheus()`, `to_json()` |
| `Engine::connections(timeout)` | the connection table: one `ConnInfo` per connection (id, peer, local, owning thread, age, idle, bytes in/out, queued bytes, read-held, backpressure, transport, udp). Gathered by asking each I/O thread; never call it from an I/O thread's callback |
| `Engine::slow_callbacks()` | the most recent slow callbacks (up to 256), oldest first |
| `Engine::pool_stats()` | logical pool threads, idle, queued, completed, panicked, rejected |
| `Engine::udp_stats()` | UDP peers open and datagrams rejected by `udp_max_peers` |
| `Engine::accel_status()` | eBPF steering per listener |
| `Telemetry::collect()`, `Telemetry::render_prometheus()` | the registered collectors' `Families` (Prometheus or JSON); the engine's series followed by the collectors', as served by `metrics_handler` |

## Prometheus

Engine series (one per I/O thread, labelled `listener`, `backend`, `thread`):

| Series | Type |
|---|---|
| `only_connections_accepted_total`, `only_connections_dialed_total`, `only_connections_closed_total` | counter |
| `only_connections_rejected_total` (max_connections), `only_accept_errors_total`, `only_idle_timeouts_total` | counter |
| `only_read_bytes_total`, `only_reads_total`, `only_written_bytes_total`, `only_writes_total` | counter |
| `only_udp_datagrams_received_total`, `only_udp_datagrams_sent_total` | counter |
| `only_send_queue_bytes` | gauge |
| `only_backpressure_events_total`, `only_overloaded_total` | counter |
| `only_tls_handshake_failures_total`, `only_transport_errors_total` | counter |
| `only_loop_iterations_total`, `only_loop_events_total`, `only_loop_callbacks_total`, `only_loop_callback_seconds_total`, `only_slow_callbacks_total` | counter |
| `only_connections_open`, `only_loop_running` | gauge |
| `only_pool_threads`, `only_pool_active`, `only_pool_queued` | gauge |
| `only_pool_completed_total`, `only_pool_panicked_total`, `only_pool_rejected_total` | counter |
| `only_uptime_seconds` | gauge |

HTTP series from `observe::HttpMetrics`: `only_http_requests_total{class="2xx"...}`,
`only_http_request_duration_seconds` (histogram, buckets from 0.5 ms to 10 s),
`only_http_requests_in_flight`, `only_http_requests_by_version_total{version="1.0|1.1|2|3"}`
(responses by the request's protocol version; on h2 and h3 that is the number of answered request streams).
QUIC and TLS series come from their collectors, see [Your own metrics](#your-own-metrics).

**Cost.** The counters are always on and callback timing is on while a slow-callback threshold
is set (the default). A same-run A/B on a quiet host (Ryzen 7 7800X3D, Linux 7.0, 5 rounds) found
no measurable cost: HTTP/1.1 plaintext and pipelined at 0.998–1.006× with timing off or with the
counters compiled out, TCP and UDP echo within their ±5–10% noise (docs/BENCHMARKS.md, "Telemetry
overhead").

`only_loop_callback_seconds_total / only_loop_iterations_total` and the slow-callback counter
are the first things to watch: they tell you whether handlers are keeping the I/O threads busy.

## HTTP endpoints

```rust,ignore
{{#include ../../../crates/only-http/examples/guide-observe.rs:endpoints}}
```

- `observe::metrics_handler(telemetry, Some(http_metrics))` answers the Prometheus text format
  (0.0.4): the engine's series, every registered collector (see
  [Your own metrics](#your-own-metrics)) and `http_metrics` if given.
- `observe::debug_handler(telemetry, token)` is an opt-in runtime debug endpoint (`only`'s
  counterpart of Go's pprof pages), answering JSON. Mount it under a wildcard route; the last
  path segment picks the view: `conns` (connection table), `loops` (per-thread counters, totals,
  pool), `slow` (recent slow callbacks), `live` (current live settings). With a token, requests
  need `Authorization: Bearer <token>` (compared in constant time) or get 401. The connection
  table is gathered on a helper thread, never on the I/O thread serving the request. Do not
  expose it publicly without a token.
- `HttpMetrics::middleware()` counts requests by status class, observes latency, tracks
  in-flight requests.
- `observe::access_log()` writes one structured record per response through `only::log`.

## Your own metrics

Anything that implements `only::metrics::Collector` can be registered with the telemetry hub and
then appears on the same `/metrics` endpoint, after the engine's series (ADR-015). No third-party
crate is involved.

```rust,ignore
{{#include ../../../crates/only-http/examples/guide-metrics.rs:collectors}}
```

- `Registry` owns named `Counter`, `Gauge` and `Histogram` instruments (shared atomics, no lock per
  update); asking again for the same name and labels returns the same instrument.
- **Exemplars.** `ExemplarHistogram::new(bounds)` (or `Registry::histogram_with_exemplars`) is
  a histogram whose buckets each remember their latest observation made inside a sampled span, with that span's
  trace and span ids (`HistogramSnapshot::exemplars`); `HttpMetrics::with_exemplars()` does the
  same for the request latency histogram, from the request span. They are exported over OTLP
  (the Prometheus text format has no place for them). A plain `Histogram` pays nothing for them
  (a separate type); an `ExemplarHistogram` observation adds a thread-local read, and inside a
  sampled span a clock read and a `try_lock` that never waits (ADR-064).
- `fn_collector(|out| ...)` turns a closure into a collector run on every scrape; `out.counter`,
  `out.gauge` and `out.histogram` add samples. Invalid names, duplicate label names and kind clashes
  are dropped (counted in `Families::dropped()`), never a panic.
- `Telemetry::register_collector(collector, labels)` adds constant labels to every sample of that
  collector: give each registration its own labels when two collectors report the same families
  (two QUIC servers, say). `unregister_collector(id)` removes it.
- `metrics_handler(telemetry, http)` serves `Telemetry::render_prometheus()` (engine series, then
  the collectors); pass `None` for `http` when `HttpMetrics` is registered as a collector.

The same data without HTTP, as a snapshot:

```rust,ignore
{{#include ../../../crates/only-http/examples/guide-metrics.rs:snapshot}}
```

Ready-made collectors:

| Collector | Series |
|---|---|
| `only_http::observe::HttpMetrics` | `only_http_requests_total{class}`, `only_http_request_duration_seconds`, `only_http_requests_in_flight`, `only_http_requests_by_version_total{version}`; with `with_routes(n)` also `only_http_route_requests_total{method, route, class}` and `only_http_route_request_duration_seconds{method, route}` |
| `only_http::observe::H2Stats` (set in `H2Config::stats`) | `only_http2_connections_open`, `only_http2_connections_total`, `only_http2_streams_open`, `only_http2_streams_total`, `only_http2_resets_total{direction}`, `only_http2_goaways_total{direction}` |
| `only_export::Exporter::collector()` | `only_export_pushes_total{sink, signal, result}` (signal `metrics`, `traces`, `logs`), `only_export_otlp_retries_total`, `only_export_metric_points_rejected_total`, `only_export_{spans,logs}_exported_total`, `_dropped_total`, `_rejected_total`, `_queued`, `only_export_statsd_dropped_series_total` |
| `only_quic::QuicServer` (also what `only_h3::serve` returns) | `only_quic_connections_open` (gauge), `only_quic_connections_accepted_total`, `only_quic_connections_closed_total`, `only_quic_datagrams_total{dir}`, `only_quic_bytes_total{dir}`, `only_quic_packets_sent_total`, `only_quic_packets_lost_total`, `only_quic_lost_bytes_total`, `only_quic_congestion_events_total`, `only_quic_ecn_ce_events_total` |
| `only::tls::TlsStats` from `Tls::stats()` | `only_tls_handshakes_total{side, version}`, `only_tls_resumed_total{side}`, `only_tls_early_data_total{side, outcome}` |

QUIC totals include connections that already closed, so they never go down. Collectors run on
the thread serving the scrape (or the exporter's thread, see [Push export](#push-export-otlp-and-statsd)),
never on an I/O thread's hot path: keep them cheap.

## Per-route metrics and HTTP/2

```rust,ignore
{{#include ../../../crates/only-export/examples/guide-export.rs:routes}}
```

- `HttpMetrics::with_routes(n)` adds a row per route: the method and the **pattern** the router
  matched (`GET /users/:id`), never the raw path, so the number of series is bounded by the
  routes you registered and by `n` (at most 4096). Routes seen after `n` share
  `route="other"`; requests no route matched (404, 405) are `method="*", route="unmatched"`. The
  route is known only inside the router, so install the middleware with `Router::layer`. A
  route's slot is found with one lock-free table probe; the counters are sharded like the
  totals (about 200 bytes per route and shard). `route_snapshot()` reads them without
  Prometheus. `Context::route()` gives the matched `RouteInfo` to your own middleware.
- `H2Stats` counts HTTP/2 connections and streams as the server sees them: gauges of what is
  open now (a stream is open from its `HEADERS` until it is closed or reset; a connection's
  streams close with it), totals, `RST_STREAM` and `GOAWAY` frames sent and received. One
  `H2Stats` can serve several listeners; without `H2Config::stats` nothing is counted.

## Spans

`only::log` has spans as well as records: timed units of work with fields, a parent, a kind and a
status, identified by a W3C trace id and span id. They go to a `Tracer` (an exporter, see below)
when they end, and have their own maximum level, `Off` by default: until it is raised a span
statement costs one relaxed atomic load and creates nothing.

```rust,ignore
{{#include ../../../crates/only-export/examples/guide-export.rs:spans}}
```

- `span!(target: .., Level::Info, "name", key = value, ...)` and `info_span!` ... start a span
  (the fields use the record syntax, without `;` and message). `record`, `set_name`,
  `set_status`, `set_kind` change it; dropping it ends it. `span.enter()` makes it the
  thread's current span until the guard drops: spans started meanwhile are its children, and
  `FmtLogger` adds `trace_id=.. span_id=..` to the records written meanwhile. On an event loop,
  enter a span only around code that runs for it, never across callbacks;
  `only::log::span::enter_context(ctx)` carries a context to another thread.
- only-http starts a **request span** (target `only_http::request`, level `info`, kind server)
  for every HTTP/1.1, HTTP/2 and HTTP/3 request while request spans are enabled: named
  `GET /users/:id` once the router matched (the method alone for unmatched requests), with
  `http.request.method`, `url.path`, `http.route`, `network.protocol.version`,
  `client.address` and `http.response.status_code`; 5xx sets the error status. It is the current
  span while the handler runs and ends when the response head is sent (a detached response ends
  it when it is sent from wherever it is). An incoming `traceparent` header makes it the child of
  the caller's span; `ctx.span_context()` gives the context to propagate downstream
  (`to_traceparent()`).
- **Connection spans** (target `only_http::connection`, level `debug`) cover one connection from
  accept to close, with the client address and protocol version.
- **Events and links.** `span.add_event("retry", &[("attempt", 2u64.into())])` records
  something that happened at one moment of the span (`push_event` takes a ready `SpanEvent` with
  its own time); `span.add_link(ctx, &[..])`, or `SpanBuilder::link(SpanLink::new(ctx))` when the
  span starts, points at another span, of this trace or another (a batch linking the requests it
  serves). A span keeps at most 128 of each (`MAX_EVENTS`, `MAX_LINKS`); more are counted in
  `SpanData::dropped_events` / `dropped_links` and exported as such. On a span that does not
  record they do nothing.
- Sampling is decided once per trace by the tracer (`sample_ratio` of the exporter); a caller's
  `traceparent` flag is followed. An unsampled span still carries its ids (its children and
  outgoing headers stay unsampled) but records nothing.
- Your own tracer: implement `only::log::span::Tracer` (`enabled`, `sample`, `on_end`) and
  install it with `set_tracer` plus `set_max_span_level`. `on_end` runs on the thread that ended
  the span, often an I/O thread: queue the span, never block.

There is no `tracing` bridge: `tracing`'s subscribers need `'static` callsite metadata created
by its own macros, so forwarding only-log spans would mean leaking metadata per span name or
hiding names in fields; OTLP export covers the usual destination, and a `Tracer` can feed
anything else (ADR-020).

## Push export (OTLP and StatsD)

The `only-export` crate pushes metrics, spans and log records from one background thread, with
the workspace's own HTTP, gRPC, TLS and protobuf code and no third-party dependency:

```rust,ignore
{{#include ../../../crates/only-export/examples/guide-export.rs:export}}
```

- **What is sent.** Every `interval` (default 10 s), the same snapshot a scrape renders: the
  engine's series and every registered collector (`Telemetry::collect_all()`), plus collectors
  passed with `.collector(..)`. Spans and log records every `span_interval` (default 2 s), or
  sooner once a batch (512) is queued.
- **OTLP/HTTP** (`otlp_http`, or `otlp_http_with(endpoint, Encoding::Json, headers)`):
  `POST /v1/metrics`, `/v1/traces` and `/v1/logs`, protobuf (`application/x-protobuf`) or
  OTLP/JSON. **OTLP/gRPC** (`otlp_grpc("http://collector:4317")`, `otlp_grpc_with(endpoint,
  metadata)`): the unary `Export` methods of the three collector services, with only-grpc's
  client on a private engine with one client I/O thread, started at the first push. Counters
  become cumulative monotonic sums, gauges gauges, histograms explicit-bucket histograms with
  their exemplars; labels become attributes, `service.name` and `resource_attr(..)` the resource.
  Spans (with their events and links) and records are grouped into one instrumentation scope per
  target. `otlp_traces_only()` keeps metrics out of OTLP when they are scraped or go to StatsD.
- **TLS.** An `https://` endpoint (either protocol) is reached over only-tls, ALPN `h2` for gRPC
  and `http/1.1` for HTTP. The collector's certificate is checked against the system's roots,
  or against `tls_roots(RootCerts)` (a private CA); `tls_client_cert(chain, key)` answers a
  collector that requires client certificates; `tls_server_name(..)` overrides the name checked
  (the endpoint's host by default). TLS options with an `http://` endpoint fail at `start`.
- **Logs.** `logs(level)` installs a logger (the process-wide only-log logger) that turns records
  up to `level` into OTLP `LogRecord`s: the message as body, severity, key-values as attributes,
  `code.file.path` and `code.line.number`, and the trace and span ids of the span current where
  the record was logged, so a collector can show a request's logs next to its trace.
  `forward_logs(FmtLogger::new(), LevelFilter::Warn)` also hands records to another logger. The
  maximum log level becomes the more verbose of the two. Records logged on the exporter's own
  threads are not exported. Like the tracer, a logger is installed once per process.
- **StatsD** (`statsd(addr, Flavor::DogStatsd | Flavor::Statsd)`, `statsd_options(prefix,
  max_packet, max_series)`): counters as the delta since the previous push (`name:3|c`), gauges
  as values (`|g`), histograms as `.count`, `.sum` and per-bucket `.bucket` deltas (with an `le`
  tag). DogStatsD carries labels as tags (`|#route:/users/:id,class:2xx`); plain StatsD appends
  them to the name (`name.class.2xx`). Lines are packed into datagrams of at most 1432 bytes.
  Spans and logs are not sent to StatsD.
- **Off the I/O threads, bounded.** The I/O threads only hand finished spans and records to
  sharded queues (default 4096 each, `span_queue` / `log_queue`): past them items are dropped
  and counted, never waited for. The StatsD delta table keeps at most `max_series` series
  (default 10 000). Each OTLP step (connect, TLS handshake, write, read, or a gRPC call) has a
  timeout (default 5 s) and HTTP responses are read up to 1 MiB.
- **When the collector is away.** A failure that may pass (no connection, a timeout, HTTP 429,
  502, 503, 504, gRPC `UNAVAILABLE`, `DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED` ...) backs the
  collector off: `retry(initial, max, max_elapsed)`, by default 1 s doubling to 30 s with jitter,
  or the server's `Retry-After`. Meanwhile each signal's failed batch waits (one per signal) and
  new items wait in their bounded queues; when the backoff ends, the batch and the queues are
  sent at once, and metrics are pushed again from a fresh snapshot (they are cumulative). A batch
  still failing after `max_elapsed` (default 5 min; `Duration::ZERO` never retries) is dropped
  and counted. Other failures (HTTP 400, gRPC `INVALID_ARGUMENT`, a TLS certificate the client
  rejects ...) drop the batch at once. Items a collector rejects in a partial success are
  counted (`spans_rejected`, `logs_rejected`, `metric_points_rejected`).
- `flush()` pushes now, ignoring a backoff, and waits; a retryable failure ends it, leaving the
  rest queued. `shutdown()` (or dropping the exporter) pushes once more and stops the thread.
  The tracer and the logger can be installed once per process: a second exporter with
  `traces(..)` or `logs(..)` fails to start.

`tools/otel/e2e.sh` runs the end-to-end tests against the OpenTelemetry Collector (contrib) in
Docker: OTLP/HTTP protobuf and JSON and OTLP/gRPC, plain and over TLS with client certificates
(a private CA made by the script), traces with events and links, logs correlated with request
spans, metrics with exemplars, and DogStatsD into its statsd receiver; the collector's file
exporters' output is checked.

## Logs

`only` logs through its own facade, `only-log` (re-exported as `only::log`), with key-value
records. Install a logger once per process to see them:

```rust,ignore
// Formatted lines on stderr: `2026-11-14T08:00:00.000123Z INFO  only: engine started listeners=[...]`
only::log::init(only::log::LevelFilter::Info).unwrap();

// Or: per-target ceilings, stdout, no timestamps ...
only::log::FmtLogger::new()
    .target_level("only_http::access", only::log::LevelFilter::Off)
    .stdout()
    .init(only::log::LevelFilter::Debug)
    .unwrap();

// Or your own sink: implement `only::log::Logger` (`enabled`, `log`, `flush`) and call
// `only::log::set_logger(&MY_LOGGER)` plus `only::log::set_max_level(..)`.
```

A record gives `level()`, `target()`, `args()` (the message, formatted lazily),
`key_values()` (`iter()`, `get("conn_id")`; values implement `Display`) and the source location.
Without a logger installed, errors and slow-callback warnings go to stderr (`only: ...`) so they
are never lost silently; everything else is dropped. The maximum level defaults to `Off` and is
checked first, with one relaxed atomic load, so disabled statements cost well under a
nanosecond.

`FmtLogger` writes each line on the thread that logs, under the stream's lock: if stderr is a
pipe nobody drains, that thread (possibly an I/O thread) blocks. For a server whose log output
may back up, `.non_blocking(only::log::DEFAULT_QUEUE_LINES)` queues formatted lines to a writer
thread (16 384 lines); when the queue is full lines are dropped, counted (`dropped()` on a
clone kept before `init`) and reported in a line of their own once the writer catches up. Call
`only::log::flush()` before exiting. The default stays synchronous, so no line is lost when a
process exits without flushing.

**Per-target levels from the environment.** `only::log::init_from_env(default)` reads `ONLY_LOG`
once, with env_logger-style directives, and installs the formatted logger with them:

```text
ONLY_LOG=info,only_http=debug,only_quic::conn=trace,only_http::access=off ./server
```

`level` sets the level of targets no directive names (without one they are off), `target=level`
the level of a target and its submodules (`target::...`), a bare `target` means `trace`; the most
specific target wins. Unset, `default` applies to everything; unparsable, a line on stderr says
why and `default` applies. Nothing reads the variable unless `init_from_env` is called. The same
syntax builds a filter in code: `"info,only_http=debug".parse::<only::log::Filter>()`, then
`FmtLogger::new().init_filtered(filter)`, or `filter.enabled(metadata)` in your own `Logger`.
Unlike env_logger, `only=debug` does not match `only_http` (targets match on `::` boundaries).

**Message filters.** As with env_logger, a `/regex` after the directives keeps only the records
whose formatted message (not the target, level or key-values) matches the pattern somewhere:

```text
ONLY_LOG='info,only_http=debug/(?i)conn(ection)? (reset|refused)|timed out' ./server
```

Everything after the first `/` is the pattern, spaces and commas included (so it may contain
`/`, which env_logger rejects); an empty pattern filters nothing, and an invalid one is reported
on stderr like any other directive error. The syntax is the `regex` crate's without captures,
look-around and Unicode classes: classes and ranges, Unicode-aware `\d \w \s`, `* + ? {m,n}`
(greedy or lazy), alternation, groups, `^ $ \A \z`, word boundaries `\b \B`, and the flags
`(?i)` (Unicode case folding), `(?m)`, `(?s)`. The engine is `only-regex`, part of the workspace:
a Thompson NFA with a DFA built when the filter is parsed, so matching never backtracks (no
pattern can make a log call slow) and costs about a nanosecond per character of the message.
`FmtLogger` matches the message it formatted for the line anyway; in your own `Logger`,
`filter.matches(record)` checks the level and the message, streaming the message into the
matcher without building a string. A filter without a pattern does not pay for any of this.
In code: `Filter::new(LevelFilter::Info).message_regex("timed out")?`.

**Compile-time caps.** The only-log features `max_level_off` ... `max_level_trace` and
`release_max_level_*` (the latter for builds without debug assertions) remove statements above
the cap at compile time, as in the `log` crate; `only::log::STATIC_MAX_LEVEL` is the result.
Enable them in the application only (features are unified across the dependency graph):
`only-log = { version = "1", features = ["release_max_level_info"] }`.

**Existing `log` setups (env_logger, `tracing-log`, fern ...).** Enable the `log` feature
(`only = { version = "1", features = ["log"] }`). While no only-log logger is installed, every
record goes to the `log` crate's logger with the same level, target, message and key-values, and
`log::max_level()` is the effective maximum; `Config::log_level` sets `log`'s level as well. To
go the other way (records of crates using `log`, such as str0m or rustls, into an only-log
logger) call `only::log::bridge::route_log_to_only()`. The feature is outside the semver promise:
it follows `log` 0.4.

| Target | Level | Records |
|---|---|---|
| `only` | info | `engine started` (listeners), `engine shutting down` (open connections), `configuration reloaded` (applied, ignored) |
| `only` | warn | slow callbacks (`kind`, `conn_id`, `elapsed_us`, `limit_us`, `thread`, `listener`); io_uring / BPF fallbacks |
| `only` | error | poller failures |
| `only` | debug | connections refused by `max_connections` |
| `only` | trace | `connection opened` / `connection closed` (`conn_id`, `peer`, `local`, `dialed`, `error`) |
| `only_http::access` | info | access log: `method`, `target`, `status`, `peer`, `elapsed_us`, `request_id` |

`Config::log_level` (reloadable) calls `only::log::set_max_level`, so verbosity can change at
runtime.

## Slow callbacks

See [Blocking work](concepts/blocking.md#slow-callback-detection). Reports go to
`Config::slow_hook`, else a `warn` log record, else stderr; each one also lands in
`Engine::slow_callbacks()` and the debug endpoint's `slow` view with the callback kind
(`on_data`, `on_close`, `spawn_blocking completion`, ...), duration, threshold and owning thread.

## Hot reload

```rust,ignore
{{#include ../../../crates/only/examples/guide-config.rs:reload}}
```

`Engine::reload(&Config)` (or `Telemetry::reload`) applies the runtime-changeable settings
without a restart and returns a `ReloadReport` with `applied` (what changed) and `ignored`
(settings that differ but need a restart):

| Reloadable | Fixed at build time |
|---|---|
| `idle_timeout`, `slow_callback_threshold`, `slow_hook`, `max_queued_bytes`, `write_high_watermark`, `max_connections`, `shutdown_timeout`, `retire_timeout`, `log_level`, `read_buffer`, `backlog`, `udp_idle_timeout` | `max_pending_responses`, `write_timeout`, `connect_timeout`, `udp_max_peers`, `udp_gro`, listeners, backends, pool sizes |

What happens to what is already open:

- **Idle timeouts** (`idle_timeout`, `udp_idle_timeout`): timers of open connections and UDP peers
  are re-armed against the new value; UDP peers use the shorter of the two.
- **`write_high_watermark`**: backpressure is re-evaluated for every connection.
- **`read_buffer`**: each I/O thread swaps its read buffer between two batches of events, when no
  `on_data` is borrowing it, so open connections read with the new size from their next read on.
  On io_uring the thread registers a second provided-buffer group of the new size (still capped at
  16 KiB) and moves each connection to it when its multishot receive is re-armed; the old group is
  freed once no receive uses it. UDP threads with GRO on keep slots of at least 64 KiB.
- **`backlog`**: every listening socket is `listen(2)`ed again; the kernel updates the queue limit
  of the live socket (capped by `net.core.somaxconn` / `kern.ipc.somaxconn`).

The I/O threads read most live settings with one relaxed load per use and apply the others when
they handle the reload notification, so reloading costs nothing on the hot path. Individual
values can also be changed with the setters on `Telemetry::live()` followed by
`Telemetry::notify_reload()`.

### I/O thread counts

`Engine::threads()` lists the active I/O threads of each listener and client group (in
`local_addrs()` order); `Engine::set_threads(index, n)` changes one while the engine runs
(ADR-028). It returns once the change is posted to the I/O threads, without waiting for it to
take effect (growing into the index of a retired thread that is just exiting joins it first).

- **Growing** starts threads (or reactivates retiring ones). On Linux each new thread binds its own
  `SO_REUSEPORT` socket in the listener's group and the kernel sends it its share of new
  connections; on macOS, and for inherited listeners, it accepts on a clone of the shared socket.
  Dials are spread over all active threads.
- **Shrinking** retires the highest threads. A retiring thread stops accepting at once and hands
  its listening socket to a remaining thread; the socket stays open throughout, so nothing waiting
  in its accept queue is reset. **No connection moves between threads**: a retiring thread keeps
  serving the connections it owns and exits after the last one closed. With
  `Config::retire_timeout`, the ones still open when it expires get `on_shutdown` (HTTP finishes
  the response in flight and closes, WebSocket sends 1001), and are closed `shutdown_timeout`
  later if still open; clients reconnect to the active threads.
- Retiring threads show up in `Metrics::loops` (`retiring: true`), in the Prometheus gauge
  `only_loop_retiring` and in the JSON (`"retiring"`); a thread that exited reports
  `running: false`, and a thread started again at the same index continues its counters.
- Not available for UDP listeners (adding or removing a socket of a UDP `SO_REUSEPORT` group would
  move peers between threads), DPDK, and listeners with `Accel::Ebpf` steering: `Unsupported`.

Under only-prefork, `Controller::reload_in_place()` (or SIGUSR1 to the supervisor) runs each
worker's `Worker::on_reload` hook, where the worker re-reads its configuration and calls
`Engine::reload` and `Engine::set_threads`: see [prefork](prefork.md#reload-in-place).

`only` does not watch configuration files itself: trigger `reload` from whatever you use (a
`SIGHUP` handler, a file watcher, an admin route as in the example above).
