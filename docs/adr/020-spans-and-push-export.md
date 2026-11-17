# ADR-020: Spans, push export (OTLP, StatsD), per-route HTTP labels and HTTP/2 gauges

English | [简体中文](020-spans-and-push-export.zh-CN.md)

Status: accepted (2026-11-17)

## Context

ADR-015 gave the engine pluggable collectors served by a Prometheus scrape, and left four gaps
listed in DEV-PLAN (M6 "production", the only-log entry): there were no spans (only-log has
records only; "`tracing` feature" was an open item), no push export (StatsD, OTLP), HTTP metrics
had no per-route labels (a cardinality policy was needed), and HTTP/2 had no connection or
stream gauges beyond per-version request counts. The libraries take no third-party dependency
(ADR-005), the I/O threads never block (docs/rules.md rule 1), queues are bounded (rule 7) and
the hot path takes no global lock and no shared refcount per request (rule 12).

## Decision

### Spans in only-log, no `tracing` bridge

A `span` module in only-log (`only::log::span`), dependency-free:

- `SpanContext` (128-bit trace id, 64-bit span id, sampled flag, remote flag) with W3C
  `traceparent` parsing and printing; `Span` (a nullable box: a disabled span is one pointer and
  every method on it is a no-op), `SpanBuilder`, `span!` / `error_span!` ... `trace_span!` with
  the record macros' key-value syntax; `record`, `set_name`, `set_kind`, `set_status`, `enter`
  (thread-local current span, restored by the guard), `in_scope`, `enter_context`, `current`.
- `Tracer` (`enabled`, `sample`, `on_end(SpanData)`), installed once per process
  (`set_tracer` / `set_boxed_tracer`), and a maximum span level of its own
  (`set_max_span_level`, `Off` by default), separate from the log level so enabling logs never
  turns spans on. A span statement checks the compile-time cap and that level (one relaxed
  load) before anything else, like a log statement.
- Parents: an explicit context (possibly remote), else the thread's current span, else a new
  trace. Sampling is decided by the tracer for roots and remote parents; children of a local span
  follow it. Unsampled spans keep their ids (for propagation) and record nothing.
- `FmtLogger` adds `trace_id` / `span_id` to records written inside an entered span.

No `tracing` bridge (not even an optional feature): `tracing` subscribers need `&'static`
callsite metadata built by `tracing`'s macros, so forwarding only-log spans would need either
leaked metadata per distinct span name or a fixed callsite with the name hidden in a field, both
poor for its ecosystem; and the bridge would track a fast-moving crate outside semver. The usual
destination, an OpenTelemetry collector, is covered by push export below, and a `Tracer` is a
three-method trait any application can implement for anything else.

### HTTP instrumentation

only-http starts a request span (target `only_http::request`, level `info`, kind server) at the
three dispatch points (HTTP/1.x, HTTP/2 streams and pushes, the transport seam only-h3 uses),
child of an incoming `traceparent`; enters it for the service call; renames it
`"<method> <route>"` when the router matches; ends it in the response path (`Finish::apply`,
which also runs for detached and streamed responses) with the status code and an error status
for 5xx. The check is `only_log::span::enabled(Level::Info)`, inline, with the work in a cold
function. Connection spans (`only_http::connection`, `debug`) cover HTTP/1.x/HTTP/2 sessions and
HTTP/3 connections (`only_http::trace::connection_span`, used by only-h3). New public items:
`Context::route`, `Context::span_context`, `RouteInfo`, `trace::{REQUEST_TARGET,
CONNECTION_TARGET, connection_span}`.

### Per-route labels

The router interns a `RouteInfo` (method, pattern, process-unique id) per distinct method and
pattern, the way it interns parameter names, and stores it in the `Context` on a match (one
pointer store). `HttpMetrics::with_routes(n)` (n ≤ 4096) maps a route's id to a slot through a
fixed open-addressing table filled lock-free with compare-and-swap; slot counters (status
classes, latency histogram) are sharded like the existing totals. Labels are the pattern, never
the path; routes past `n` share `route="other"`, unmatched requests are `route="unmatched"`.
`HttpMetrics::new()` is unchanged: no table, one predictable branch. `route_snapshot()` and two
new families (`only_http_route_requests_total`, `only_http_route_request_duration_seconds`).

### HTTP/2 gauges

`H2Stats` (sharded relaxed counters, a `Collector`) set through a new `H2Config::stats` field
(`None` by default): connections and streams opened and closed (gauges are their differences),
`RST_STREAM` and `GOAWAY` frames each way. A connection's still-open streams are counted closed
when it closes, once (on close or when the core drops).

### Push export: a new crate, `only-export`

Dependencies: only-core, only-log, only-protobuf (all in-house). One thread (`only-export`):

- metrics every interval: `Telemetry::collect_all()` (new, with `Metrics::collect_into`: the
  engine's series as `Families`, identical to the Prometheus rendering) plus extra collectors;
- OTLP/HTTP, protobuf (hand-encoded with only-protobuf's wire primitives) or JSON, from one
  message tree; counters as cumulative monotonic sums, gauges, explicit-bucket histograms; spans
  grouped by target into scopes;
- StatsD and DogStatsD over UDP: counter deltas against a bounded table of last values, gauges,
  histogram count/sum/bucket deltas, datagrams packed to a size limit;
- spans: `traces(level)` installs a tracer whose `on_end` pushes into a sharded queue bounded
  by a total (default 4096); past it spans are dropped and counted. Batches go out every
  `span_interval` or when one is full (a `try_send` wake-up, never a wait).

A separate crate keeps only-protobuf and the client code out of programs that do not export, and
out of only-core. OTLP over gRPC is not offered: HTTP/protobuf is accepted by every collector and
needs no HTTP/2 client on a background thread. TLS to the collector is not offered: the client is
plain HTTP/1.1 over `std::net`, meant for a local collector or agent.

## Alternatives considered

- **An optional `tracing` feature in only-log** (outside semver, as the `log` bridge is):
  rejected for the callsite reasons above; can be revisited if users ask, as its own crate.
- **Spans sharing the log level**: rejected; an application raising logs to `info` would start
  paying for request spans.
- **Per-route labels keyed by the request path with an LRU**: unbounded input and a lock per
  request; the router already knows the pattern.
- **A mutex-protected route map**: a global lock per request (rule 12).
- **Exporting from the I/O threads, or retrying failed pushes**: blocking and unbounded memory.
- **Putting the exporter in only-core or only-http**: every server would link the protobuf
  runtime and the client.

## Consequences

- Additive public API in only-log, only-core, only-http (`H2Config` gains a field; it is
  `#[non_exhaustive]`, so only struct literals inside the crate change) and a new crate.
- With everything off, the request path adds one atomic load (spans), one pointer store
  (route) and two well-predicted branches; measured in docs/BENCHMARKS.md ("Observability
  overhead").
- A tracer is per process: one exporter with traces per process.
- Not done: OTLP over gRPC, TLS to the collector, OTLP logs, span events and links, exemplars,
  a `tracing` bridge.
