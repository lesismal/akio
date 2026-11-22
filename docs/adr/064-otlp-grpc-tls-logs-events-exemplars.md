# ADR-064: OTLP over gRPC and TLS, OTLP logs, span events and links, exemplars, export retry

English | [简体中文](064-otlp-grpc-tls-logs-events-exemplars.zh-CN.md)

Status: accepted (2026-11-20)

## Context

ADR-020 added push export (`akio-export`: OTLP/HTTP and StatsD from one background thread) and
left five gaps in DEV-PLAN (the ADR-020 entry of M6): OTLP over gRPC, TLS to the collector, OTLP
logs, span events and links, and exemplars. It also chose to drop failed pushes rather than
retry them. Since then the workspace gained its own gRPC client (akio-grpc on akio-http's HTTP/2
client), TLS stack (akio-tls) and protobuf runtime (akio-protobuf), so none of these needs a
third-party crate (ADR-005). The constraints are unchanged: nothing is exported from an I/O
thread (docs/rules.md rule 1), every queue is bounded with a safe default (rules 7 and 10), and
a statement whose signal is off costs what it cost before.

## Decision

### Span events and links (akio-log)

`SpanEvent` (name, time, fields) and `SpanLink` (a `SpanContext`, fields), both
`#[non_exhaustive]` with constructors and a `field` builder. `Span::add_event(name, &[(key,
FieldValue)])` stamps the event with the span's clock (start plus the monotonic elapsed time,
like the end); `Span::push_event` takes a ready event; `Span::add_link` and `SpanBuilder::link`
add links (OpenTelemetry recommends links at creation, where a sampler could see them). Each
span keeps at most `MAX_EVENTS` = `MAX_LINKS` = 128 (OpenTelemetry's defaults); more are counted
in `SpanData::dropped_events` / `dropped_links` and exported as OTLP's dropped counts.
`SpanData` (`#[non_exhaustive]`) gains the four fields. On a disabled or unsampled span the
methods do nothing; the disabled path (a null `Span`) is untouched.

### Exemplars (akio-core, akio-http)

`Exemplar` (value, time, trace id, span id) and `ExemplarReservoir`: one slot per bucket keeping
the latest observation made inside a sampled span (OpenTelemetry's aligned-histogram reservoir).
`offer_current` reads the thread's current span (akio-log's thread-local) and, when it is
sampled, the clock, then `try_lock`s the slot: never a wait; when two threads offer to one bucket
at once one exemplar is kept. `ExemplarHistogram` (a `Histogram` plus a reservoir, `ExemplarHistogram::new(bounds)` or
`Registry::histogram_with_exemplars`) is a type of its own, so a plain `Histogram::observe` is
the same code as before (a flag inside `Histogram` cost one branch, measured at 4% of a 4.7 ns
observation on gpu51);
`HistogramSnapshot::exemplars` carries them (`with_exemplars` sets them on a snapshot). In
akio-http, `HttpMetrics::with_exemplars()` keeps exemplars of the request-latency histogram:
the middleware captures the request span's context at dispatch (only when exemplars are on and
the span is sampled) and offers the latency when the response goes out, so a detached response
still points at its request span. Exemplars are exported over OTLP (`HistogramDataPoint.exemplars`,
hex ids in OTLP/JSON); the Prometheus 0.0.4 text format has no place for them and is unchanged.

### OTLP logs (akio-export)

`ExporterBuilder::logs(level)` installs a logger (`akio_log::set_boxed_logger`) that copies each
record up to `level` into a bounded, sharded queue (the span queue's code, now generic):
time, level, target, the formatted message, key-values as `FieldValue`s, file and line, and
`span::current()` (the span current on the logging thread). The exporter sends them as
`ExportLogsServiceRequest`: one scope per target, severity number and text, body, attributes
plus `code.file.path` and `code.line.number`, `trace_id`, `span_id` and the trace flags.
`forward_logs(logger, level)` also hands records to another logger (stderr, a file); the global
maximum level is set to the more verbose of the two (`Config::log_level`, applied by the engine
later, wins). Records logged on the exporter's own threads (its worker and the gRPC engine's I/O
thread, marked by a thread-local) are not exported: no feedback from logs about exporting logs.
Like the tracer, a logger is installed once per process; `start` checks both before installing
either (neither can be uninstalled). The default queue holds 4096 records, batches of 512.

### OTLP over gRPC

`otlp_grpc(endpoint)` / `otlp_grpc_with(endpoint, metadata)` call the unary `Export` methods of
`MetricsService`, `TraceService` and `LogsService` with akio-grpc's `GrpcClient`, over
`H2Client` on a private `Engine` with one client I/O thread, built and started on the exporter
thread at the first push (`shutdown_timeout` 200 ms so closing is immediate). The exporter
thread blocks in `unary` (bounded by the timeout); the I/O thread only runs the connection's
callbacks. A call failing with `UNAVAILABLE`, `DEADLINE_EXCEEDED` or `CANCELLED` drops the
connection so the next push dials again. The request bodies are the same protobuf the HTTP path
sends (one encoder). Sharing the application's engine was considered: it would put the
exporter's connection on an application I/O thread and tie the exporter's life to the engine's;
one extra thread is cheaper than that coupling.

### TLS to the collector

`https://` endpoints are accepted for both protocols. Configuration: `tls_roots(RootCerts)` (a
private CA; default `RootCerts::system()`), `tls_client_cert(chain, key)` (mutual TLS),
`tls_server_name(name)` (default: the endpoint's host). The exporter builds the akio-tls
`ClientConfig` itself so the ALPN is right (`h2` for gRPC, `http/1.1` for HTTP). OTLP/HTTP runs
the blocking `akio_tls::stream::Stream` over the `TcpStream` (read and write timeouts bound the
handshake too); gRPC passes the config to `H2Client::dial`. TLS options with an `http://`
endpoint, or without OTLP, fail at `start` rather than being silently ignored.

### Retry with backoff

ADR-020 dropped failed pushes. With a collector that restarts or sheds load, that loses every
span ended during the outage; with bounded queues a retry costs bounded memory, so it is now
the default. A failure that may pass (no connection, a timeout, HTTP 429 / 502 / 503 / 504, gRPC
`CANCELLED`, `DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED`, `ABORTED`, `OUT_OF_RANGE`,
`UNAVAILABLE`, `DATA_LOSS`: the OTLP specification's list) puts the collector in backoff, shared
by the signals since they go to one place: `retry(initial, max, max_elapsed)`, default 1 s
doubling to 30 s with jitter (half to all of the nominal delay), or the server's `Retry-After`
(seconds, capped by `max_elapsed`). The failed batch of each signal is kept (one per signal,
already encoded) and sent again when the backoff ends, before new items; new spans and records
wait in their bounded queues; metrics are not kept but pushed from a fresh snapshot when the
backoff ends (cumulative temporality makes the missed ones redundant). A batch older than
`max_elapsed` (default 5 min; zero disables retries) is dropped and counted. Other failures
(HTTP 4xx other than 429, gRPC `INVALID_ARGUMENT`, `UNAUTHENTICATED` ..., a certificate the
client rejects is a connection failure and so retried) drop the batch at once.
Memory while the collector is away: the queues' bounds plus one encoded batch per signal.

`flush()` ignores the backoff once, and a retryable failure ends the round, so a flush (or the
last push of `shutdown`) against a dead collector waits for one timeout, not one per signal.
After the backoff ends the worker sends the waiting batch and drains the queues at once instead
of at the next `span_interval`.

### Partial success, statistics

Responses are read (HTTP bodies up to 1 MiB, as before; gRPC messages) and their
`partial_success` decoded with akio-protobuf's reader: rejected items are counted
(`metric_points_rejected`, `spans_rejected`, `logs_rejected`) and not retried. `ExportStats`
(`#[non_exhaustive]`) gains `otlp_logs_ok/failed`, `otlp_retried`, the rejected counts and the
log queue's exported / dropped / queued; `spans_queued` and `logs_queued` include the batch
waiting to be retried. The stats collector adds `akio_export_pushes_total{signal="logs"}`,
`akio_export_otlp_retries_total`, `akio_export_metric_points_rejected_total`,
`akio_export_logs_*` and `akio_export_spans_rejected_total`.

### Dependencies

akio-export now depends on only, akio-http, akio-grpc and akio-tls (all in-house; akio-tls was
already in every program that uses `akio`). They are not optional features: a program that
exports is a program built on `akio`, which links them already, and features would multiply the
API snapshot and the test matrix for no saving.

## Alternatives considered

- **gRPC over a hand-written HTTP/2 client on `std::net`**: a second HTTP/2 implementation to
  keep correct; akio-grpc's client already interoperates with the collector's grpc-go.
- **Retrying metrics snapshots too**: cumulative sums make an old snapshot redundant once a new
  one is sent; keeping them would grow memory with the outage.
- **Unbounded retry (never give up)**: a collector that never comes back would hold a batch per
  signal for ever and keep the queues full; `max_elapsed` bounds that, and setting it high is a
  choice.
- **Exemplars on every histogram**: a thread-local read on every observation of every histogram
  in every program. Even an opt-in flag inside `Histogram` cost a branch per observation
  (4% in the micro-benchmark), hence the separate type.
- **Exemplars in the Prometheus text output**: only OpenMetrics carries them; the 0.0.4 format
  `metrics_handler` serves is unchanged.
- **Log records as span events**: OpenTelemetry treats them as separate signals correlated by
  ids; collectors and backends index them that way.
- **A log appender trait instead of installing the logger**: one logger per process is how
  akio-log works; `forward_logs` covers keeping stderr output.

## Consequences

- Additive public API in akio-log, akio-core, akio-http and akio-export (fields of
  `#[non_exhaustive]` structs, new types, methods and constants); the API snapshots only grow.
- Behaviour change in akio-export: failed pushes are retried with backoff (previously dropped),
  `https://` endpoints are accepted (previously an error). `ExporterBuilder::retry(.., ..,
  Duration::ZERO)` restores dropping failed batches (the collector is still backed off).
- With everything off, nothing changed on the hot paths: a disabled span or log statement is
  the same atomic load (same-run A/B 0.994–1.009, docs/BENCHMARKS.md "OTLP export additions"), a
  plain `Histogram` is unchanged (exemplars live in `ExemplarHistogram`), and
  `HttpMetrics` without exemplars one branch per request (unmeasurable: 0.999 and 1.001).
- A process with the gRPC exporter runs one more thread (the private engine's I/O thread).
- Not done: exponential histograms, gzip request compression, gRPC `RetryInfo` details (the
  exporter's own backoff applies), OpenMetrics exemplars, a `tracing` bridge.
