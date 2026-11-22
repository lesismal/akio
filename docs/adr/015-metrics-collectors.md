# ADR-015: Pluggable metrics collectors

English | [简体中文](015-metrics-collectors.zh-CN.md)

Status: accepted (2026-11-16)

## Context

The engine exports its own counters (`Engine::metrics()`, Prometheus text or JSON) and akio-http
serves them with `observe::metrics_handler(telemetry, Option<HttpMetrics>)`. Nothing else can be
added to that endpoint: an application's own counters, or the statistics protocol crates already
keep (QUIC `ConnectionStats`, TLS handshake outcomes, requests per HTTP version), need a second
endpoint or a hand-written handler. The project takes no third-party dependencies (ADR-005), so the
`prometheus` / `metrics` crates are not an option.

## Decision

A new module `akio_core::metrics` (re-exported as `akio::metrics`), dependency-free:

- **`Collector`** trait (`Send + Sync`): `fn collect(&self, out: &mut Families)`. Called on demand
  (a scrape), never on the I/O hot path.
- **`Families`**: the snapshot a scrape builds. `counter` / `gauge` / `histogram` add one sample
  (name, help, labels, value); samples of the same name are grouped into one `Family` whatever
  order they arrive in. Names and label names are checked against the Prometheus grammar and label
  values escaped; a sample with an invalid name, or whose kind differs from its family's, is
  dropped (a scrape never panics). Rendered with `to_prometheus` / `write_prometheus` (text format
  0.0.4) or `to_json`, or read programmatically through `iter` / `get` (`Family`, `Sample`,
  `Value`, `HistogramSnapshot`). `collect_from(collector, labels)` runs a collector with constant
  labels added to each of its samples. Values are `f64`, as in Prometheus.
- **Instruments** for application code: `Counter`, `Gauge`, `Histogram` (cheap clones of an `Arc`,
  relaxed atomics, no locks on update) and `Registry`, a `Collector` that owns named instruments
  (`registry.counter(name, help, labels)` returns the existing instrument when the same name and
  labels are asked for again).
- **Engine hook**: `Telemetry::register_collector(Arc<dyn Collector>, labels) -> CollectorId`,
  `unregister_collector(id)`, `collect()` (the registered collectors' `Families`) and
  `render_prometheus()` (engine series, then the collectors). `metrics_handler` serves
  `render_prometheus()`, so every registered collector appears on the existing endpoint without a
  new handler.
- **Protocol collectors**, each an additive `impl Collector`:
  - akio-http `HttpMetrics` (same series as before, plus `akio_http_requests_by_version_total{version}`,
    which is the request/stream count per HTTP/1.x, h2 and h3);
  - akio-quic `QuicServer` (connections open/accepted/closed, datagrams and bytes each way, packets
    sent and lost, lost bytes, congestion events; totals include connections that already closed);
  - akio-tls `TlsStats`, from `Tls::stats()` (completed handshakes by version and side, resumed
    sessions, early data accepted/rejected). Failed handshakes stay in the engine's
    `akio_tls_handshake_failures_total`.

## Alternatives considered

- **Push export (StatsD, OTLP)**: needs a wire client and a schedule; out of scope. `Families` can
  be rendered into any format later, so push can be built on the same collectors.
- **Routing the engine's own series through `Families`**: rejected for now; `Metrics` keeps its
  exact rendering and its JSON shape (no output change for existing dashboards).
- **Per-route HTTP labels**: separate item (cardinality policy needed).

## Consequences

- Additive public API only (new module, new methods, new trait impls); existing output unchanged
  except one new family in `HttpMetrics`.
- Collectors run while the registry lock is held for the list of collectors only (cloned out
  first), so a slow collector delays a scrape, not the engine.
- Two collectors emitting the same family with the same labels produce duplicate samples; giving
  each registration distinct constant labels (`register_collector(c, &[("server", "a")])`) is the
  caller's job.
