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
`only_http_requests_in_flight`.

`only_loop_callback_seconds_total / only_loop_iterations_total` and the slow-callback counter
are the first things to watch: they tell you whether handlers are keeping the I/O threads busy.

## HTTP endpoints

```rust,ignore
{{#include ../../../crates/only-http/examples/guide-observe.rs:endpoints}}
```

- `observe::metrics_handler(telemetry, Some(http_metrics))` answers the Prometheus text format
  (0.0.4).
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
| `idle_timeout`, `slow_callback_threshold`, `slow_hook`, `max_queued_bytes`, `write_high_watermark`, `max_connections`, `shutdown_timeout`, `log_level` | `read_buffer`, `backlog`, `udp_idle_timeout`, listeners, backends, thread counts, pool sizes |

Open connections pick up a new idle timeout and watermark right away (timers are re-armed and
backpressure re-evaluated). UDP listeners keep the idle timeout they were built with. The I/O
threads read live settings with one relaxed load per use, so reloading costs nothing on the hot
path. Individual values can also be changed with the setters on `Telemetry::live()` followed by
`Telemetry::notify_reload()`.

`only` does not watch configuration files itself: trigger `reload` from whatever you use (a
`SIGHUP` handler, a file watcher, an admin route as in the example above).
