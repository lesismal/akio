# Observability and hot reload

Every engine owns a **telemetry hub** (`flash::Telemetry`): per-thread counters, the connection
table, slow-callback records and the live (reloadable) settings. It is reachable as
`Config::telemetry` before the engine is built and as `Engine::telemetry()` afterwards. The I/O
threads update plain per-thread counters with relaxed atomics (cache-line aligned, nothing
locked or allocated per event); snapshots are assembled on demand.

## From code

```rust,ignore
{{#include ../../../crates/flash/examples/guide-config.rs:observe}}
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
| `flash_connections_accepted_total`, `flash_connections_dialed_total`, `flash_connections_closed_total` | counter |
| `flash_connections_rejected_total` (max_connections), `flash_accept_errors_total`, `flash_idle_timeouts_total` | counter |
| `flash_read_bytes_total`, `flash_reads_total`, `flash_written_bytes_total`, `flash_writes_total` | counter |
| `flash_udp_datagrams_received_total`, `flash_udp_datagrams_sent_total` | counter |
| `flash_send_queue_bytes` | gauge |
| `flash_backpressure_events_total`, `flash_overloaded_total` | counter |
| `flash_tls_handshake_failures_total`, `flash_transport_errors_total` | counter |
| `flash_loop_iterations_total`, `flash_loop_events_total`, `flash_loop_callbacks_total`, `flash_loop_callback_seconds_total`, `flash_slow_callbacks_total` | counter |
| `flash_connections_open`, `flash_loop_running` | gauge |
| `flash_pool_threads`, `flash_pool_active`, `flash_pool_queued` | gauge |
| `flash_pool_completed_total`, `flash_pool_panicked_total`, `flash_pool_rejected_total` | counter |
| `flash_uptime_seconds` | gauge |

HTTP series from `observe::HttpMetrics`: `flash_http_requests_total{class="2xx"...}`,
`flash_http_request_duration_seconds` (histogram, buckets from 0.5 ms to 10 s),
`flash_http_requests_in_flight`.

`flash_loop_callback_seconds_total / flash_loop_iterations_total` and the slow-callback counter
are the first things to watch: they tell you whether handlers are keeping the I/O threads busy.

## HTTP endpoints

```rust,ignore
{{#include ../../../crates/flash-http/examples/guide-observe.rs:endpoints}}
```

- `observe::metrics_handler(telemetry, Some(http_metrics))` answers the Prometheus text format
  (0.0.4).
- `observe::debug_handler(telemetry, token)` is an opt-in runtime debug endpoint (flash's
  counterpart of Go's pprof pages), answering JSON. Mount it under a wildcard route; the last
  path segment picks the view: `conns` (connection table), `loops` (per-thread counters, totals,
  pool), `slow` (recent slow callbacks), `live` (current live settings). With a token, requests
  need `Authorization: Bearer <token>` (compared in constant time) or get 401. The connection
  table is gathered on a helper thread, never on the I/O thread serving the request. Do not
  expose it publicly without a token.
- `HttpMetrics::middleware()` counts requests by status class, observes latency, tracks
  in-flight requests.
- `observe::access_log()` writes one structured record per response through the `log` facade.

## Logs

flash logs through the [`log`](https://docs.rs/log) facade with key-value records; install any
backend (env_logger, a `log`-to-`tracing` bridge, ...) to see them. Without a logger installed,
errors and slow-callback warnings go to stderr so they are never lost silently.

| Target | Level | Records |
|---|---|---|
| `flash` | info | `engine started` (listeners), `engine shutting down` (open connections), `configuration reloaded` (applied, ignored) |
| `flash` | warn | slow callbacks (`kind`, `conn_id`, `elapsed_us`, `limit_us`, `thread`, `listener`); io_uring / BPF fallbacks |
| `flash` | error | poller failures |
| `flash` | debug | connections refused by `max_connections` |
| `flash` | trace | `connection opened` / `connection closed` (`conn_id`, `peer`, `local`, `dialed`, `error`) |
| `flash_http::access` | info | access log: `method`, `target`, `status`, `peer`, `elapsed_us`, `request_id` |

`Config::log_level` (reloadable) calls `log::set_max_level`, so verbosity can change at runtime.

## Slow callbacks

See [Blocking work](concepts/blocking.md#slow-callback-detection). Reports go to
`Config::slow_hook`, else a `warn` log record, else stderr; each one also lands in
`Engine::slow_callbacks()` and the debug endpoint's `slow` view with the callback kind
(`on_data`, `on_close`, `spawn_blocking completion`, ...), duration, threshold and owning thread.

## Hot reload

```rust,ignore
{{#include ../../../crates/flash/examples/guide-config.rs:reload}}
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

flash does not watch configuration files itself: trigger `reload` from whatever you use (a
`SIGHUP` handler, a file watcher, an admin route as in the example above).
