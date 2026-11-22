# akio-log

[中文](README.zh-CN.md)

The logging facade of [`akio`](https://github.com/lesismal/akio), without third-party
dependencies (`#![forbid(unsafe_code)]`). `akio` re-exports it as `akio::log`. It replaces the `log` crate
in every `akio` library; an optional bridge keeps `log`-based setups (env_logger,
`tracing-log` ...) working.

- Levels `Error` .. `Trace` and `LevelFilter` (`Off` .. `Trace`), ordered, parsed and printed
  like the `log` crate's.
- Macros `error!`, `warn!`, `info!`, `debug!`, `trace!`, `log!`, `log_enabled!` with `log`'s
  syntax: `target: "..."`, key-values `key = value`, `key:% = value` (Display),
  `key:? = value` (Debug), then `;` and the format string.
- A global maximum level in an atomic: a disabled statement costs one relaxed load and a
  compare before anything is evaluated. `set_max_level` changes it at run time (`akio`'s
  `Config::log_level` and `Engine::reload` call it).
- `Logger` trait (`enabled`, `log`, `flush`), installed once with `set_logger(&'static ...)` or
  `set_boxed_logger`. Records give level, target, message (`fmt::Arguments`, formatted lazily),
  key-values and source location.
- Built-in loggers: `init(LevelFilter)` installs `FmtLogger` in one call
  (`2026-11-14T08:00:00.000123Z INFO  akio: engine started listeners=[127.0.0.1:8080]`, UTC,
  per-target ceilings, stderr or stdout); `StderrLogger` prints `target: message`.
- `Filter`: per-target levels from env_logger-style directives; `init_from_env(default)` reads
  `AKIO_LOG=info,akio_http=debug,akio_quic::conn=trace` once and installs `FmtLogger` with it
  (opt-in: nothing reads the environment otherwise). Targets match on `::` boundaries, the most
  specific wins. A trailing `/regex` keeps only the records whose message matches it
  (`AKIO_LOG=info,akio_http=debug/connection (reset|refused)`, env_logger's syntax; everything
  after the first `/` is the pattern). The engine is the in-house `akio-regex` (Unicode
  `\d \w \s`, `(?i)`, `\b`, no backtracking, time linear in the message); `FmtLogger` matches the
  message it already formatted for the line, `Filter::matches` streams the message into the
  matcher without building a string, and a filter without a pattern costs nothing extra.
- Compile-time caps, as in the `log` crate: features `max_level_off` .. `max_level_trace` and
  `release_max_level_*` compile statements above the cap out (`STATIC_MAX_LEVEL`). For
  applications only (cargo unifies features across the dependency graph).
- Spans (`akio_log::span`): `span!` / `info_span!` ... start timed spans with fields, a W3C
  trace context (`SpanContext`, `traceparent` in and out), parents from `parent:` or the span
  entered on the thread; finished spans go to a `Tracer` (`set_tracer`). Their own maximum level
  (`set_max_span_level`) is off by default, so a span statement costs one relaxed load until
  enabled. `akio-export` ships a tracer that sends them to an OpenTelemetry collector.
- No logger installed: records are dropped; `log_or_stderr` prints the records it is given to
  stderr (`akio` uses it for errors and fallbacks, and prints slow-callback warnings the same
  way, so they are never lost silently).

```rust
use akio_log::{LevelFilter, info, warn};

akio_log::init(LevelFilter::Info).unwrap();
let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 9000));
info!(target: "app", conn_id = 7u64, peer:% = peer; "connection opened");
warn!("{} retries left", 3);
```

## The `log` bridge (cargo feature `log`)

Enable `akio`'s (or akio-core's / akio-log's) `log` feature:

- **akio-log to `log`**, automatic: while no akio-log logger is installed, records go to
  `log::logger()` with the same level, target, message, location and key-values, and the
  effective maximum level is `log::max_level()`. `set_max_level` also sets `log`'s. An
  application that called `env_logger::init()` sees `akio`'s records as before.
- **`log` to akio-log**, opt-in: `akio_log::bridge::route_log_to_only()` installs a `log::Log`
  adapter so crates logging through `log` (str0m, rustls ...) reach the akio-log logger.
- `From` / `Into` between the level types of both crates.

The two directions never loop. The feature follows `log` 0.4 and is outside the semver promise
(a newer `log` may come in a minor release).

## Cost

`cargo bench -p akio-log --bench overhead` (Apple M-series, release; ns per statement):

| Statement | akio-log | `log` 0.4 |
|---|---|---|
| `trace!` with 2 key-values, level disabled | 0.25-0.29 | 0.36-0.37 |
| `log_enabled!`, disabled | 0.25 | 0.25 |
| `info!` with 2 key-values, enabled, logger discards | 2.3 | 3.0 |
| `Filter::matches`, no message regex | 4.9 | |
| `Filter::matches` with `/connection (reset\|refused)`, 72-byte message (formatting included) | 120 | |

With the `log` feature and no akio-log logger installed, the disabled check also reads
`log::max_level()` (about 0.5 ns). The compile-time cap adds nothing when no cap feature is on
(the benchmark binary is byte-identical on macOS; on x86_64 a disabled `trace!` measured 0.400 ns
before and 0.401 ns after, same run); with a cap, statements above it are gone.
