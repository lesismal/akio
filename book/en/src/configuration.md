# Configuration reference

All configuration is plain Rust values: structs with public fields and `Default`, builders with
methods. There is no configuration file format; load yours (TOML, env, flags) and map it onto
these types.

Every config struct is `#[non_exhaustive]` so that settings can be added in minor releases
without breaking you: start from `Default` (or a preset such as `KcpConfig::fast()`) and assign
the fields you need, as below. Struct literals (`Config { .. }`) do not compile outside `only`
([API stability](https://github.com/lesismal/only/blob/main/docs/api-stability.md)). **Reloadable** means `Engine::reload(&Config)` applies it to the running engine,
including open connections ([Observability and hot reload](observability.md)).

```rust,ignore
{{#include ../../../crates/only/examples/guide-config.rs:config}}
```

## `only::Config`

Passed with `EngineBuilder::config(cfg)`; shared by every listener of the engine.

| Field | Default | Reloadable | Meaning |
|---|---|---|---|
| `read_buffer` | 64 KiB | no | read buffer per I/O thread; the most `on_data` receives at once (io_uring: buffers of `min(read_buffer, 16 KiB)`) |
| `write_high_watermark` | 256 KiB | yes | reads pause while a connection has this much queued, resume at a quarter |
| `max_queued_bytes` | 64 MiB | yes | `send` fails with `Overloaded` beyond this per connection |
| `backlog` | 1024 | no | `listen(2)` backlog |
| `idle_timeout` | `None` | yes | close (with `TimedOut`) when the peer sent nothing for this long |
| `slow_callback_threshold` | `Some(100 ms)` | yes | report callbacks running longer; `None` disables timing |
| `slow_hook` | `None` | yes | `SlowHook(Arc<dyn Fn(&SlowCallback)>)` receiving reports (else log/stderr) |
| `udp_idle_timeout` | 60 s | no | drop a silent UDP peer (`idle_timeout` wins when set and shorter) |
| `udp_max_peers` | `None` | no | most peers per UDP listener; new peers beyond are dropped and counted |
| `udp_gro` | false | no | Linux UDP GRO; needs `read_buffer` >= 64 KiB |
| `shutdown_timeout` | 10 s | yes | after `shutdown`, force-close what is still open after this long |
| `max_connections` | 0 (none) | yes | accepted connections beyond this many open ones are closed right away (engine-wide count, dialed and UDP peers included) |
| `log_level` | `None` | yes | calls `log::set_max_level` with it |
| `telemetry` | new hub | – | the engine's `Arc<Telemetry>`; clone it before `build` to wire endpoints |

## `EngineBuilder`

| Method | Default | Meaning |
|---|---|---|
| `listen(Listener)` | – | adds a listener (one backend group each) |
| `config(Config)` | `Config::default()` | engine-wide tunables |
| `pool(PoolConfig)` | see below | the logical pool for `spawn_blocking` |
| `client_threads(n)` | 0 | I/O threads only for `Engine::dial`; without them dials use the last listener's threads |
| `udp_client_threads(n)` | 0 | I/O threads for `Engine::dial_udp`; without them the last UDP listener's threads (or an error) |
| `build()` | – | binds and validates; returns `io::Result<Engine>` |

## `Listener`

| Method | Default | Meaning |
|---|---|---|
| `Listener::tcp(addr)` / `Listener::udp(addr)` | – | port 0 picks a free port |
| `serve(acceptor)` | required | the acceptor (`serve_any` for type-erased ones such as `Mux`) |
| `threads(n)` | one per core | I/O threads of this listener (at least 1) |
| `backend(Backend)` | `Epoll` | `Epoll` (kqueue on macOS) or `IoUring(UringConfig)` |
| `accel(Accel)` | `None` | `Ebpf(EbpfConfig)` for steering |

None of these are reloadable: listeners, backends and thread counts are fixed when the engine is
built.

`UringConfig`: `entries` (SQ depth, 0 = default), `sqpoll` (kernel SQ polling thread, false),
`strict` (fail instead of falling back to epoll, false).

`EbpfConfig`: `steering` (`Steering::Cpu` by default, or `Steering::Hash` by source IP or IP and
port), `ebpf_programs` (prefer eBPF when privileged, true; classic BPF otherwise), `strict`
(fail instead of degrading, false).

## `PoolConfig` (logical pool)

| Field | Default | Meaning |
|---|---|---|
| `min_threads` | 0 | threads kept alive when idle |
| `max_threads` | 8 × cores (at least 8) | started on demand when work is queued and none is idle |
| `queue_capacity` | 65,536 | jobs that may wait; beyond it `spawn_blocking` returns `Overloaded` |
| `keep_alive` | 30 s | idle time before a thread above `min_threads` exits |

## Protocol settings

| Type | Field: default |
|---|---|
| `only_http::HttpConfig` | `max_header_bytes`: 64 KiB, `max_body_bytes`: 1 MiB, `h2`: `Some(H2Config::default())` |
| `only_http::H2Config` | `max_concurrent_streams`: 128, `initial_window`: 1 MiB, `conn_window`: 16 MiB, `max_header_list`: 64 KiB, `max_body_bytes`: 1 MiB, `max_pending_bytes`: 8 MiB |
| `only_http::files::Files` | `index`: `index.html`, `max_cached_bytes`: 256 KiB, `max_open_files`: 64, `check_interval`: 5 s, `cache_control`: none |
| `only_http::middleware::Cors` | `allow_origin`: `*`, `allow_methods`: GET, POST, PUT, PATCH, DELETE, OPTIONS, `allow_headers`: Content-Type, Authorization, `max_age`: 600 s |
| `only_http::middleware::Compress` | `min_bytes`: 1024, `level`: 6 |
| `only_http::h2client::H2Options` | `initial_window`: 1 MiB, `conn_window`: 16 MiB, `enable_push`: false |
| `only_ws::WsConfig` | `max_message_bytes`: 16 MiB, `permessage_deflate`: true, `compress_min_bytes`: 128 |
| `only_http::WsOptions` | `config`: `WsConfig::default()`, `protocols`: none, `origin_allowed`: none |
| `only_ws::client::DialOptions` | `config`, `pmd`, `protocols`, `origin`, `headers`, `tls`: none, `server_name`: URL host, `handshake_timeout`: 10 s, `close_timeout`: 3 s |
| `only_h3::H3Config` | `max_body`: 8 MiB, `max_field_section`: 64 KiB |
| `only_grpc::GrpcServer` | `max_message`: 4 MiB, `compress`: false |
| `only_arpc::Routes` | `max_body`: 64 MiB |
| `only_kcp::KcpConfig` | see [KCP](protocols/kcp.md#config) |

## Environment variables

| Variable | Effect |
|---|---|
| `ONLY_UDP_GSO=0` | disable UDP GSO on Linux (Linux 4.18+; probed once per process otherwise) |
| `ONLY_UDP_GRO=0` | never enable UDP GRO, even with `Config::udp_gro` (Linux 5.0+) |

The test suite also reads `ONLY_TEST_BACKEND=uring` (run the engine tests on io_uring) and
`ONLY_TEST_EXPECT_EBPF=1` (fail instead of skip when eBPF is unavailable).

## Cargo features

| Crate | Feature | Default | Effect |
|---|---|---|---|
| only-http | `regex` | on | no effect (kept for compatibility): regexp route parameters (`{id:[0-9]+}`) are always available |
| only-grpc | `prost` | off | `codec::Message` for prost messages (outside the semver promise) |
| `only`, only-tls, only-quic, only-webrtc | `unstable` | off | raw access to the wrapped rustls / quinn-proto / str0m (outside the semver promise) |
