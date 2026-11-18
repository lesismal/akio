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
| `read_buffer` | 64 KiB | yes | read buffer per I/O thread; the most `on_data` receives at once (io_uring: buffers of `min(read_buffer, 16 KiB)`); a reload applies from each connection's next read |
| `write_high_watermark` | 256 KiB | yes | reads pause while a connection has this much queued, resume at a quarter |
| `max_queued_bytes` | 64 MiB | yes | `send` fails with `Overloaded` beyond this per connection |
| `max_pending_responses` | 32 | no | ordered (pipelined) responses: reads pause while this many reserved responses are not yet written, and resume at half; responses held back behind a slow one also pause reads at `write_high_watermark` bytes and close the connection past `max_queued_bytes`; `None` = no count limit |
| `backlog` | 1024 | yes | `listen(2)` backlog; a reload `listen`s the live sockets again |
| `idle_timeout` | `None` | yes | close (with `TimedOut`) when the peer sent nothing for this long |
| `write_timeout` | 60 s | no | close (with `TimedOut`) when queued output made no progress for this long: a peer that stopped reading; `None` disables it |
| `slow_callback_threshold` | `Some(100 ms)` | yes | report callbacks running longer; `None` disables timing |
| `slow_hook` | `None` | yes | `SlowHook(Arc<dyn Fn(&SlowCallback)>)` receiving reports (else log/stderr) |
| `udp_idle_timeout` | 60 s | yes | drop a silent UDP peer (`idle_timeout` wins when set and shorter) |
| `udp_max_peers` | 65536 | no | most peers per UDP listener; new peers beyond are dropped and counted; `None` = no limit |
| `udp_gro` | true | no | Linux UDP GRO where the kernel supports it; needs `read_buffer` >= 64 KiB |
| `connect_timeout` | 10 s | no | `Engine::dial` gives up (`TimedOut` to `on_error`) when not connected after this long; `None` leaves it to the OS |
| `shutdown_timeout` | 10 s | yes | after `shutdown`, force-close what is still open after this long |
| `retire_timeout` | `None` | yes | an I/O thread retired by `Engine::set_threads` serves its connections this long, then shuts the rest down gracefully (`on_shutdown`, force-closed after `shutdown_timeout`); `None`: until they close |
| `max_connections` | 0 (none) | yes | accepted connections beyond this many open ones are closed right away (engine-wide count, dialed and UDP peers included) |
| `log_level` | `None` | yes | `only::log::LevelFilter`; calls `only::log::set_max_level` with it |
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

Listeners and backends are fixed when the engine is built. Thread counts change at runtime with
`Engine::set_threads(index, n)` (TCP listeners and client groups; see
[Observability and hot reload](observability.md#io-thread-counts)).

`UringConfig`: `entries` (SQ depth, 0 = default), `sqpoll` (kernel SQ polling thread, false),
`strict` (fail instead of falling back to epoll, false).

`EbpfConfig`: `steering` (`Steering::Cpu` by default, or `Steering::Hash` by source IP or IP and
port), `ebpf_programs` (prefer eBPF when privileged, true; classic BPF otherwise), `strict`
(fail instead of degrading, false), `pin_threads` (pin I/O thread `i` of `n` to the CPUs with
`cpu % n == i`, false).

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
| `only_http::HttpConfig` | `max_header_bytes`: 64 KiB, `max_body_bytes`: 1 MiB, `h2`: `Some(H2Config::default())`, `head_timeout`: 10 s, `keep_alive_timeout`: 75 s, `body_timeout`: 60 s |
| `only_http::H2Config` | `max_concurrent_streams`: 128, `initial_window`: 1 MiB, `conn_window`: 16 MiB, `max_header_list`: 64 KiB, `max_body_bytes`: 1 MiB, `max_pending_bytes`: 8 MiB, `max_conn_pending_bytes`: 32 MiB, `max_resets`: 100, `max_control_frames`: 1000, `reset_window`: 30 s |
| `only_http::files::Files` | `index`: `index.html`, `max_cached_bytes`: 256 KiB, `max_open_files`: 64, `check_interval`: 5 s, `cache_control`: none |
| `only_http::middleware::Cors` | `allow_origin`: `*`, `allow_methods`: GET, POST, PUT, PATCH, DELETE, OPTIONS, `allow_headers`: Content-Type, Authorization, `max_age`: 600 s |
| `only_http::middleware::Compress` | `min_bytes`: 1024, `level`: 6 |
| `only_http::client::ClientOptions` | `max_head_bytes`: 64 KiB, `max_body_bytes`: 64 MiB, `idle_timeout`: 90 s, `max_idle_per_host`: 32, `max_idle`: 256 |
| `only_http::h2client::H2Options` | `initial_window`: 1 MiB, `conn_window`: 16 MiB, `enable_push`: false, `max_header_list`: 64 KiB, `max_body_bytes`: 64 MiB (buffered responses) |
| `only_ws::WsConfig` | `max_message_bytes`: 16 MiB, `permessage_deflate`: true, `compress_min_bytes`: 128 |
| `only_http::WsOptions` | `config`: `WsConfig::default()`, `protocols`: none, `origin_allowed`: none |
| `only_ws::client::DialOptions` | `config`, `pmd`, `protocols`, `origin`, `headers`, `tls`: none, `server_name`: URL host, `handshake_timeout`: 10 s, `close_timeout`: 3 s, `proxy`: none, `max_redirects`: 0 |
| `only_media::HubConfig` | `gop_cache_bytes`: 16 MiB, `max_streams`: 1024, `max_subscribers`: 1000 per path (0: no limit) |
| `only_media::rtmp::RtmpConfig` | `chunk_size`: 4096, `write_queue_limit`: 2 MiB, `max_write_queue`: 16 MiB, `handshake_timeout`: 10 s, `idle_timeout`: 60 s (players exempt); messages 16 MiB, unfinished messages 32 MiB per connection |
| `only_media::rtsp::RtspConfig` | `write_queue_limit`: 2 MiB, `max_write_queue`: 16 MiB, `request_timeout`: 10 s, `session_timeout`: 60 s (advertised and enforced) |
| `only_media::srt::SrtConfig` | `max_send_backlog`: 2 MiB, `max_conns`: 1024 (0: no limit) |
| `only_media::whip::WhipConfig` | `max_sessions`: 256 (0: no limit) |
| `only_media::hls::HlsConfig` | `target_duration`: 2 s, `playlist_size`: 6, `keep_segments`: 3, `max_bytes`: 64 MiB (bounds the segment being written too), `idle_timeout`: 30 s |
| `only_webrtc::RtcServer` / `Endpoint` | `max_peers`: 1024 (0: no limit), `connect_timeout`: 30 s |
| `only_h3::H3Config` | `max_body_bytes`: 8 MiB, `max_field_section_bytes`: 64 KiB, `qpack_max_table_capacity`: 4096, `qpack_blocked_streams`: 16, `qpack_encoder_capacity`: 0 (off) |
| `only_h3::H3ClientOptions` | `max_body_bytes`: 8 MiB, `max_field_section_bytes`: 64 KiB, `request_timeout`: 30 s, `qpack_max_table_capacity`: 4096, `qpack_blocked_streams`: 16, `qpack_encoder_capacity`: 0 (off) |
| `only_grpc::GrpcServer` | `max_message`: 4 MiB, `max_collect_bytes`: 64 MiB, `max_deadline`: 24 h, `compress`: false |
| `only_grpc::GrpcClient` | `max_message_bytes`: 4 MiB, `max_collect_bytes`: 64 MiB, `default_timeout`: 30 s (`unary` / `collect`) |
| `only_arpc::Routes` | `max_body`: 64 MiB, `max_streams_per_conn`: 1024, `call_timeout`: 30 s |
| `only_kcp::KcpConfig` | see [KCP](protocols/kcp.md#config) |

## Environment variables

| Variable | Effect |
|---|---|
| `ONLY_UDP_GSO=0` | disable UDP GSO on Linux (Linux 4.18+; probed once per process otherwise) |
| `ONLY_UDP_GRO=0` | never enable UDP GRO, whatever `Config::udp_gro` says (Linux 5.0+) |
| `ONLY_UDP_ECN=0` | never set an ECN codepoint on outgoing UDP datagrams (QUIC marks ECT(0) on Linux and macOS otherwise) |
| `ONLY_LOG=...` | log filter directives (`info,only_http=debug`), read only when the application calls `only::log::init_from_env` |

Test and diagnostic knob (ADR-029), not a tuning setting: `ONLY_DEFAULT_BACKEND=uring` (Linux)
serves every TCP listener that does not call `Listener::backend` with io_uring (non-strict: it falls
back to epoll with a warning where io_uring is unavailable), so an unchanged program can be run
on io_uring; `book/check-guides.sh` uses it. An explicit `Listener::backend` always wins; UDP
listeners and client threads are not affected; it is read once per `Engine::build`.

The test suite also reads `ONLY_TEST_BACKEND=uring` (run the engine tests on io_uring) and
`ONLY_TEST_EXPECT_EBPF=1` (fail instead of skip when eBPF is unavailable).

## Cargo features

| Crate | Feature | Default | Effect |
|---|---|---|---|
| only-http | `regex` | on | no effect (kept for compatibility): regexp route parameters (`{id:[0-9]+}`) are always available |
| only-grpc | `prost` | off | `codec::Message` for prost messages (outside the semver promise) |
| `only`, only-tls, only-quic, only-webrtc | `unstable` | off | reserved and empty: only-tls, only-quic and only-webrtc run their own TLS, QUIC and WebRTC, so nothing is wrapped any more |
