# 配置参考

所有配置都是普通的 Rust 值：带公开字段和 `Default` 的结构体，以及带方法的构建器。only 没有
配置文件格式；用你自己的方式加载（TOML、环境变量、命令行参数），再映射到这些类型上。

所有配置结构体都是 `#[non_exhaustive]`，这样新设置可以在次版本中加入而不破坏你的代码：从
`Default`（或 `KcpConfig::fast()` 这样的预设）开始，再给需要的字段赋值，如下例。在 only 之外
不能用结构体字面量（`Config { .. }`）构造它们
（[API 稳定性](https://github.com/lesismal/only/blob/main/docs/api-stability.zh-CN.md)）。
**可热更新**表示 `Engine::reload(&Config)` 会把它应用到运行中的 engine，包括已打开的连接
（[可观测性与热更新](observability.md)）。

```rust,ignore
{{#include ../../../crates/only/examples/guide-config.rs:config}}
```

## `only::Config`

通过 `EngineBuilder::config(cfg)` 传入；engine 的所有 listener 共享。

| 字段 | 默认值 | 可热更新 | 含义 |
|---|---|---|---|
| `read_buffer` | 64 KiB | 是 | 每个 I/O 线程的读缓冲区；`on_data` 一次最多收到的字节数（io_uring：缓冲区大小为 `min(read_buffer, 16 KiB)`）；热更新从每个连接的下一次读开始生效 |
| `write_high_watermark` | 256 KiB | 是 | 连接排队达到此值时暂停读，降到四分之一时恢复 |
| `max_queued_bytes` | 64 MiB | 是 | 每连接排队超过此值后 `send` 返回 `Overloaded` |
| `max_pending_responses` | 32 | 否 | 有序（流水线）响应：已预留但尚未写出的响应达到此数时暂停读，降到一半时恢复；排在慢响应之后的响应字节达到 `write_high_watermark` 时同样暂停读，超过 `max_queued_bytes` 时关闭连接；`None` = 不限数量 |
| `backlog` | 1024 | 是 | `listen(2)` 的 backlog；热更新会对活的监听套接字重新 `listen` |
| `idle_timeout` | `None` | 是 | 对端这么久没有发来数据时关闭（`TimedOut`） |
| `write_timeout` | 60 s | 否 | 排队的输出这么久没有任何进展（对端不再读取）时关闭（`TimedOut`）；`None` 关闭此检查 |
| `slow_callback_threshold` | `Some(100 ms)` | 是 | 报告运行超过此时长的回调；`None` 关闭计时 |
| `slow_hook` | `None` | 是 | 接收报告的 `SlowHook(Arc<dyn Fn(&SlowCallback)>)`（否则写日志/stderr） |
| `udp_idle_timeout` | 60 s | 是 | 丢弃静默的 UDP 对端（设置了更短的 `idle_timeout` 时以它为准） |
| `udp_max_peers` | 65536 | 否 | 每个 UDP listener 的最大对端数；超出后新对端被丢弃并计数；`None` 为不限 |
| `udp_gro` | true | 否 | 内核支持时启用 Linux UDP GRO；需要 `read_buffer` >= 64 KiB |
| `connect_timeout` | 10 s | 否 | `Engine::dial` 这么久仍未连上时放弃（`on_error` 收到 `TimedOut`）；`None` 交给操作系统 |
| `shutdown_timeout` | 10 s | 是 | `shutdown` 之后，超过这么久仍未关闭的连接被强制关闭 |
| `retire_timeout` | `None` | 是 | 被 `Engine::set_threads` 退役的 I/O 线程继续服务其连接这么久，然后优雅关闭剩下的（`on_shutdown`，`shutdown_timeout` 后强制关闭）；`None`：直到它们自己关闭 |
| `max_connections` | 0（不限） | 是 | 打开的连接数达到此值后，新 accept 的连接立即关闭（全 engine 计数，含 dial 的连接和 UDP 对端） |
| `log_level` | `None` | 是 | `only::log::LevelFilter`；用它调用 `only::log::set_max_level` |
| `telemetry` | 新的 hub | – | engine 的 `Arc<Telemetry>`；在 `build` 前克隆它来接入端点 |

## `EngineBuilder`

| 方法 | 默认值 | 含义 |
|---|---|---|
| `listen(Listener)` | – | 添加一个 listener（每个一个后端线程组） |
| `config(Config)` | `Config::default()` | 全 engine 的参数 |
| `pool(PoolConfig)` | 见下文 | `spawn_blocking` 使用的逻辑线程池 |
| `client_threads(n)` | 0 | 只用于 `Engine::dial` 的 I/O 线程；没有时 dial 使用最后一个 listener 的线程 |
| `udp_client_threads(n)` | 0 | 用于 `Engine::dial_udp` 的 I/O 线程；没有时使用最后一个 UDP listener 的线程（或报错） |
| `build()` | – | 绑定并校验；返回 `io::Result<Engine>` |

## `Listener`

| 方法 | 默认值 | 含义 |
|---|---|---|
| `Listener::tcp(addr)` / `Listener::udp(addr)` | – | 端口 0 表示选择空闲端口 |
| `serve(acceptor)` | 必填 | acceptor（`Mux` 这类类型擦除的 acceptor 用 `serve_any`） |
| `threads(n)` | 每核一个 | 该 listener 的 I/O 线程数（至少 1） |
| `backend(Backend)` | `Epoll` | `Epoll`（macOS 上为 kqueue）或 `IoUring(UringConfig)` |
| `accel(Accel)` | `None` | 用于分流的 `Ebpf(EbpfConfig)` |

listener 和后端在构建 engine 时就固定了。线程数可以在运行时用 `Engine::set_threads(index, n)`
修改（TCP listener 和 client 组；见[可观测性与热更新](observability.md#io-线程数)）。

`UringConfig`：`entries`（SQ 深度，0 = 默认）、`sqpoll`（内核 SQ 轮询线程，false）、`strict`
（失败而不是回退到 epoll，false）。

`EbpfConfig`：`steering`（默认 `Steering::Cpu`，或按源 IP、源 IP 加端口的 `Steering::Hash`）、
`ebpf_programs`（有特权时优先用 eBPF，true；否则用经典 BPF）、`strict`（失败而不是降级，
false）、`pin_threads`（把 n 个 I/O 线程中的线程 `i` 绑到 `cpu % n == i` 的 CPU 上，false）。

## `PoolConfig`（逻辑线程池）

| 字段 | 默认值 | 含义 |
|---|---|---|
| `min_threads` | 0 | 空闲时也保留的线程数 |
| `max_threads` | 8 × 核数（至少 8） | 有任务排队且没有空闲线程时按需启动 |
| `queue_capacity` | 65,536 | 可以等待的任务数；超出后 `spawn_blocking` 返回 `Overloaded` |
| `keep_alive` | 30 s | 超过 `min_threads` 的线程空闲这么久后退出 |

## 协议设置

| 类型 | 字段：默认值 |
|---|---|
| `only_http::HttpConfig` | `max_header_bytes`：64 KiB，`max_body_bytes`：1 MiB，`h2`：`Some(H2Config::default())`，`head_timeout`：10 s，`keep_alive_timeout`：75 s，`body_timeout`：60 s |
| `only_http::H2Config` | `max_concurrent_streams`：128，`initial_window`：1 MiB，`conn_window`：16 MiB，`max_header_list`：64 KiB，`max_body_bytes`：1 MiB，`max_pending_bytes`：8 MiB，`max_conn_pending_bytes`：32 MiB，`max_resets`：100，`max_control_frames`：1000，`reset_window`：30 s |
| `only_http::files::Files` | `index`：`index.html`，`max_cached_bytes`：256 KiB，`max_open_files`：64，`check_interval`：5 s，`cache_control`：无 |
| `only_http::middleware::Cors` | `allow_origin`：`*`，`allow_methods`：GET, POST, PUT, PATCH, DELETE, OPTIONS，`allow_headers`：Content-Type, Authorization，`max_age`：600 s |
| `only_http::middleware::Compress` | `min_bytes`：1024，`level`：6 |
| `only_http::client::ClientOptions` | `max_head_bytes`：64 KiB，`max_body_bytes`：64 MiB，`idle_timeout`：90 s，`max_idle_per_host`：32，`max_idle`：256 |
| `only_http::h2client::H2Options` | `initial_window`：1 MiB，`conn_window`：16 MiB，`enable_push`：false，`max_header_list`：64 KiB，`max_body_bytes`：64 MiB（缓冲式响应） |
| `only_ws::WsConfig` | `max_message_bytes`：16 MiB，`permessage_deflate`：true，`compress_min_bytes`：128 |
| `only_http::WsOptions` | `config`：`WsConfig::default()`，`protocols`：无，`origin_allowed`：无 |
| `only_ws::client::DialOptions` | `config`、`pmd`、`protocols`、`origin`、`headers`、`tls`：无，`server_name`：URL 中的主机，`handshake_timeout`：10 s，`close_timeout`：3 s |
| `only_media::HubConfig` | `gop_cache_bytes`：16 MiB，`max_streams`：1024，`max_subscribers`：每路径 1000（0：不限） |
| `only_media::rtmp::RtmpConfig` | `chunk_size`：4096，`write_queue_limit`：2 MiB，`max_write_queue`：16 MiB，`handshake_timeout`：10 s，`idle_timeout`：60 s（播放者除外）；消息 16 MiB，每连接未完成消息合计 32 MiB |
| `only_media::rtsp::RtspConfig` | `write_queue_limit`：2 MiB，`max_write_queue`：16 MiB，`request_timeout`：10 s，`session_timeout`：60 s（通告并强制执行） |
| `only_media::srt::SrtConfig` | `max_send_backlog`：2 MiB，`max_conns`：1024（0：不限） |
| `only_media::whip::WhipConfig` | `max_sessions`：256（0：不限） |
| `only_media::hls::HlsConfig` | `target_duration`：2 s，`playlist_size`：6，`keep_segments`：3，`max_bytes`：64 MiB（也约束正在写的分段），`idle_timeout`：30 s |
| `only_webrtc::RtcServer` / `Endpoint` | `max_peers`：1024（0：不限），`connect_timeout`：30 s |
| `only_h3::H3Config` | `max_body`：8 MiB，`max_field_section`：64 KiB |
| `only_h3::H3ClientOptions` | `max_body_bytes`：8 MiB，`max_field_section_bytes`：64 KiB，`request_timeout`：30 s |
| `only_grpc::GrpcServer` | `max_message`：4 MiB，`max_collect_bytes`：64 MiB，`max_deadline`：24 小时，`compress`：false |
| `only_grpc::GrpcClient` | `max_message_bytes`：4 MiB，`max_collect_bytes`：64 MiB，`default_timeout`：30 秒（`unary` / `collect`） |
| `only_arpc::Routes` | `max_body`：64 MiB，`max_streams_per_conn`：1024，`call_timeout`：30 秒 |
| `only_kcp::KcpConfig` | 见 [KCP](protocols/kcp.md#config) |

## 环境变量

| 变量 | 作用 |
|---|---|
| `ONLY_UDP_GSO=0` | 在 Linux 上关闭 UDP GSO（Linux 4.18+；否则每个进程探测一次） |
| `ONLY_UDP_GRO=0` | 无论 `Config::udp_gro` 如何都不启用 UDP GRO（Linux 5.0+） |

测试套件还会读取 `ONLY_TEST_BACKEND=uring`（在 io_uring 上运行 engine 测试）和
`ONLY_TEST_EXPECT_EBPF=1`（eBPF 不可用时失败而不是跳过）。

## Cargo feature

| crate | feature | 默认 | 作用 |
|---|---|---|---|
| only-http | `regex` | 开启 | 无作用（为兼容保留）：正则路由参数（`{id:[0-9]+}`）始终可用 |
| only-grpc | `prost` | 关闭 | 为 prost 消息实现 `codec::Message`（不在 semver 承诺内） |
| only、only-tls、only-quic、only-webrtc | `unstable` | 关闭 | 预留的空 feature：only-tls、only-quic 与 only-webrtc 运行自研的 TLS、QUIC 与 WebRTC，已没有被封装的依赖 |
