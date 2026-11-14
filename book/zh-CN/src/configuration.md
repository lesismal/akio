# 配置参考

所有配置都是普通的 Rust 值：带公开字段和 `Default` 的结构体，以及带方法的构建器。flash 没有
配置文件格式；用你自己的方式加载（TOML、环境变量、命令行参数），再映射到这些类型上。
**可热更新**表示 `Engine::reload(&Config)` 会把它应用到运行中的 engine，包括已打开的连接
（[可观测性与热更新](observability.md)）。

```rust,ignore
{{#include ../../../crates/flash/examples/guide-config.rs:config}}
```

## `flash::Config`

通过 `EngineBuilder::config(cfg)` 传入；engine 的所有 listener 共享。

| 字段 | 默认值 | 可热更新 | 含义 |
|---|---|---|---|
| `read_buffer` | 64 KiB | 否 | 每个 I/O 线程的读缓冲区；`on_data` 一次最多收到的字节数（io_uring：缓冲区大小为 `min(read_buffer, 16 KiB)`） |
| `write_high_watermark` | 256 KiB | 是 | 连接排队达到此值时暂停读，降到四分之一时恢复 |
| `max_queued_bytes` | 64 MiB | 是 | 每连接排队超过此值后 `send` 返回 `Overloaded` |
| `backlog` | 1024 | 否 | `listen(2)` 的 backlog |
| `idle_timeout` | `None` | 是 | 对端这么久没有发来数据时关闭（`TimedOut`） |
| `slow_callback_threshold` | `Some(100 ms)` | 是 | 报告运行超过此时长的回调；`None` 关闭计时 |
| `slow_hook` | `None` | 是 | 接收报告的 `SlowHook(Arc<dyn Fn(&SlowCallback)>)`（否则写日志/stderr） |
| `udp_idle_timeout` | 60 s | 否 | 丢弃静默的 UDP 对端（设置了更短的 `idle_timeout` 时以它为准） |
| `udp_max_peers` | `None` | 否 | 每个 UDP listener 的最大对端数；超出后新对端被丢弃并计数 |
| `udp_gro` | false | 否 | Linux UDP GRO；需要 `read_buffer` >= 64 KiB |
| `shutdown_timeout` | 10 s | 是 | `shutdown` 之后，超过这么久仍未关闭的连接被强制关闭 |
| `max_connections` | 0（不限） | 是 | 打开的连接数达到此值后，新 accept 的连接立即关闭（全 engine 计数，含 dial 的连接和 UDP 对端） |
| `log_level` | `None` | 是 | 用它调用 `log::set_max_level` |
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

这些都不可热更新：listener、后端和线程数在构建 engine 时就固定了。

`UringConfig`：`entries`（SQ 深度，0 = 默认）、`sqpoll`（内核 SQ 轮询线程，false）、`strict`
（失败而不是回退到 epoll，false）。

`EbpfConfig`：`steering`（默认 `Steering::Cpu`，或按源 IP、源 IP 加端口的 `Steering::Hash`）、
`ebpf_programs`（有特权时优先用 eBPF，true；否则用经典 BPF）、`strict`（失败而不是降级，
false）。

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
| `flash_http::HttpConfig` | `max_header_bytes`：64 KiB，`max_body_bytes`：1 MiB，`h2`：`Some(H2Config::default())` |
| `flash_http::H2Config` | `max_concurrent_streams`：128，`initial_window`：1 MiB，`conn_window`：16 MiB，`max_header_list`：64 KiB，`max_body_bytes`：1 MiB，`max_pending_bytes`：8 MiB |
| `flash_http::files::Files` | `index`：`index.html`，`max_cached_bytes`：256 KiB，`max_open_files`：64，`check_interval`：5 s，`cache_control`：无 |
| `flash_http::middleware::Cors` | `allow_origin`：`*`，`allow_methods`：GET, POST, PUT, PATCH, DELETE, OPTIONS，`allow_headers`：Content-Type, Authorization，`max_age`：600 s |
| `flash_http::middleware::Compress` | `min_bytes`：1024，`level`：6 |
| `flash_http::h2client::H2Options` | `initial_window`：1 MiB，`conn_window`：16 MiB，`enable_push`：false |
| `flash_ws::WsConfig` | `max_message_bytes`：16 MiB，`permessage_deflate`：true，`compress_min_bytes`：128 |
| `flash_http::WsOptions` | `config`：`WsConfig::default()`，`protocols`：无，`origin_allowed`：无 |
| `flash_ws::client::DialOptions` | `config`、`pmd`、`protocols`、`origin`、`headers`、`tls`：无，`server_name`：URL 中的主机，`handshake_timeout`：10 s，`close_timeout`：3 s |
| `flash_h3::H3Config` | `max_body`：8 MiB，`max_field_section`：64 KiB |
| `flash_grpc::GrpcServer` | `max_message`：4 MiB，`compress`：false |
| `flash_arpc::Routes` | `max_body`：64 MiB |
| `flash_kcp::Config` | 见 [KCP](protocols/kcp.md#config) |

## 环境变量

| 变量 | 作用 |
|---|---|
| `FLASH_UDP_GSO=0` | 在 Linux 上关闭 UDP GSO（Linux 4.18+；否则每个进程探测一次） |
| `FLASH_UDP_GRO=0` | 即使设置了 `Config::udp_gro` 也不启用 UDP GRO（Linux 5.0+） |

测试套件还会读取 `FLASH_TEST_BACKEND=uring`（在 io_uring 上运行 engine 测试）和
`FLASH_TEST_EXPECT_EBPF=1`（eBPF 不可用时失败而不是跳过）。

## Cargo feature

| crate | feature | 默认 | 作用 |
|---|---|---|---|
| flash-http | `regex` | 开启 | 正则路由参数（`{id:[0-9]+}`） |
| flash-grpc | `prost` | 关闭 | 用于 prost 消息的 `flash_grpc::codec` 辅助函数 |
