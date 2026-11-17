# ADR-009：引擎上限与超时的安全默认值

[English](009-safe-defaults.md) | 简体中文

状态：已接受（2026-11-16）

## 背景

[docs/rules.zh-CN.md](../rules.zh-CN.md)（规则 10）要求每种资源都有带安全默认值的上限，使什么都不设置的
配置仍然有界。按这条规则审查引擎（`only_core::Config`），发现三个默认值把控制权交给了远端：

- `write_timeout: None`：不再读取的对端会让它的连接以及最多 `max_queued_bytes`（64 MiB）的排队输出
  永远存在。
- `udp_max_peers: None`：每个来自新源地址的数据报都会创建一个存活 `udp_idle_timeout`（60 s）的对端，
  伪造源地址可以让这张表无限增长。
- `Engine::dial` 没有连接超时：发往丢弃 SYN 的地址时要等操作系统（Linux 上 75–130 s），所有基于
  `dial` 的客户端（HTTP、h2、gRPC、arpc、SOCKS 上游、BitTorrent）都继承了这一点。

改变默认值会改变现有配置的行为，因此在此记录。

## 决定

1. **`write_timeout` 默认 60 s**（nginx `send_timeout`）。只有排队的输出整整一个周期都没有进展时才
   触发，慢但仍在读取的对端不受影响。
2. **`udp_max_peers` 默认每个 listener 65536。** 超出后来自新对端的数据报被丢弃并计入
   `UdpStats::rejected`；已知对端不受影响。预期单个 listener 有更多并发对端的服务器调大它。
3. **新增 `Config::connect_timeout: Option<Duration>`，默认 10 s。** 超时后仍未完成的 dial 在其 I/O
   线程上被放弃（epoll、kqueue 和 io_uring；io_uring 上会取消挂起的 poll），`on_error` 收到
   `ErrorKind::TimedOut`。`None` 恢复原来的行为。only-dpdk 本来就有自己的 10 s。
4. **引擎层的 `idle_timeout` 仍为 `None`。** "空闲"的含义取决于协议：长连接的 RPC 或 WebSocket 可以
   合理地长时间静默，而 HTTP keep-alive 连接不应如此。各协议 crate 自己负责超时（读请求头、keep-alive、
   握手、协议嗅探），并有各自的安全默认值。
5. **`max_connections` 仍为 0（引擎不设上限）。** 进程的打开文件数上限已经约束了接受的连接数，`accept`
   因 `EMFILE` 失败时 listener 会退避而不是空转。曾考虑由 `RLIMIT_NOFILE` 推算默认值并否决：UDP 对端
   计入 `max_connections` 却不占用描述符，这样的默认值会让繁忙的 QUIC 服务器拒绝 TCP 连接。文档建议把它
   设为低于打开文件数上限的值。

## 影响

- 由 `Config::default()` 构建的配置可以抵御停止读取的对端、伪造源地址的 UDP 洪泛和无应答的 dial。依赖
  dial 等待超过 10 s、允许对端停滞超过 60 s 或每个 listener 超过 65536 个 UDP 对端的代码需要显式设置
  对应字段。
- `Config::connect_timeout` 是新增的公开 API（`Config` 是 `#[non_exhaustive]`）。
- 各协议 crate 对自己的资源遵循同样的规则；同一改动中选定的默认值（HTTP、gRPC/arpc、WebSocket、媒体、
  QUIC/HTTP/3、KCP、SOCKS、mux、TURN、BitTorrent、DTLS）列在 CHANGELOG 的"处处安全默认值"条目中。其中两项由
  用户决定：SOCKS 和 HTTP CONNECT 默认拒绝非公网目标（开放代理 / SSRF），only-log 默认仍同步写出
  （`FmtLogger::non_blocking` 需显式开启）。
