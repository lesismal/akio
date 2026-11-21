# API 稳定性与语义化版本策略

[English](api-stability.md)

本文说明 only 从 1.0.0 起的承诺：哪些 crate 和条目受[语义化版本](https://semver.org/lang/zh-CN/)
约束、什么算破坏性变更、最低支持的 Rust 版本（MSRV）如何调整，以及各平台的支持级别。弃用流程见
[deprecation.zh-CN.md](deprecation.zh-CN.md)；变更历史见 [CHANGELOG.zh-CN.md](../CHANGELOG.zh-CN.md)。

## 1. 版本号

- **同步发布。** workspace 中所有 crate 共用一个版本号（`[workspace.package] version`），并一起
  发布。workspace 内 crate 之间用精确版本依赖（`=1.2.3`），因此一次构建中的 crate 总是来自同一个
  发布。
- **1.0.0 起遵循 semver。** 对受保护的 API（第 2 节）：补丁版本（`1.2.x`）只修复缺陷；次版本
  （`1.x.0`）可以新增 API、弃用 API；只有主版本（`x.0.0`）可以删除或修改受保护的 API。由于各
  crate 同步发布，任何一个受保护 crate 的破坏性变更都意味着全部 crate 进入新主版本；这类发布会
  提前规划，且很少发生。
- **预发布版本**（`1.0.0-rc.N`）仍可以改变任何东西；发布候选版的目的就是在承诺生效前找出必须
  修改的地方。

## 2. 承诺的范围

### Crate

| 级别 | Crate | 承诺 |
|---|---|---|
| 公开 | `only`、`only-core`、`only-log`、`only-tls`、`only-http`、`only-ws`、`only-mux`、`only-socks`、`only-arpc`、`only-grpc`、`only-protobuf`、`only-protobuf-build`、`only-kcp`、`only-quic`、`only-h3`、`only-ebpf`、`only-prefork`、`only-turn`、`only-webrtc`、`only-media` | 其公开 API（见下）完整遵循 semver。 |
| 内部 | `only-sys`、`only-buf`、`only-timer`、`only-pool`、`only-epoll`、`only-uring`、`only-crypto`、`only-x509`、`only-dtls`、`only-srtp`、`only-rtp`、`only-sctp`、`only-ice`、`only-deflate`、`only-brotli`、`only-zstd`、`only-regex` | 实现用的 crate，仅因公开 crate 依赖它们才发布。它们自身的 API 可能在**任何**发布中变化；请依赖 `only` / `only-core`。它们贡献给公开 API 的类型（`SharedBuf`、`PoolConfig`、`PoolStats`）通过 `only-core` 和 `only` 中的再导出受到保护。 |
| 实验性 | `only-dpdk`，以及 `only` 的 `dpdk` / `dpdk-pmd` feature（`Backend::Dpdk`、`only::dpdk`） | 内核旁路后端是新加入的，其配置仍可能在任何发布中变化。在生产中使用过之后再纳入保护（公开层级）；在此之前快照 `api/only-dpdk.txt` 只用于让变化可见。 |

`tools/` 与 `fuzz/` 不发布。

### 条目

受保护：从公开 crate 根部可达、出现在其 rustdoc 中的所有条目，包括公开类型的 trait 实现和 auto
trait（`Send`、`Sync`、`Unpin`、`UnwindSafe`）。

不受保护：

- 标记为 `#[doc(hidden)]` 的条目以及只能经由它们访问的一切。这些是 workspace 内各 crate 共享的、
  面向后端的管道代码（`ConnInner`、`LoopLink`、`Group`、`DynAcceptor`、`DynHandler`、`LoopStats`、
  `Pool`、`only_http::transport`、`only_ws::WsSession`、`only_ebpf::cbpf`、`Conn::inner`、
  遥测辅助函数等），可能在任何发布中变化。
- `fuzzing` cargo feature 及其启用的 `fuzzing` 模块（`fuzz/` 的入口）。
- `unstable` cargo feature（`only`、`only-tls`、`only-quic`、`only-webrtc`）及其启用的一切：
  only-tls 改用自研 TLS（DEV-PLAN 第 C 波）、only-quic 改用自研 QUIC 且 only-webrtc 改用自研 WebRTC
  协议栈（第 D 波）之后，它们的 `unstable` feature 不再启用任何东西：保留为空的预留 feature，以便
  `only/unstable` 照常编译；`only::tls::rustls`、`from_rustls`、`as_rustls`、`only_quic::proto`、
  `from_quinn`、`as_quinn_mut`、`only_webrtc::str0m`、`crypto_provider_str0m`、`Peer::with_rtc`、
  `RtcConfig::with_str0m` 与 `OtherEvent::as_str0m` 已移除。被封装的 crate 升级时它们的签名就会变化，
  这可能发生在次版本中。任何暂时无法承诺的公开内容都放进 `#[doc(hidden)]` 或 `unstable` 之后，
  绝不悄悄进入受保护的 API。
- `only-grpc` 的 `prost` feature（为 prost 消息实现 `codec::Message`；已弃用，推荐改用
  `only-protobuf`，其生成的消息直接实现该 trait）：它用到 prost 的类型，
  因此 prost 升级可能出现在次版本中。
- `log` cargo feature（`only`、`only-core`、`only-log`）：到 `log` crate 的桥接
  （`only_log::bridge`、级别类型之间的 `From` 转换、把记录转发给 `log` 的 logger）。它用到
  `log` 的类型并跟随 `log` 0.4；次版本可能升级 `log`。桥接的行为见手册的可观测性一章。
- `Display` 输出、日志消息和 panic 消息的具体文本。
- 文档中注明未指定的行为，以及性能特征。

虽然不是 Rust API，以下也属于承诺的一部分：各协议 crate 的线上格式（HTTP/1.1、HTTP/2、HTTP/3、
WebSocket、arpc、gRPC、KCP、SOCKS 保持互通），Prometheus 指标的名称和标签，以及 JSON 调试端点的
字段（次版本可以新增字段和指标；只有主版本才能删除或改名）。

### 公开依赖

受保护的 API 不使用任何其他 crate 的类型。QUIC API 以前用 `bytes` crate 的 `Bytes` 承载流与数据报
负载，only-quic 改用自研 QUIC（DEV-PLAN 第 D 波）时换成了形状相同的 `only_quic::Bytes`（引用计数，
`slice`、`split_to`、`from_static`、`From<Vec<u8>>` 等；见 CHANGELOG 的迁移说明）。日志使用工作区
自己的门面 `only-log`（`only::log`，`Config::log_level: Option<only::log::LevelFilter>`）；只有
开启 `log` cargo feature 时才依赖 `log`，该 feature 不在承诺之内（见上）。可观测性一章列出的日志
target（`only`、`only_http::access`、`only_webrtc`）和键名与指标名同等对待：次版本可新增，只在
主版本中改名或删除。

TLS 由 `only-tls` 自己实现（基于 `only-crypto` 与 `only-x509`），不依赖任何第三方 crate；QUIC 也由
`only-quic` 自己实现（基于 `only-tls` 与 `only-crypto`），WebRTC 也是如此（第 D 波）：`only-webrtc`
运行在内部的 `only-ice`、`only-dtls`、`only-srtp`、`only-rtp` 与 `only-sctp` 之上，它们的类型都不出现在
其 API 中。仍承担协议工作的 1.0 之前的依赖（prost）都已**被封装**：受保护的 API
改用 only 自己的类型（`only::tls::{ServerConfig, ClientConfig, Certificate, PrivateKey,
RootCerts, Error}`、`only_quic::{ServerConfig, ClientConfig, TransportConfig, StreamId, Dir,
Side, ConnectionError, ConnectionStats}`、`only_grpc::codec::Message`）。升级它们，或用自研实现替换
它们，都不是破坏性变更。只有通过上面的 `unstable` feature 与 `prost` feature 才能访问它们，而这些
feature 不在承诺之内。

## 3. 什么算破坏性变更

对受保护条目而言，以下属于破坏性变更（只能出现在主版本）：

- 删除或重命名条目、模块、再导出、公开字段或枚举变体；
- 修改函数签名：参数、返回类型、泛型参数、增加约束；
- 给穷尽（exhaustive）枚举增加变体，或给穷尽结构体增加公开字段（允许这样做的类型见第 4 节）；
- 给用户实现的 trait 增加必须实现的方法（没有默认实现），或修改已有方法的签名；
- 删除 trait 实现，包括失去 `Send`、`Sync` 等 auto trait；
- 把某个公开依赖的最低要求版本提高到 semver 不兼容的新版本；
- 以正确程序可观察到的方式改变文档化的行为（改变程序行为的默认值、线上格式），修复缺陷除外。

以下不算破坏性变更（次版本中允许）：

- 新增条目、模块、trait 实现和固有方法；
- 给 `#[non_exhaustive]` 结构体增加字段、给 `#[non_exhaustive]` 枚举增加变体；
- 给 trait 增加带默认实现的方法；这在极少数情况下会与用户类型的同名方法冲突，按 Rust API 指南
  接受这一点；
- 弃用条目（见 [deprecation.zh-CN.md](deprecation.zh-CN.md)）；
- 提高 MSRV（第 5 节）；
- 涉及不受保护条目的任何改动。

补丁版本只包含缺陷修复；修复可以改变与文档相矛盾的行为。

## 4. 保持 API 可扩展的约定

这些约定由 lint 或评审检查，新 API 也遵循：

- **配置结构体**（`Config`、`HttpConfig`、`H2Config`、`WsConfig`、`KcpConfig`、`H3Config`、
  `PoolConfig`、`UringConfig`、`EbpfConfig`、`H2Options`、`WsOptions`、`DialOptions`、
  `CallOptions`、各中间件配置等）都是带公开字段和 `Default` 的 `#[non_exhaustive]` 结构体。从
  `Default::default()`（或 `KcpConfig::fast()` 这样的预设）开始，再给字段赋值：

  ```rust
  let mut cfg = only::Config::default();
  cfg.idle_timeout = Some(std::time::Duration::from_secs(30));
  ```

  在定义它们的 crate 之外不能使用结构体字面量，正因如此新设置才能在次版本中出现。我们选择公开
  字段而不是构建器方法：设置一个值只有一种方式，`Debug` 输出可读，API 不会翻倍，字段文档就在
  字段旁边。`*Config` 表示服务器、engine 或协议实例的设置；`*Options` 表示单次操作（一次 dial、
  一次调用、一次升级）的参数。
- 由 only 填写、用户读取的**报告结构体**（`Metrics`、`LoopCounters`、`ConnInfo`、`SlowRecord`、
  `PoolStats`、`UdpStats`、`TlsInfo`、`ClientResponse`、`Stats` 等）以及消息类型 `Request` /
  `Response` 都是 `#[non_exhaustive]`；用构造函数创建消息（`Request::new`、`Response::new`、
  `ClientRequest::new`、`FileBody::new`）。
- **错误枚举**以及将会增长的枚举（`Backend`、`Accel`、`Rule`、`Method`、`Version`、`Steering`、
  `CloseReason` 等）都是 `#[non_exhaustive]`：匹配时需要通配分支。每个错误类型都实现
  `std::error::Error + Display + Debug + Send + Sync`。变体按定义就完整的枚举保持穷尽，这样
  `match` 不需要通配分支：事件枚举（`BodyEvent`、`H2Event`、`StreamEvent`、`Message`、`Event`）、
  由规范固定的协议常量（`Opcode`、`Role`、`grpc::Code`）以及 `Decision`。
- **每个公开类型都实现 `Debug`**（lint `missing_debug_implementations`）；返回 `Self` 的构建器
  方法都带 `#[must_use]`（clippy `return_self_not_must_use`）。
- **Trait**：用户实现的 trait（`Handler`、`Acceptor`、`Transport`、`Service`、`Middleware`、
  `WsHandler`、`RawHandler`、`QuicHandler`、`KcpHandler`）只会增加带默认实现的方法。用户只应调用
  而不应实现的 trait 会被密封（私有 supertrait），从而可以随意增加方法；only 1.0 中没有这样的
  trait，面向后端的 trait 改为 `#[doc(hidden)]`。
- **命名**：`dial` 以非阻塞方式发起客户端连接（回调，或稍后就绪的句柄）；`dial_blocking` 等到
  连接建立；`serve` / `serve_with(cfg, service)` 构造服务端 acceptor；字节数上限以 `_bytes` 结尾；
  连接级回调以 `on_` 开头。

## 5. 最低支持的 Rust 版本

- MSRV 即 workspace `Cargo.toml` 中的 `rust-version`，目前为 **1.85**（edition 2024）。CI 用恰好
  这个工具链构建并测试（`msrv` job）。
- 提高 MSRV 不算破坏性变更，但只在**次版本**中进行，绝不在补丁版本中进行，会写入变更日志，且新的
  MSRV 作为稳定版发布已满六个月，除非安全修复需要更新的版本。

## 6. 平台支持

| 级别 | 平台 | 含义 |
|---|---|---|
| 1 | Linux x86_64 与 aarch64（glibc）：任何受支持内核上的 epoll 后端；5.19+ 上的 io_uring 后端；UDP GSO/GRO、`sendmmsg`/`recvmmsg`；BPF 分流（经典 BPF 无需特权，eBPF 需要 `CAP_BPF`）；6.15+ 上的 sockmap relay（或 `Relay::new_any_kernel`） | 每次提交都构建并完整测试（两种后端）；有基准测试；缺陷会阻塞发布。运行内核缺少的特性会被探测并回退（io_uring 回退到 epoll，eBPF 回退到经典 BPF 或不加速），除非设置了 `strict`。 |
| 2 | macOS（aarch64、x86_64）：kqueue 后端 | 在 CI 中构建并测试；用于开发。未针对性能调优；仅 Linux 支持的特性（io_uring、BPF、UDP GSO/GRO）按文档返回 `Unsupported` 或回退。 |
| 2 | 使用 musl 的 Linux x86_64 与 aarch64（`*-unknown-linux-musl`，如 Alpine）：与 glibc 相同的后端 | 已在 Alpine 容器中测试：`only_sys::ffi` 的布局与常量与 `libc` crate 的 musl 定义对比；两种架构上运行 only-sys、only-core、only-epoll、only-uring 与 only-ebpf 的测试（epoll 与 io_uring），aarch64 上另外运行 `only` 的测试。musl 的 `struct cmsghdr` 按 4 字节对齐，内核（以及我们）的按 8 字节对齐；大小与偏移一致。没有基准测试；并非每个 crate 的测试都运行。 |
| 3 | 其他 Unix 系统 | 可能可以编译；不测试。没有可用后端时 `Engine::build` 返回 `Unsupported`。 |
| — | Windows | 2.0 之前不支持（没有 IOCP 后端）。 |

把某个平台降到更低级别会在变更日志中公告，且只在次版本或主版本中进行。

## 7. 如何保证承诺

- **API 快照。** `api/<crate>.txt` 保存每个发布 crate 的公开 API，内容是
  [`cargo public-api`](https://github.com/cargo-public-api/cargo-public-api) 在 Linux 上的输出
  （不含隐藏条目和 `fuzzing` feature）。CI job `public-api`（`ci-ok` 的门禁之一）运行
  `tools/api/public-api.sh`，API 与快照不一致时失败。有意的变更要与重新生成的快照
  （`tools/api/public-api.sh --bless`）和一条 `CHANGELOG.md` 记录一起提交，这样每次 API 变更在
  评审中都清晰可见。
- **semver 检查。** 1.0.0 发布到 crates.io 之后，CI job `semver-checks` 对公开级别的 crate 运行
  [`cargo-semver-checks`](https://github.com/obi1kenobi/cargo-semver-checks)，与 crates.io 上的
  最新发布比较，非主版本中出现破坏性变更时失败。在基线发布之前该 job 会跳过（它会检测到尚无
  发布）。
