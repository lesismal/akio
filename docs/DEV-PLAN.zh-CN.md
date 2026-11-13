# flash 开发计划（Dev Plan）

[English](DEV-PLAN.md) | 简体中文

> 状态：**已审核通过**（2026-11-13），与 ROADMAP 一并确定。
>
> 原说明：配套文档：[ROADMAP.zh-CN.md](ROADMAP.zh-CN.md)（做什么、为什么、何时）。本文档说明**怎么做**：仓库结构、公共 API 草图、每个里程碑的任务拆解、测试与协作规范。

## 1. 仓库结构（Cargo workspace）

```text
flash/
├─ Cargo.toml                  # workspace
├─ crates/
│  ├─ flash-sys/               # unsafe 系统调用封装：epoll/kqueue/io_uring/eventfd/sendfile/splice…
│  ├─ flash-buf/               # size-class 缓冲池、共享只读缓冲（Bytes 风格）
│  ├─ flash-timer/             # 分层时间轮
│  ├─ flash-pool/              # 逻辑线程池（自适应、有界队列、过载策略）
│  ├─ flash-core/              # Engine / Listener / Conn / Handler / Reactor trait
│  ├─ flash-epoll/             # epoll(+kqueue) reactor
│  ├─ flash-uring/             # io_uring reactor
│  ├─ flash-ebpf/              # eBPF 加速层（aya），feature 门控
│  ├─ flash-dpdk/              # DPDK reactor + 用户态栈，feature 门控
│  ├─ flash-tls/               # rustls sans-io 集成（+ kTLS 可选）
│  ├─ flash-http/              # HTTP/1.x、HTTP/2、Router、Context、静态文件
│  ├─ flash-ws/                # WebSocket
│  ├─ flash-mux/               # 同端口多协议嗅探
│  ├─ flash-middleware/        # compress/cors/csrf/etag/limiter/logger/recover/requestid…
│  ├─ flash-arpc/  flash-grpc/  flash-socks/  flash-kcp/  flash-quic/  flash-h3/
│  ├─ flash-media/ flash-webrtc/ flash-bittorrent/   # M7，独立 crate
│  └─ flash/                   # 门面 crate：re-export + feature 开关
├─ examples/                   # echo、http、ws、proxy、blocking-offload …
├─ benches/                    # 跨实现 benchmark 套件（含对 fib 的脚本）
├─ fuzz/                       # cargo-fuzz targets
├─ tests/                      # 集成/互通/混沌测试
└─ docs/                       # ROADMAP、DEV-PLAN、adr/（架构决策记录）
```

依赖方向（单向）：`sys → buf/timer/pool → core → {epoll,uring,ebpf,dpdk}` ；`core → tls → http/ws/…`。协议 crate 只依赖 `flash-core` 的公共 trait，不依赖具体后端。

## 2. 公共 API 草图（M0 的 ADR 里定稿）

```rust
pub trait Handler: Send + 'static {
    type Conn: Send + 'static;                       // 每连接状态，仅在所属 IO 线程访问，无需 Sync
    fn on_open(&self, c: &Conn) -> Self::Conn;
    fn on_data(&self, c: &Conn, st: &mut Self::Conn, data: &[u8]);   // 非阻塞，IO 线程内联
    fn on_close(&self, c: &Conn, st: Self::Conn, err: Option<Error>);
    fn on_hangup(&self, _c: &Conn, _st: &mut Self::Conn) {}          // 可选
    fn on_shutdown(&self, _c: &Conn) {}                              // 可选
}

#[derive(Clone)] pub struct Conn(Arc<ConnInner>);                    // Send + Sync
impl Conn {
    pub fn send(&self, data: &[u8]) -> Result<()>;
    pub fn send_owned(&self, data: Vec<u8>) -> Result<()>;
    pub fn send_shared(&self, data: SharedBuf) -> Result<()>;
    pub fn send_file(&self, f: &File, off: u64, len: u64) -> Result<()>;
    pub fn cork(&self); pub fn flush(&self) -> Result<()>;
    pub fn close(&self); pub fn close_after_send(&self);
    pub fn hold_reads(&self, hold: bool);
    pub fn notify_output(&self, limit: usize, cb: impl FnOnce(Result<()>) + Send + 'static);
    pub fn spawn_blocking<R: Send + 'static>(
        &self,
        work: impl FnOnce() -> R + Send + 'static,
        done: impl FnOnce(&Conn, &mut H::Conn, R) + Send + 'static,   // 回到所属 IO 线程
    ) -> Result<()>;
    pub fn local_addr(&self) -> SocketAddr; pub fn peer_addr(&self) -> SocketAddr;
}

pub enum Backend { Epoll, IoUring(UringConfig), Dpdk(DpdkConfig) /* Kqueue 仅 macOS */ }
pub enum Accel   { None, Ebpf(EbpfConfig) }
```
> 以上只是草图：`Handler::Conn` 与 `spawn_blocking` 回调里如何拿到 `&mut Self::Conn`（泛型 vs. `dyn Any`）会在 M0 通过原型比较，选对用户最友好、且不引入 `Sync` 约束的方案。

## 3. 里程碑任务拆解

每个任务以 `[ ]` 标记，括号内为产出物。每个里程碑结束需通过 **DoD（见 ROADMAP 第 4 节）+ benchmark 报告 + CHANGELOG**。

### M0 立项与骨架（1–2 周）
- [x] workspace + `rust-toolchain.toml` + `rustfmt/clippy` 配置 + LICENSE
- [x] CI：Linux x86_64/aarch64 + macOS；`fmt / clippy -D warnings / test / miri(纯 Rust crate) / loom`
- [x] ADR-001 线程模型；ADR-002 Conn 锁模型与生命周期；ADR-003 Handler 与每连接状态类型；ADR-004 后端抽象 `Reactor` trait；ADR-005 依赖策略；ADR-006 eBPF 的定位
- [x] 原型：对比 2–3 种 `Handler` API 形态，选定
- [x] benchmark 脚手架：echo 客户端压测工具 + 对照实现（fib、tokio、monoio）

### M1 核心引擎：epoll + kqueue（4–6 周）
- [x] `flash-sys`：epoll、eventfd、`accept4`、`writev`、`sendfile`、`splice`、`SO_REUSEPORT`、非阻塞 socket 选项
- [x] `flash-buf`：size-class 池、线程本地缓存、`SharedBuf` 引用计数缓冲
- [x] `flash-timer`：时间轮（连接读写超时、空闲超时、用户定时器）
- [x] `flash-core`：`Engine/Listener/Reactor/Handler/Conn`；每 IO 线程事件循环；accept 分发；命令队列 + eventfd 唤醒
- [x] `Conn` 跨线程路径：发送队列、直写优先、唤醒 loop、关闭状态机、generation 防误操作
- [x] 背压：写水位、`hold_reads`、`max_pending_bytes`；优雅关闭
- [x] 异步 dial（客户端连接）
- [x] kqueue reactor（共享逻辑，macOS 可开发/调试）
- [x] 测试：单元、`loom`（cork/发送/关闭竞争，5 个模型，已进 CI）、5000 个同时连接 + 20×500 次连接/关闭循环并检查 fd 泄漏（macOS 与 Linux）
- [x] 空闲超时已接入 loop（`Config::idle_timeout`，每个 I/O 线程一个时间轮）
- [ ] 未完成，顺延到后续里程碑：10 万连接测试、读/写超时、在专用 Linux 机器上与 fib/tokio/monoio 的 echo 对比
- **交付**：`examples/echo`，echo benchmark 报告 v0

> M1 状态：**除上述未完成项外已收尾。** 在 Linux（epoll）与 macOS（kqueue）上验证：12 个引擎测试、2 个压力测试、5 个 loom 模型（故意写坏 `mark_closed` 后 loom 模型会失败，说明它确实在探索这个竞争）。`echo-bench` 现在把连接复用到少量客户端线程上；在同一台 macOS 机器上，flash 与 4 线程 tokio echo 都是约 10.5–11.5 万 req/s，也就是客户端仍是瓶颈，这次结果只能说明“同一量级”，无法排名。与 fib 的对比需要 fib 先有一个纯 TCP echo（目前没有）以及两台 Linux 机器，顺延到 M2 的 benchmark 报告。`Conn::spawn_blocking` 属于 M2。

### M2 多后端 + 逻辑池 + UDP + TLS（6–8 周）
- [x] `flash-pool`：自适应线程池（按需增长到上限，空闲线程退出）、有界队列、过载返回 `Error::Overloaded`、统计
- [x] `Conn::spawn_blocking` + 回调回投 IO 线程（连接已关闭或 `work` panic 时跳过）；有序应答槽（`reserve_response`；未填充就被丢弃的槽会关闭连接）
- [x] 慢回调检测（`Config::slow_callback_threshold`，默认 100 ms；`slow_hook` 或 stderr）。指标导出仍待做
- [x] `flash-uring`：multishot accept 与 recv、provided buffer ring、cooperative/deferred task-run + single-issuer 的 ring、eventfd 唤醒、内核探测（5.19+）并自动降级到 epoll（`UringConfig::strict` 可改为拒绝）。写路径走共享的“直接 `write` + 队列”逻辑，积压部分用 `poll(POLLOUT)`
- [ ] `flash-uring`：暂未使用（有测量依据再做）：registered files、`SEND_ZC`、`MSG_RING` 唤醒、基于 ring 的发送
- [x] **每 listener 选择后端**：Engine 内多后端并存、线程组独立配置（已测试：同一 Engine 里 epoll + io_uring 两个 listener）；不支持的组合返回明确错误
- [x] UDP（服务端）：`Listener::udp`；每个 peer 地址一个 `Conn`，沿用普通 `Handler`（每个数据报一次 `on_data`，`send` 即发一个数据报，可在任意线程调用），空闲淘汰（`Config::udp_idle_timeout`），优雅关闭不等待排空，`spawn_blocking` 与 `close_after_send` 可用；Linux 上每线程一个 `SO_REUSEPORT` socket（同一 peer 固定在一个线程），其他系统单线程；Linux 上用 `recvmmsg` 批量收。已在 macOS 与 Linux 测试
- [x] UDP 客户端：`Engine::dial_udp`（配合 `EngineBuilder::udp_client_threads`，或使用某个 UDP listener 的线程）：每个拨出的连接有自己 `connect` 过的 socket，因此有独立本地端口；`on_open` 立即执行，每个数据报一次 `on_data`，支持空闲超时与 `close()`；收到 ICMP“端口不可达”会以 `ConnectionRefused` 结束连接。已测试：对 flash UDP 服务端（30 个并发拨号 = 30 个不同 peer）、关闭的端口、不应答的服务端、跨线程发送
- [ ] UDP 未完成：`sendmmsg`、GRO/GSO、无连接的批量 `DatagramsHandler`、基于 io_uring 的 UDP（io_uring listener 请求目前由 epoll 服务）、peer 数量上限、拨出 socket 的批量接收（目前每个数据报一次 `recv`）
- [x] `flash-tls`：rustls 以 sans-io 方式通过 `Conn` 之下的 `Transport` 层驱动（服务端与客户端；`Tls::server` / `Tls::client` 包装任意 acceptor，handler 看到明文），握手在 IO 线程内完成，握手期间发送的应用数据先缓存，`close_after_send` 发送 close_notify，`tls_info`（ALPN、SNI、版本）。会话票据、SNI 证书选择、客户端认证、版本：通过 rustls 自己的配置。已在 epoll 与 io_uring 上测试：echo（3 MiB）、ALPN/SNI、明文垃圾数据与不受信证书的客户端、TLS 上的 `spawn_blocking` + 有序槽、flash 拨 flash
- [ ] kTLS 评估（未开始）；TLS 1.3 early data 与客户端证书辅助函数留给 rustls 配置
- [x] 测试：整套 engine/offload/stress 测试在 epoll 与 io_uring 上都跑（`FLASH_TEST_BACKEND=uring`，Linux CI 也跑）；跨后端混合 listener。另已完成：阻塞投递测试（IO 线程不被阻塞、完成回调在 IO 线程且带 handler 状态、池满、连接提前关闭、有序、槽丢弃、慢回调）
- **交付**：`examples/blocking-offload`（已完成）、后端对比 benchmark 报告（已完成：[BENCHMARKS.zh-CN.md](BENCHMARKS.zh-CN.md)）

> M2 状态：逻辑池与 io_uring 已完成；21 个 engine/offload/stress 测试在 Linux（内核 6.12，Docker）上两种后端都通过，重复运行无失败。**io_uring 与 epoll 对比（同一台 Docker 虚拟机，echo，64 B，客户端同机）：** 服务端 4 线程/256 连接时两者都被客户端限制（各约 80–100 万 req/s，无法排名）；服务端 1 线程/512 连接（受服务端限制）时 epoll 为 41.6 万和 49.2 万，io_uring 为 52.7 万和 53.8 万，io_uring 领先约 10–25%。最初的 io_uring 实现每收到一段数据都重新提交一次 `PROVIDE_BUFFERS`，只有 epoll 的约 60%；改用 buffer ring 归还缓冲（写内存而不是提交请求）后差距消失。数据来自与客户端共用 CPU 的虚拟机，只能作方向参考，不是正式 benchmark 报告。**M2 已完成。** benchmark 报告：[BENCHMARKS.zh-CN.md](BENCHMARKS.zh-CN.md)。概要：TCP echo 与 fib、tokio 同一量级（所有测过的负载都领先 fib；64 连接与 16 KiB 落后 tokio 约 15%，512 连接领先），该环境下 io_uring 并不比 epoll 快，逻辑池相对在 I/O 线程里阻塞约恢复 58 倍。

### M3 HTTP/1 + WebSocket（6–8 周）
- [x] `flash-http` h1 服务端：`httparse` 解析请求头，自写增量 chunked 解码器（扩展、trailers、任意切分），流水线且按序应答（有序槽），keep-alive/`Connection: close`/HTTP/1.0，`Expect: 100-continue`，限制（头大小、body 大小、头数量），防请求走私（CL+TE、重复 CL），`Context` 支持 `detach()` 之后在任意线程完成应答，优雅关闭时让在途应答先完成。已在 epoll 与 io_uring 上测试
- [x] 流式：请求 body 通过 `Streaming(svc)` + `ctx.on_body`（分块、trailers、无大小限制），响应 body 通过 `ctx.stream_response`（chunked / 以关闭为界，排在更早的流水线响应之后）；文件 body 用 `sendfile(2)`（TLS 下经内存读取）；核心支持：`ResponseStream`、`Part::File`
- [ ] h1 未完成：HTTP/1 over TLS 的测试（`Tls` 包装可组合，但这里没测）、路由参数的百分号解码（已提供 `percent_decode`）
- [x] Router：静态 > `:param` > `*通配`，带回溯，405 与 `Allow`，HEAD 走 GET 路由，`nest`，每个 router 自己的 layer，自定义 fallback；重复/冲突路由在注册时 panic
- [ ] Router 未完成：正则参数、零分配路由（目前每个请求分配一个 `Vec` 和若干 `String`）及其 benchmark
- [x] 中间件：recover、request id、CORS（预检）、访问日志
- [x] 中间件：响应时间、compress（gzip/deflate）、etag + 304、csrf（双重提交 cookie）、按 IP 的令牌桶限流。尚未提供 brotli（还没引入 brotli 依赖）
- [x] 静态文件（`files::Files`）：路径安全、MIME、ETag/Last-Modified/304、单段 Range、index 文件、预压缩 `.br`/`.gz` 同名文件、带 stat 间隔的内存缓存、大文件用 `sendfile`。基于 inotify 的变更跟踪未做（用 stat 间隔代替）
- [x] `flash-ws`：RFC 6455 + permessage-deflate（context takeover、服务端窗口位数）、`PreparedMessage` 广播、子协议、Origin 检查、关闭握手；Autobahn|Testsuite：核心 298 项 OK + 3 项 informational，permessage-deflate 216/216 OK，由 `tools/autobahn/run.sh` 在 CI 中运行。Autobahn 发现了 miniz_oxide 的一个 deflate bug（flate2 现改用 zlib-rs）
- [x] HTTP/1 异步客户端（`client::Client`）：回调、`ResponseFuture`（`wait`、`wait_timeout`、`.await`）、按主机复用 keep-alive 连接（复用的连接已失效时重试一次）、chunked/以关闭为界的 body、通过 `flash::tls` 支持 HTTPS、地址回退（先 ::1 再 127.0.0.1）。未做：重定向、单请求超时、把 DNS 解析移出调用线程
- [ ] 与 hyper、fib 的 HTTP/1 对比报告（plaintext、pipelined、json）：放到功能阶段结束后的统一 benchmark 阶段
- **交付**：`examples/http`、`examples/ws-chat`

> M3 状态：**除对比报告外功能已完成**（报告移到 benchmark 阶段）：支持流式与 sendfile 的 h1 服务端、router、9 个中间件、静态文件、通过 Autobahn 全部用例的 flash-ws（核心 298 项 + 3 项 informational，permessage-deflate 216/216）、h1 客户端。示例：`crates/flash-http/examples/{hello,ws-chat,ws-echo}.rs`。

### M4 HTTP/2 + 多协议（8–10 周）
- [x] HTTP/2（`flash-http`，与 HTTP/1 共用 `Service`/`Context`）：帧、流、双向流控、HPACK（`loona-hpack`）、h2c（先验与 `Upgrade`）、TLS ALPN `h2`、server push（`ctx.push`）、双向流式 body、GOAWAY 优雅关闭；h2spec strict 147/147（CI job `h2spec`）；curl 互通（先验、upgrade、POST）；`h2client::H2Client`（多路复用、流控、push、TLS）。顺带发现：rustls 单次写入明文超过 64 KiB 会失败，`flash-tls` 现按记录大小分段加密
- [x] `flash-mux`：首字节嗅探（TLS、HTTP/1、HTTP/2 preface、SOCKS4/5、前缀、自定义规则、fallback）；被选中的 acceptor 像自己 accept 的连接一样接管（回放已读字节、逻辑池回调、优雅关闭）
- [ ] `flash-arpc`：线协议兼容、双向调用、notify、stream、广播、重连
- [ ] `flash-grpc`：一元 + 流式、metadata、deadline、interceptor、gzip；codec 可插拔（prost）
- [x] `flash-socks`：SOCKS5（无认证 / 用户名密码，IPv4/IPv6/域名在逻辑池中解析）、SOCKS4/4a、HTTP `CONNECT` 代理（通过 `Context::upgrade_raw`）；回调到回调的转发，双向背压（核心新增 `Conn::on_drain`；它暴露了一个在 loop 之外清空队列时丢失唤醒的问题，已修复）。未做：SOCKS BIND / UDP ASSOCIATE、Linux `splice` 路径
- [ ] 测试：与 curl/nghttp2/grpc-go/tonic 互通
- **交付**：`examples/grpc`、`examples/proxy`

### M5 QUIC/H3 + KCP + eBPF（8–10 周）
- [ ] `flash-quic`/`flash-h3`：基于 sans-io QUIC 核心（quinn-proto/quiche 评估后定），QPACK，WebSocket over H3；与 curl/quiche 互通
- [ ] `flash-kcp`：兼容 skywind3000/kcp 与 kcp-go（加密、XOR、FEC）、按需 flush
- [ ] `flash-ebpf`：aya 加载 REUSEPORT 选择程序（CPU 亲和/一致性哈希）、sockmap/`sk_msg` relay、可选 XDP 限速；无特权或内核不支持时降级
- [ ] 测试：eBPF 程序在 CI 容器（privileged）与本地 VM 双环境跑
- **交付**：`examples/h3`、`examples/kcp`、eBPF 加速 benchmark

### M6 DPDK + 生产化（6–8 周）
- [ ] `flash-dpdk`：EAL 初始化、mbuf 收发、用户态 TCP/IP 栈选型与集成（先 UDP，再 TCP）、与 Engine 线程组对接
- [ ] 生产化：指标（Prometheus 风格）、结构化日志、运行时 debug/pprof 等价物（连接表、队列深度、慢回调）、配置热更新
- [ ] 混沌测试：随机断连、半关闭、慢客户端、池饱和、fd 耗尽
- [ ] Prefork（可选）
- **交付**：长稳（≥72h）报告

### M7 重型协议（开放）
- [ ] 流媒体（RTMP/RTSP/SRT/FLV/HLS/WHIP/WHEP + hub）
- [ ] WebRTC（ICE/DTLS-SRTP/DataChannel/TURN）
- [ ] BitTorrent（metainfo/tracker/peer wire/uTP/DHT/MSE）
- 各自独立 crate、独立 README 与测试；视社区与精力并行推进。

### 1.0 稳定化
- [ ] API 审阅与冻结、semver 策略、弃用流程
- [ ] 全量 fuzz 语料与覆盖率报告、`cargo-audit/deny`、unsafe 审查清单
- [ ] 文档站 + 迁移指南（从 fib / tokio / hyper）+ 架构文档

## 4. 工程规范
- **分支/提交**：`main` 保持可发布；功能分支 + PR；Conventional Commits。
- **代码**：`#![forbid(unsafe_code)]` 为默认，仅 `flash-sys`、后端、`flash-buf` 允许 unsafe，且每处带 `// SAFETY:`。
- **测试金字塔**：单元 → loom/miri → 集成/互通 → 混沌 → benchmark；新功能必须带测试，协议解析必须带 fuzz target。
- **ADR**：任何影响公共 API、线程/锁模型、依赖的决策先写 `docs/adr/NNN-*.md`。
- **文档**：每个 crate 有 crate-level 文档与可运行 doctest；README 保持中英双语（与 fib 一致）。
- **性能**：PR 若触及热路径，附 benchmark 前后对比；夜间 benchmark 对比历史基线。

## 5. 建议的启动顺序（审核通过后）
1. M0：先定稿 ADR-001~004 与 `Handler`/`Conn` API 原型（这是后续所有工作的地基，改动成本最高）。
2. M1：先打通 epoll TCP echo + 跨线程 `Conn::send`，尽早上 loom 和 benchmark。
3. M2 开头先做逻辑池（它直接决定 `Handler` 的状态类型设计），再做 io_uring。
4. 其余按里程碑顺序推进；M7 视情况并行。
