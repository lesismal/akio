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
- [ ] 测试：单元、`loom`（发送/关闭竞争）、echo 压测、10k/100k 连接稳定性、fd 泄漏检测
- **交付**：`examples/echo`，echo benchmark 报告 v0

> M1 状态：核心引擎已实现，并在 Linux（epoll）与 macOS（kqueue）上测试通过。**M1 收尾前仍待完成：** 发送/关闭竞争的 `loom` 模型、1 万/10 万连接与 fd 泄漏测试、与 fib/tokio/monoio 的 echo 对比（纯 std 的 `echo-bench` 客户端是一连接一线程，客户端先于服务端饱和，需要更好的压测器）。定时器目前是独立的时间轮，尚未接入 loop（空闲/读写超时）。`Conn::spawn_blocking` 属于 M2。

### M2 多后端 + 逻辑池 + UDP + TLS（6–8 周）
- [ ] `flash-pool`：自适应线程池、有界队列、过载策略、指标
- [ ] `Conn::spawn_blocking` + 回调回投 IO 线程；有序应答槽；连接关闭期间的完成回调语义
- [ ] 慢回调检测（阈值、日志/指标）
- [ ] `flash-uring`：multishot accept/recv、provided buffer ring、registered files、`SEND_ZC`、`MSG_RING` 跨线程唤醒；内核特性探测与自动降级
- [ ] **每 listener 选择后端**：Engine 内多后端并存、线程组独立配置；配置校验与错误提示
- [ ] UDP：每 peer 一连接、`recvmmsg/sendmmsg`、GRO/GSO；`DatagramsHandler` 批量接口
- [ ] `flash-tls`：rustls sans-io 驱动、握手在 IO 线程内、会话票据、SNI、ALPN；kTLS 评估
- [ ] 测试：同一套 echo 测试矩阵跑 epoll/io_uring；跨后端混合 listener；阻塞投递压测（池满、连接提前关闭）
- **交付**：`examples/blocking-offload`、后端对比 benchmark 报告

### M3 HTTP/1 + WebSocket（6–8 周）
- [ ] `flash-http` h1：sans-io 解析（pipelining、chunked、trailers、streaming body、Expect: 100）、`Context`/`Respond`、`sendfile`
- [ ] Router（静态 > regexp 参数 > 参数 > 通配，405/Allow，Mount/Group）；零分配路由 benchmark
- [ ] 中间件：recover、logger、requestid、responsetime、compress、cors、csrf、etag、limiter
- [ ] 静态文件缓存（预压缩 `.br/.gz`、inotify 跟随变更）
- [ ] `flash-ws`：RFC 6455 + permessage-deflate、`PreparedMessage` 广播、Autobahn 进 CI
- [ ] HTTP/1 异步客户端（回调 / future 两种结果通道）
- [ ] 与 hyper、fib 的 HTTP/1 对比报告（plaintext、pipelined、json）
- **交付**：`examples/http`、`examples/ws-chat`

### M4 HTTP/2 + 多协议（8–10 周）
- [ ] HTTP/2：帧/流/流控、HPACK、h2c（先验 + Upgrade）、server push、h2spec 进 CI；h2 客户端
- [ ] `flash-mux`：首字节嗅探（HTTP/TLS/SOCKS/自定义）
- [ ] `flash-arpc`：线协议兼容、双向调用、notify、stream、广播、重连
- [ ] `flash-grpc`：一元 + 流式、metadata、deadline、interceptor、gzip；codec 可插拔（prost）
- [ ] `flash-socks` + HTTP CONNECT 代理：回调到回调转发、双向背压；Linux 下 splice 路径
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
