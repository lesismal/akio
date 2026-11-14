# only 开发计划（Dev Plan）

[English](DEV-PLAN.md) | 简体中文

> 状态：**已审核通过**（2026-11-13），与 ROADMAP 一并确定。
>
> 原说明：配套文档：[ROADMAP.zh-CN.md](ROADMAP.zh-CN.md)（做什么、为什么、何时）。本文档说明**怎么做**：仓库结构、公共 API 草图、每个里程碑的任务拆解、测试与协作规范。

## 1. 仓库结构（Cargo workspace）

```text
only/
├─ Cargo.toml                  # workspace
├─ crates/
│  ├─ only-sys/               # unsafe 系统调用封装：epoll/kqueue/io_uring/eventfd/sendfile/splice…
│  ├─ only-buf/               # size-class 缓冲池、共享只读缓冲（Bytes 风格）
│  ├─ only-timer/             # 分层时间轮
│  ├─ only-pool/              # 逻辑线程池（自适应、有界队列、过载策略）
│  ├─ only-core/              # Engine / Listener / Conn / Handler / Reactor trait
│  ├─ only-epoll/             # epoll(+kqueue) reactor
│  ├─ only-uring/             # io_uring reactor
│  ├─ only-ebpf/              # eBPF 加速层（aya），feature 门控
│  ├─ only-dpdk/              # DPDK reactor + 用户态栈，feature 门控
│  ├─ only-tls/               # rustls sans-io 集成（+ kTLS 可选）
│  ├─ only-http/              # HTTP/1.x、HTTP/2、Router、Context、静态文件
│  ├─ only-ws/                # WebSocket
│  ├─ only-mux/               # 同端口多协议嗅探
│  ├─ only-middleware/        # compress/cors/csrf/etag/limiter/logger/recover/requestid…
│  ├─ only-arpc/  only-grpc/  only-socks/  only-kcp/  only-quic/  only-h3/
│  ├─ only-media/ only-webrtc/ only-bittorrent/   # M7，独立 crate
│  └─ only/                   # 门面 crate：re-export + feature 开关
├─ examples/                   # echo、http、ws、proxy、blocking-offload …
├─ benches/                    # 跨实现 benchmark 套件（含对 fib 的脚本）
├─ fuzz/                       # cargo-fuzz targets
├─ tests/                      # 集成/互通/混沌测试
└─ docs/                       # ROADMAP、DEV-PLAN、adr/（架构决策记录）
```

依赖方向（单向）：`sys → buf/timer/pool → core → {epoll,uring,ebpf,dpdk}` ；`core → tls → http/ws/…`。协议 crate 只依赖 `only-core` 的公共 trait，不依赖具体后端。

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
- [x] `only-sys`：epoll、eventfd、`accept4`、`writev`、`sendfile`、`splice`、`SO_REUSEPORT`、非阻塞 socket 选项
- [x] `only-buf`：size-class 池、线程本地缓存、`SharedBuf` 引用计数缓冲
- [x] `only-timer`：时间轮（连接读写超时、空闲超时、用户定时器）
- [x] `only-core`：`Engine/Listener/Reactor/Handler/Conn`；每 IO 线程事件循环；accept 分发；命令队列 + eventfd 唤醒
- [x] `Conn` 跨线程路径：发送队列、直写优先、唤醒 loop、关闭状态机、generation 防误操作
- [x] 背压：写水位、`hold_reads`、`max_pending_bytes`；优雅关闭
- [x] 异步 dial（客户端连接）
- [x] kqueue reactor（共享逻辑，macOS 可开发/调试）
- [x] 测试：单元、`loom`（cork/发送/关闭竞争，5 个模型，已进 CI）、5000 个同时连接 + 20×500 次连接/关闭循环并检查 fd 泄漏（macOS 与 Linux）
- [x] 空闲超时已接入 loop（`Config::idle_timeout`，每个 I/O 线程一个时间轮）
- [x] M1 遗留项已在基准测试阶段完成：10 万连接测试（10 万空闲连接约 55 MB）、`Config::write_timeout`（输出无进展时以 `TimedOut` 关闭；`idle_timeout` 充当读超时）、与 fib/tokio 的 echo 对比（`docs/BENCHMARKS.md`）。未完成：与 monoio 对比、在专用（非共享）Linux 机器上测量
- **交付**：`examples/echo`，echo benchmark 报告 v0

> M1 状态：**除上述未完成项外已收尾。** 在 Linux（epoll）与 macOS（kqueue）上验证：12 个引擎测试、2 个压力测试、5 个 loom 模型（故意写坏 `mark_closed` 后 loom 模型会失败，说明它确实在探索这个竞争）。`echo-bench` 现在把连接复用到少量客户端线程上；在同一台 macOS 机器上，only 与 4 线程 tokio echo 都是约 10.5–11.5 万 req/s，也就是客户端仍是瓶颈，这次结果只能说明“同一量级”，无法排名。与 fib 的对比需要 fib 先有一个纯 TCP echo（目前没有）以及两台 Linux 机器，顺延到 M2 的 benchmark 报告。`Conn::spawn_blocking` 属于 M2。

### M2 多后端 + 逻辑池 + UDP + TLS（6–8 周）
- [x] `only-pool`：自适应线程池（按需增长到上限，空闲线程退出）、有界队列、过载返回 `Error::Overloaded`、统计
- [x] `Conn::spawn_blocking` + 回调回投 IO 线程（连接已关闭或 `work` panic 时跳过）；有序应答槽（`reserve_response`；未填充就被丢弃的槽会关闭连接）
- [x] 慢回调检测（`Config::slow_callback_threshold`，默认 100 ms；`slow_hook` 或 stderr）。指标导出仍待做
- [x] `only-uring`：multishot accept 与 recv、provided buffer ring、cooperative/deferred task-run + single-issuer 的 ring、eventfd 唤醒、内核探测（5.19+）并自动降级到 epoll（`UringConfig::strict` 可改为拒绝）。写路径走共享的“直接 `write` + 队列”逻辑，积压部分用 `poll(POLLOUT)`
- [ ] `only-uring`：暂未使用（有测量依据再做）：registered files、`SEND_ZC`、`MSG_RING` 唤醒、基于 ring 的发送
- [x] **每 listener 选择后端**：Engine 内多后端并存、线程组独立配置（已测试：同一 Engine 里 epoll + io_uring 两个 listener）；不支持的组合返回明确错误
- [x] UDP（服务端）：`Listener::udp`；每个 peer 地址一个 `Conn`，沿用普通 `Handler`（每个数据报一次 `on_data`，`send` 即发一个数据报，可在任意线程调用），空闲淘汰（`Config::udp_idle_timeout`），优雅关闭不等待排空，`spawn_blocking` 与 `close_after_send` 可用；Linux 上每线程一个 `SO_REUSEPORT` socket（同一 peer 固定在一个线程），其他系统单线程；Linux 上用 `recvmmsg` 批量收。已在 macOS 与 Linux 测试
- [x] UDP 客户端：`Engine::dial_udp`（配合 `EngineBuilder::udp_client_threads`，或使用某个 UDP listener 的线程）：每个拨出的连接有自己 `connect` 过的 socket，因此有独立本地端口；`on_open` 立即执行，每个数据报一次 `on_data`，支持空闲超时与 `close()`；收到 ICMP“端口不可达”会以 `ConnectionRefused` 结束连接。已测试：对 only UDP 服务端（30 个并发拨号 = 30 个不同 peer）、关闭的端口、不应答的服务端、跨线程发送
- [x] UDP 批量化（Linux）：服务端与拨号 socket 均用 `recvmmsg`；同一接收批次的回复跨 peer 用 `sendmmsg` 发出，同一 peer 的等长数据报合并为 UDP GSO（运行时探测，遇 EIO/EINVAL 永久回退，`ONLY_UDP_GSO=0` 可关闭）；新增 `Conn::send_segments`，only-quic 每次最多发送 10 个数据报；可选 GRO（`Config::udp_gro`）；`Config::udp_max_peers` 限制 peer 数并计数（`Engine::udp_stats`）。突发发送时每数据报服务端 CPU 降低 30–46%，64 B echo 约 +19%。未完成：无连接的 `DatagramsHandler`；io_uring UDP 经评估暂不值得（recvmmsg/sendmmsg 已按批处理）；真实网卡上的测量
- [x] `only-tls`：rustls 以 sans-io 方式通过 `Conn` 之下的 `Transport` 层驱动（服务端与客户端；`Tls::server` / `Tls::client` 包装任意 acceptor，handler 看到明文），握手在 IO 线程内完成，握手期间发送的应用数据先缓存，`close_after_send` 发送 close_notify，`tls_info`（ALPN、SNI、版本）。会话票据、SNI 证书选择、客户端认证、版本：通过 rustls 自己的配置。已在 epoll 与 io_uring 上测试：echo（3 MiB）、ALPN/SNI、明文垃圾数据与不受信证书的客户端、TLS 上的 `spawn_blocking` + 有序槽、only 拨 only
- [ ] kTLS 评估（未开始）；TLS 1.3 early data 与客户端证书辅助函数留给 rustls 配置
- [x] 测试：整套 engine/offload/stress 测试在 epoll 与 io_uring 上都跑（`ONLY_TEST_BACKEND=uring`，Linux CI 也跑）；跨后端混合 listener。另已完成：阻塞投递测试（IO 线程不被阻塞、完成回调在 IO 线程且带 handler 状态、池满、连接提前关闭、有序、槽丢弃、慢回调）
- **交付**：`examples/blocking-offload`（已完成）、后端对比 benchmark 报告（已完成：[BENCHMARKS.zh-CN.md](BENCHMARKS.zh-CN.md)）

> M2 状态：逻辑池与 io_uring 已完成；21 个 engine/offload/stress 测试在 Linux（内核 6.12，Docker）上两种后端都通过，重复运行无失败。**io_uring 与 epoll 对比（同一台 Docker 虚拟机，echo，64 B，客户端同机）：** 服务端 4 线程/256 连接时两者都被客户端限制（各约 80–100 万 req/s，无法排名）；服务端 1 线程/512 连接（受服务端限制）时 epoll 为 41.6 万和 49.2 万，io_uring 为 52.7 万和 53.8 万，io_uring 领先约 10–25%。最初的 io_uring 实现每收到一段数据都重新提交一次 `PROVIDE_BUFFERS`，只有 epoll 的约 60%；改用 buffer ring 归还缓冲（写内存而不是提交请求）后差距消失。数据来自与客户端共用 CPU 的虚拟机，只能作方向参考，不是正式 benchmark 报告。**M2 已完成。** benchmark 报告：[BENCHMARKS.zh-CN.md](BENCHMARKS.zh-CN.md)。概要：TCP echo 与 fib、tokio 同一量级（所有测过的负载都领先 fib；64 连接与 16 KiB 落后 tokio 约 15%，512 连接领先），该环境下 io_uring 并不比 epoll 快，逻辑池相对在 I/O 线程里阻塞约恢复 58 倍。

### M3 HTTP/1 + WebSocket（6–8 周）
- [x] `only-http` h1 服务端：`httparse` 解析请求头，自写增量 chunked 解码器（扩展、trailers、任意切分），流水线且按序应答（有序槽），keep-alive/`Connection: close`/HTTP/1.0，`Expect: 100-continue`，限制（头大小、body 大小、头数量），防请求走私（CL+TE、重复 CL），`Context` 支持 `detach()` 之后在任意线程完成应答，优雅关闭时让在途应答先完成。已在 epoll 与 io_uring 上测试
- [x] 流式：请求 body 通过 `Streaming(svc)` + `ctx.on_body`（分块、trailers、无大小限制），响应 body 通过 `ctx.stream_response`（chunked / 以关闭为界，排在更早的流水线响应之后）；文件 body 用 `sendfile(2)`（TLS 下经内存读取）；核心支持：`ResponseStream`、`Part::File`
- [x] h1 后续：HTTP/1 over TLS 测试（`tests/tls.rs`：keep-alive、pipelining、大请求体与 chunked、静态文件、WebSocket 升级）；路由参数在分发时只做一次百分号解码（`Context::param`），原始值可通过 `param_raw` 获取。静态文件：`If-Match`/`If-Unmodified-Since`（412）、按时间比较的 `If-Modified-Since`、`If-Range`，大文件缓存已打开的文件句柄和元数据（`max_open_files`）。未完成：多段 Range 响应、打开文件缓存的淘汰
- [x] Router：静态 > `:param` > `*通配`，带回溯，405 与 `Allow`，HEAD 走 GET 路由，`nest`，每个 router 自己的 layer，自定义 fallback；重复/冲突路由在注册时 panic
- [x] Router 后续：查找过程零分配（参数位置内联存储，参数名与路由树共享），新增 `Router::lookup`/`RouteMatch`；`examples/router-bench.rs` 用 52 条 GitHub 风格路由测试：每次查找约 30 ns、0 次分配，旧实现约 130 ns、4.4 次。正则参数 `{id:[0-9]+}`（默认开启的 `regex` feature），另支持 `{id}`/`{*rest}`；优先级：静态 > 正则 > 普通参数 > 通配符，支持回溯。未完成：段内部分匹配（`/{name}.txt`）
- [x] 中间件：recover、request id、CORS（预检）、访问日志
- [x] 中间件：响应时间、compress（gzip/deflate）、etag + 304、csrf（双重提交 cookie）、按 IP 的令牌桶限流。尚未提供 brotli（还没引入 brotli 依赖）
- [x] 静态文件（`files::Files`）：路径安全、MIME、ETag/Last-Modified/304、单段 Range、index 文件、预压缩 `.br`/`.gz` 同名文件、带 stat 间隔的内存缓存、大文件用 `sendfile`。基于 inotify 的变更跟踪未做（用 stat 间隔代替）
- [x] `only-ws`：RFC 6455 + permessage-deflate（context takeover、服务端窗口位数）、`PreparedMessage` 广播、子协议、Origin 检查、关闭握手；Autobahn|Testsuite：核心 298 项 OK + 3 项 informational，permessage-deflate 216/216 OK，由 `tools/autobahn/run.sh` 在 CI 中运行。Autobahn 发现了 miniz_oxide 的一个 deflate bug（flate2 现改用 zlib-rs）
- [x] WebSocket 客户端（`only_ws::client::dial`/`connect`）：通过 `only::tls` 支持 `ws://`/`wss://`（SNI、自定义 rustls 配置），多地址回退，握手校验（key/accept、子协议、Origin、自定义头），握手与关闭超时，permessage-deflate 协商并遵从服务端选择，帧掩码、符合 RFC 的关闭握手、分片发送。Autobahn 客户端测试（`tools/autobahn/run.sh client`）：517 个用例 514 OK + 3 informational，no-context-takeover 补充轮 216/216；与 fib 的 Go websocket 服务端互通。未完成：系统根证书、代理、重定向、引擎关闭时发送 1001
- [x] HTTP/1 异步客户端（`client::Client`）：回调、`ResponseFuture`（`wait`、`wait_timeout`、`.await`）、按主机复用 keep-alive 连接（复用的连接已失效时重试一次）、chunked/以关闭为界的 body、通过 `only::tls` 支持 HTTPS、地址回退（先 ::1 再 127.0.0.1）。未做：重定向、单请求超时、把 DNS 解析移出调用线程
- [x] 统一基准测试报告（`docs/BENCHMARKS.md`、`tools/bench`：Docker 镜像、wrk/h2load/echo-bench、10k/100k 连接内存、perf 剖析、与其他版本的 A/B；新增 hyper-ref，扩展 tokio-ref/fib-ref）：HTTP/1.1 plaintext/pipelined/JSON、h2c、TCP/UDP/TLS/WebSocket echo，对比 hyper、tokio、tokio-tungstenite、fib。优化：自研 HPACK Huffman 解码（h2c 29 万 → 187 万请求/秒，×6.4）、HTTP/1.1 热路径（plaintext +4–9%，pipelined +17%）、每连接内存（keep-alive 1.6 → 0.9 KB，WebSocket 2.1 → 1.7 KB）。pipelined HTTP/1.1（约 0.8×）与 h2c 仍落后于 fib；数据来自共享、噪声较大的主机
- **交付**：`examples/http`、`examples/ws-chat`

> M3 状态：**除对比报告外功能已完成**（报告移到 benchmark 阶段）：支持流式与 sendfile 的 h1 服务端、router、9 个中间件、静态文件、通过 Autobahn 全部用例的 only-ws（核心 298 项 + 3 项 informational，permessage-deflate 216/216）、h1 客户端。示例：`crates/only-http/examples/{hello,ws-chat,ws-echo}.rs`。

### M4 HTTP/2 + 多协议（8–10 周）
- [x] HTTP/2（`only-http`，与 HTTP/1 共用 `Service`/`Context`）：帧、流、双向流控、HPACK（`loona-hpack`）、h2c（先验与 `Upgrade`）、TLS ALPN `h2`、server push（`ctx.push`）、双向流式 body、GOAWAY 优雅关闭；h2spec strict 147/147（CI job `h2spec`）；curl 互通（先验、upgrade、POST）；`h2client::H2Client`（多路复用、流控、push、TLS）。顺带发现：rustls 单次写入明文超过 64 KiB 会失败，`only-tls` 现按记录大小分段加密
- [x] `only-mux`：首字节嗅探（TLS、HTTP/1、HTTP/2 preface、SOCKS4/5、前缀、自定义规则、fallback）；被选中的 acceptor 像自己 accept 的连接一样接管（回放已读字节、逻辑池回调、优雅关闭）
- [x] `only-arpc`：lesismal/arpc 线协议；双向调用、notify、带超时的异步调用、detach 后应答、stream、广播（共享同一帧）、客户端重连；与 fib 的 Go arpc 双向互通已验证（`tools/interop/arpc/run.sh`）。未做：中间件/编解码链、客户端连接池
- [x] `only-grpc`：基于 only-http 的 HTTP/2，支持一元、服务端/客户端流与双向流（服务端可与普通 HTTP 共用端口），metadata 头与 trailers、trailers-only 错误、deadline（`grpc-timeout`）、拦截器、双向 gzip、消息大小限制、prost 辅助（feature `prost`）；客户端基于 `H2Client::open`（新增的流式请求 API）。与 grpc-go v1.85 双向互通已验证（`tools/interop/grpc/run.sh`）
- [x] `only-socks`：SOCKS5（无认证 / 用户名密码，IPv4/IPv6/域名在逻辑池中解析）、SOCKS4/4a、HTTP `CONNECT` 代理（通过 `Context::upgrade_raw`）；回调到回调的转发，双向背压（核心新增 `Conn::on_drain`；它暴露了一个在 loop 之外清空队列时丢失唤醒的问题，已修复）。未做：SOCKS BIND / UDP ASSOCIATE、Linux `splice` 路径
- [x] 测试：与 curl（h2 先验、h2c upgrade）、h2spec、grpc-go、fib 的 Go arpc 互通。未测：nghttp2 工具、tonic
- **交付**：`examples/grpc`、`examples/proxy`（对应 `crates/only-grpc/examples/grpc-interop.rs` 与 `crates/only-socks` 的测试）

> M4 状态：**已完成。** HTTP/2（h2spec 147/147）、only-mux、only-socks、only-arpc（与 Go 互通）、only-grpc（与 grpc-go 互通）。

### M5 QUIC/H3 + KCP + eBPF（8–10 周）
- [x] `only-quic`/`only-h3`：基于 sans-io QUIC 核心（quinn-proto/quiche 评估后定），QPACK，WebSocket over H3；与 curl/quiche 互通 —— 选定 quinn-proto 0.11。`only-quic`：每个 UDP listener 一个 `quinn_proto::Endpoint`（按连接 ID 路由，支持连接迁移），`QuicServer` acceptor 与 `dial`，`QuicHandler` 回调（流、reset、stop-sending、datagram、关闭）每连接串行执行，非阻塞写入（按流排队、`Writable` 时续写），共享定时线程，rustls（ring）配置辅助函数。`only-h3`：HTTP/3 帧、QPACK（静态表 + 字面量，动态表容量为 0，支持 Huffman 解码）、控制流/QPACK 流及其错误规则；通过新增的 `only_http::transport` 钩子在 H3 上运行任意 `only_http::Service`（同一个 `Context`，含 `detach`、`stream_response`、trailers），body/字段段限制（413/431），`H3Client`。与 quic-go v0.62 及 fib 自身的 QUIC/HTTP/3 双向互通（`tools/interop/h3/run.sh`）。未完成：curl/quiche 互通（手头没有支持 HTTP/3 的构建）、H3 上的 WebSocket（扩展 CONNECT）、QPACK 动态表、服务器推送、流式请求体
- [x] `only-kcp`：兼容 skywind3000/kcp 与 kcp-go（加密、XOR、FEC）、按需 flush —— sans-io 的 KCP 核心（移植自 fib），kcp-go 的 Reed–Solomon FEC（klauspost 矩阵），加密 none/xor/aes/aes-128/aes-192/aes-128-gcm；UDP listener 上的 `KcpServer` acceptor（按对端建会话、会话替换、`max_sessions`）、`dial`、在 I/O 线程回调的 `KcpHandler`，按 `next_flush` 驱动的共享定时线程；dead-link 关闭；与 kcp-go v5 双向互通，覆盖六种加密/FEC 组合，并经过每 7 个丢 1 个数据报的中继（`tools/interop/kcp/run.sh`）
- [x] `only-ebpf`：`SO_REUSEPORT` 调度，按 CPU（`cpu % threads`）或确定性一致性哈希（Maglev，251 槽，按源 IP 或 IP+端口）；经典 BPF 无需特权，TCP/UDP 均可，有特权时用 eBPF（`SK_REUSEPORT` + sockarray）。`Accel::Ebpf(EbpfConfig)` 不可用时降级（`strict` 时报错），`Engine::accel_status()` 查询实际挂载情况。sockmap 转发（以 socket cookie 为键的 `SOCKHASH` + `sk_skb` verdict）：`Relay::splice`/`splice_conns` 在内核中转发两条 TCP 连接；默认要求 Linux 6.15+，因为 6.12 在 psock backlog 遇到 EAGAIN 会丢数据（已复现）。程序手工汇编、原始 `bpf(2)` 加载（不依赖 aya、不需要 nightly；见 ADR-006）。未完成：XDP 限速、I/O 线程绑定 CPU、only-socks 接入 relay、eBPF 哈希层、eBPF 基准测试
- [x] 测试：eBPF 程序在特权 Docker 容器（eBPF 层、relay）与非特权容器（经典 BPF、降级路径）中运行，覆盖 epoll 与 io_uring；`ONLY_TEST_EXPECT_EBPF=1` 时跳过即失败。未完成：本地 VM 测试
- **交付**：`examples/h3`、`examples/kcp`、eBPF 加速 benchmark

### M6 DPDK + 生产化（6–8 周）
- [x] `only-dpdk`（实验性）：在 only I/O 线程上运行 smoltcp 用户态 TCP/IP 协议栈；按 `EalConfig` 初始化 EAL，每个 rx/tx 队列一个线程，经 C shim 批量收发 mbuf，RSS 并扇出 ARP；另支持 TAP、AF_PACKET 与内存链路。`Backend::Dpdk(DpdkConfig)` 位于 `dpdk`/`dpdk-pmd` feature 之后；支持 UDP/TCP listener 与 `dial`/`dial_udp`；only-kcp 无需修改即可运行。已在 Docker 中与 Linux 内核协议栈互测（DPDK `net_tap` 单/双队列、TAP、veth 上的 AF_PACKET）；重型 CI 任务 `dpdk`。未完成：IPv6、IP 分片与卸载、多队列拨号、SACK/拥塞控制、真实网卡基准（IP 分片、多队列拨号、SACK 与拥塞控制已随自研协议栈完成，见下文第 A 波）
- [x] 生产化：每个 I/O 线程的 relaxed 计数器（连接、字节、读写次数、UDP 数据报、发送队列字节、背压/过载、TLS 握手失败、循环迭代/事件/回调耗时、慢回调）及池统计，`Engine::metrics()` 输出 Prometheus 文本或 JSON；基于 `log` 门面的结构化日志（带键值，无 logger 时回退 stderr，`Config::log_level`）；运行时调试：由事件循环收集的连接表、慢回调环形缓冲、线程循环统计；only-http 提供 `metrics_handler`、`HttpMetrics`（状态码分类、延迟直方图）、`access_log`、可用 token 保护的 `debug_handler`；`Engine::reload`/`Live` 热更新（空闲超时、慢回调阈值/钩子、队列上限、高水位、新增 `max_connections`、关闭超时、日志级别）。未完成：`tracing` feature、读缓冲/backlog/线程数/UDP 空闲超时的热更新、按路由的 HTTP 标签、在空闲机器上测量开销
- [x] 混沌测试：为引擎（`only/tests/chaos.rs`）、fd 耗尽（`chaos_fd.rs`）、TLS（`chaos_tls.rs`）和 HTTP/WebSocket（`only-http/tests/chaos.rs`）新增带种子、可复现的测试：RST 中断、半关闭、慢读与不读客户端、逻辑池饱和、EMFILE、负载下关闭；校验 `on_close` 恰好一次、无卡死、队列有界、无 fd 泄漏。默认只跑少量种子，`ONLY_CHAOS=1 ONLY_CHAOS_SECS=300` 进行浸泡（macOS、Linux epoll 与 io_uring 均无违规）。修复的 bug：EOF 截断未完成的有序响应；超限有序响应被静默丢弃；epoll 在 EMFILE 时空转；io_uring 漏掉数据之后的 RST；io_uring 可能复用仍被未提交 SQE 引用的 fd
- [x] Prefork（可选）：`only-prefork`：supervisor 以 N 个 worker 重新执行二进制，各自运行 `Engine`；监听套接字经 SO_REUSEPORT 共享（Linux 默认）或继承（macOS 默认，重启/重载期间不拒绝连接）；崩溃退避重启、SIGTERM/SIGINT 排空、SIGHUP/`Supervisor::reload` 切换代际、pdeathsig、CPU 绑核；新增 `Listener::tcp_from_std`。未完成：基于 bpffs 的跨进程 eBPF 分流；ReusePort 重载需要 `tcp_migrate_req`
- **交付**：长稳（≥72h）报告

### M7 重型协议（开放）
- [x] 流媒体（`only-media`）：统一 hub（GOP 缓存、慢播放者丢帧至关键帧、鉴权钩子、重推等待、时间戳规整、统计）；RTMP 服务端（digest 握手、Enhanced RTMP H.265/Opus）、HTTP-FLV、WS-FLV、HLS（MPEG-TS、LL-HLS 分片、阻塞式刷新）、RTSP 服务端（TCP/UDP、推流/播放、Digest 鉴权）、SRT live（ARQ、TSBPD、AES、推/拉流）、WHIP/WHEP 信令；每个协议均与 ffmpeg/ffprobe 互通；9 个 fuzz 目标。未完成：fMP4 HLS、加密、RTMP/RTSP 客户端、SRT rendezvous、hub 中的 WebRTC 媒体
- [x] WebRTC（`only-webrtc`、`only-turn`）：在 only UDP 上运行 str0m 0.24，使用纯 Rust 加密实现；ICE-lite 的 `RtcServer` 与完整 ICE 的 `Endpoint`（新增 `Engine::bind_udp`），DTLS-SRTP、SCTP 数据通道、带 NACK/PLI/TWCC 的 RTP/RTCP；STUN 编解码/服务器与 TURN 服务器（长期与 REST 凭据、通道、EVEN-PORT、配额）。与 pion（双向，含经 only TURN）、fib、pion/turn、coturn 互通；3 个 fuzz 目标。未完成：TCP/TLS 上的 TURN、`Endpoint` 的 TURN 客户端、ICE-TCP、mDNS
- [x] BitTorrent（`only-bittorrent`）：bencode、v1 种子与磁力链接、HTTP/UDP tracker（客户端与服务端）、带 Fast 扩展/ut_metadata/PEX/MSE-RC4 的 peer wire、带 LEDBAT 的 uTP、主线 DHT、客户端（最稀有优先、残局、choke、存储走逻辑池）；新增 `Engine::dial_udp_from`。与 libtorrent 2.0.11、aria2 1.37 互通 15/15；6 个 fuzz 目标。未完成：BEP 52（v2/混合）、web seed、LSD、BEP 44、IPv6 DHT、限速与分享率限制
- 各自独立 crate、独立 README 与测试；视社区与精力并行推进。

### 1.0 稳定化
- [x] API 审阅与冻结、semver 策略、弃用流程：清点并快照公开 API（`api/*.txt`、cargo public-api、CI 门禁 `public-api`；`semver-checks` 在 1.0.0 发布后生效）；lint 强制 `Debug` 与 `#[must_use]`；配置、报告与可增长枚举 `#[non_exhaustive]`；后端管道 `#[doc(hidden)]`；新增 `AnyAcceptor`/`serve_any`；统一 `dial`/`dial_blocking`、`serve`/`serve_with`、`*_bytes`；kcp、h3 以类型化错误取代 `String`；迁移表见 `CHANGELOG.md`；`docs/api-stability.md`（semver 分级、MSRV 1.85、平台级别）、`docs/deprecation.md`；版本 1.0.0-rc.1 并补全发布元数据。1.0.0 前待定：crates.io 上 `flash` 名称已被占用；公开依赖尚未到 1.0（rustls、quinn-proto、prost）（均已在下文“1.0.0 发布决定”中解决）
- [x] 全量 fuzz 语料与覆盖率报告、`cargo-audit/deny`、unsafe 审查清单。模糊测试：`fuzz/` cargo-fuzz 工程 21 个目标（HTTP/1、HTTP/2 + HPACK、WebSocket、arpc、gRPC、SOCKS、mux、KCP、HTTP/3 + QPACK、cBPF），最小化语料约 2.6 MB 由 stable 单元测试回放，每个目标在 Linux 上约 14 分钟，每夜 CI 任务；修复 HTTP/2 死锁、递归 server push、gRPC `grpc-timeout` panic/溢出、KCP RTT 溢出、SOCKS 缓冲无上限。供应链：`deny.toml` + `.cargo/audit.toml`，`cargo deny`/`cargo audit` 通过并作为 CI 门禁（一个仅开发依赖的通告带理由忽略，直到 MSRV 1.88）。unsafe：仅限 only-sys、only-uring、only-ebpf，其余 crate 全部 `forbid(unsafe_code)`，缺少安全注释即报错，CI 运行清单 `--check`（`docs/unsafe-review.md`、`SECURITY.md`）；修复 12 个问题（含 `RecvBatch` 堆溢出、io_uring 缓冲区别名及在途操作未结束即释放、bpf(2) 键/值大小未校验）。Miri 扩展到协议 crate，在 zlib-rs 0.6.8 中发现 UB（待向上游报告）。未完成：首次运行 ASan/TSan（已加入重型 CI 任务）
- [x] CI 加固与覆盖率：严格 lint 集（`missing_docs` deny、`unreachable_pub`、库代码 `unwrap_used`、精选 pedantic/nursery），rustdoc `-D warnings`；矩阵：Linux x86_64/arm64 × epoll/io_uring、macOS（尽力而为）、MSRV 1.85、cargo-hack 特性组合、Miri、loom、Autobahn（服务端+客户端）、h2spec、文档书构建与 Pages 部署、重任务（Go 互通、每夜 fuzz）；统一的 `ci-ok` 门禁。覆盖率任务（cargo-llvm-cov，两种后端合并）：行覆盖率 85.9% → 91.6%，每个 crate ≥ 85%。顺带修复：only-quic 在方向错误的流上 panic、15 处持锁调用回调、`--no-default-features` 测试编译、两处测试竞态。尚未在 GitHub 上实际运行验证（Pages 设置、fib 检出、Codecov）
- [x] 文档站 + 迁移指南 + 架构文档：mdBook `book/en` 与 `book/zh-CN`（快速上手、核心概念、每个协议一章、配置参考、可观测性与热更新、性能调优、故障排查），由 `book/build.sh` 构建；所有代码片段来自 14 个可运行的 `guide-*` 示例；从 fib、tokio、hyper/axum 迁移的指南；带 Mermaid 图的 `docs/architecture.md`；各 crate 的 rustdoc 链接到对应章节；根目录 README。未完成：Pages 部署、在 Linux 上运行这些示例

### 1.0.0 发布决定（2026-11-14）
- [x] 项目更名为 **only**：crate 改为 `only`、`only-core`、`only-http` 等（crates.io 上 `flash` 已被占用），涉及代码、文档、手册、工具与 CI：目录与包名 `crates/only-*`、代码路径 `only_*`、环境变量 `ONLY_*`、指标 `only_*`、日志 target 与线程名 `only*`、快照 `api/only-*.txt`、Docker 镜像、两本手册与全部文档；GitHub 仓库已改名为 `lesismal/only`（Pages 为 `lesismal.github.io/only`）；对照表见 CHANGELOG
- [x] 将尚未 1.0 的公开依赖（rustls、quinn-proto、prost、str0m）封装在项目自己的类型之后，原始访问只在 `unstable` feature 中提供，使升级它们不再是破坏性变更：`tls::{ServerConfig, ClientConfig}` 构建器（PEM/DER 证书与私钥、按 SNI 选证书、ALPN、客户端认证、会话缓存与票据、根证书、仅测试用的跳过验证）与 `tls::Error`，供 TLS、HTTP/HTTP-2 客户端、WebSocket 客户端、QUIC 与 HTTP/3 使用；自有 QUIC `ServerConfig` / `ClientConfig` / `TransportConfig`、`StreamId` / `Dir` / `Side`、`ConnectionError`、`ConnectionStats`；gRPC 的 `codec::Message` trait，prost 适配器在 `prost` feature 之后（不在 semver 内）；自有 WebRTC id、媒体、事件、候选、`RtcConfig` 与 `SdpChanges`，`Peer::with_rtc` 移到 `unstable` 之后；API 快照中不再含 rustls/quinn/prost/str0m 类型；迁移表见 CHANGELOG
- 回调名保持各协议自己的术语（QUIC 的 `on_connected`、WebSocket 的 `on_open` 等）

### 长期目标：去掉所有三方依赖
- [ ] 逐个自研库中用到的所有三方依赖，每一项保持相同的公开 API（API 快照不变），以已知答案测试向量、互通与模糊测试作为门禁。顺序（每一波依赖前一波）：
  - [x] 第 A 波：`only-crypto`（SHA-1/2、MD5、HMAC、HKDF、PBKDF2、CRC32、AES、CTR、GCM、ChaCha20-Poly1305、base64、系统随机数）替代 sha1/sha2/md-5/hmac/pbkdf2/aes/aes-gcm/ctr/crc32fast/base64/getrandom（已完成：AES 使用 AES-NI / ARMv8 AES，并有常数时间 fixsliced 回退，ctmul64 GHASH，NIST CAVP / RFC / Wycheproof 向量，与旧 crate 的差分测试和模糊测试目标；only-kcp、-turn、-ws、-http、-media、-bittorrent 与 -webrtc 已迁移，线上格式经证明不变；后续：SHA-NI / ARMv8 SHA、PMULL / PCLMULQDQ GHASH 与 CRC32 指令，因为可移植的 SHA-1 约为旧 crate 加速速度的一半，CRC-32 只有其一小部分）；自研 HTTP/1 解析、HPACK 与正则引擎替代 httparse/loona-hpack/regex；自研 deflate/zlib/gzip 替代 flate2；自研用户态 TCP/IP 栈替代 smoltcp；自研 protobuf 运行时替代 prost
    - [x] protobuf：`only-protobuf`（运行时：线格式、消息、开放枚举、未知字段、well-known 类型；无依赖）与 `only-protobuf-build`（自研 `.proto` 解析器与供 `build.rs` 使用的代码生成器，不需要 protoc / syn / quote；生成 only-grpc 服务桩代码）。用 protoc 生成的黄金编码、与 prost 的差分测试和 fuzz 目标 `protobuf_diff`、与 grpc-go 自带 route_guide / helloworld 生成代码的互通（`tools/interop/grpc/run.sh`）做了验证。only-grpc 的 `prost` feature 已弃用（保留，不在 semver 内）。未做：group、extension、edition、JSON 映射、反射
    - [x] HTTP 编解码：`only_ws::http1`（零拷贝、增量、按 RFC 9110/9112 严格校验的头部解析器；安全代码中按字扫描，速度与 httparse 相当）、`only_http::hpack`（编码器与解码器都带动态表，双向 Huffman，大小更新，never-indexed 字段，解码时即应用列表大小限制；RFC 7541 附录 C 向量）、`only_http::re`（路由约束用的线性时间 Thompson NFA，小模式用位并行，其余用 Pike VM）；httparse/loona-hpack/regex 已从库中移除（仅 `fuzz/` 的差分目标与 `tools/codec-bench` 保留）；h2spec 147/147，`regex` feature 变为空操作
    - [x] 自研用户态 TCP/IP 协议栈替代 smoltcp（`only-dpdk/src/net`，`#![forbid(unsafe_code)]`，无依赖）：以太网、带待发队列的 ARP（首个 SYN 不再丢失）、IPv4 分片/重组、ICMP（回显，不可达交付给已拨出的 UDP 连接）、UDP，以及遵循 RFC 9293 的 TCP：RFC 6298 RTO、SACK + RFC 6675 恢复、NewReno 与 CUBIC、窗口缩放 + 时间戳/PAWS、延迟 ACK、keepalive、TIME-WAIT、RFC 5961、SYN cookie；事件驱动的循环与定时器堆；多队列拨号；TAP/AF_PACKET 不再依赖 smoltcp 的 phy。模拟丢包链路测试、Docker 中与内核互测（netem 丢包、窗口缩放、500 条连接），7 个模糊测试目标。未完成：IPv6/NDP、卸载、pacing/ECN
    - [x] Deflate：`only-deflate`（纯安全 Rust，无依赖）替代 only-ws、only-http、only-grpc 中的 flate2/zlib-rs：raw DEFLATE、zlib 与 gzip 的流式解压（任意拆分输入、有界输出、窗口 2^8..2^15、与 zlib 相同的编码检查）与压缩（哈希链、惰性匹配、zlib 级别、限长动态 Huffman、固定或存储块、同步/完全刷新、窗口 2^8..2^15，因此 permessage-deflate 现在也支持 8 位窗口）。与 zlib-rs 和 `gzip(1)` 双向互通、与 zlib-rs 差分模糊测试、Autobahn permessage-deflate 服务端与客户端用例、与 grpc-go 的 gRPC gzip 互通、Miri（zlib-rs 的别名问题随之消失，only-grpc 的 gzip 测试重新在 Miri 下运行）。级别 1/6/9 的压缩率与 zlib-rs 相当或更好；解压吞吐为 zlib-rs 的 0.75-0.85 倍，压缩为 0.25-0.6 倍（无 SIMD、无 `unsafe`）；permessage-deflate 回显吞吐（仅压缩部分）在 64 B 消息时为 zlib-rs 的 1.2 倍，0.5-64 KiB 时为 0.5-0.7 倍
  - [x] 第 B 波：公钥密码学（X25519、P-256 ECDH/ECDSA、Ed25519、RSA PKCS#1/PSS 验签）与 ASN.1/X.509；自研日志门面替代 `log`（可选 `log` 桥接）；自研系统调用与 io_uring 绑定替代 libc/io-uring
    - [x] 日志门面：`only-log`（无依赖，`#![forbid(unsafe_code)]`，以 `only::log` 重新导出）：级别、target、沿用 `log` 宏语法的结构化键值对、原子全局最大级别（禁用语句 0.25-0.29 ns，`log` 为 0.36）、`Logger` / `set_logger` / `set_boxed_logger`、内置 `FmtLogger`（`only::log::init`）与 `StderrLogger`，保留 stderr 兜底。所有 crate 已迁移，`log` 退出库的依赖；target 与键名不变。可选 `log` feature（不在 semver 内）：未安装 only-log logger 时记录转发给 `log` 的 logger，`bridge::route_log_to_only` 反向接入。破坏性变更：`Config::log_level` / `Telemetry::set_log_level` 改用 `only::log::LevelFilter`。未完成：编译期级别 feature、环境变量过滤语法、`tracing` span
    - [x] 系统调用与 io_uring 绑定：`only_sys::ffi`（自有 C 类型、常量、带编译期布局断言的 `#[repr(C)]` 结构体，Linux 上 C 库与 macOS 上 libSystem 函数的 `extern "C"` 声明；`bpf`/`io_uring_*` 经 `syscall(2)` 按架构区分调用号；errno/EINTR 语义不变）与 `only-uring` 的 `ring`（setup/enter/register、按内核内存序访问的 mmap SQ/CQ ring、SQE 构造、CQE 标志、probe 与特性检查、SQPOLL）；only-ebpf 与 only-dpdk 已迁移；`libc`/`io-uring` 已从各库移除（`libc` 仍是 dev-dependency：在 macOS aarch64、Linux aarch64 与 x86_64 上将每个布局与常量与之对比）。未做：裸 `asm!` 系统调用（C 库仍经 `std` 链接）、musl 专门的布局测试
    - [x] 公钥密码学与 X.509：`only-crypto` 新增 X25519、Ed25519、P-256/P-384 的 ECDH 与 ECDSA（RFC 6979）、RSA PKCS#1 v1.5/PSS 签名与验证（2048–8192 位，CRT + 盲化）、严格 DER/PEM 以及 PKCS#8/SEC1/PKCS#1/SPKI 密钥（`pkey`）；新的 `only-x509` 解析证书、构建并校验证书链（有效期、CA/pathLen、KU/EKU、名称约束、RFC 6125 名称匹配），并能生成自签名 / CA 签发的证书。常数时间域运算、完备公式、全表查表；Wycheproof/RFC 向量，与 ring/RustCrypto/rcgen/rustls-webpki 交叉验证，真实与 OpenSSL 证书链，模糊测试目标 `x509_parse` 与 `crypto_sig_verify`。相对 ring 的速度：Ed25519/X25519 0.7–0.85 倍，P-256 约 0.3 倍（ring 用汇编），P-384 0.8–2 倍，RSA-2048 约 0.4 倍。后续：专用 P-256 域（Solinas/fiat）、wNAF 验签、RSA 密钥生成、CRL/OCSP
  - [ ] 第 C 波：自研 TLS 1.2/1.3 与 DTLS 替代 rustls（及 ring）
  - [ ] 第 D 波：自研 QUIC 替代 quinn-proto（及 bytes）；自研 WebRTC 栈（ICE、DTLS-SRTP、SCTP、RTP/RTCP）替代 str0m/dimpl/p256
  - 仅测试用的工具（loom、rcgen 等）最后替换，或保留

## 4. 工程规范
- **分支/提交**：`main` 保持可发布；功能分支 + PR；Conventional Commits。
- **代码**：`#![forbid(unsafe_code)]` 为默认，仅 `only-sys`、后端、`only-buf` 允许 unsafe，且每处带 `// SAFETY:`。
- **测试金字塔**：单元 → loom/miri → 集成/互通 → 混沌 → benchmark；新功能必须带测试，协议解析必须带 fuzz target。
- **ADR**：任何影响公共 API、线程/锁模型、依赖的决策先写 `docs/adr/NNN-*.md`。
- **文档**：每个 crate 有 crate-level 文档与可运行 doctest；README 保持中英双语（与 fib 一致）。
- **性能**：PR 若触及热路径，附 benchmark 前后对比；夜间 benchmark 对比历史基线。

## 5. 建议的启动顺序（审核通过后）
1. M0：先定稿 ADR-001~004 与 `Handler`/`Conn` API 原型（这是后续所有工作的地基，改动成本最高）。
2. M1：先打通 epoll TCP echo + 跨线程 `Conn::send`，尽早上 loom 和 benchmark。
3. M2 开头先做逻辑池（它直接决定 `Handler` 的状态类型设计），再做 io_uring。
4. 其余按里程碑顺序推进；M7 视情况并行。
