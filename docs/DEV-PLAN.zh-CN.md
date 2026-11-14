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
- [x] UDP 批量化（Linux）：服务端与拨号 socket 均用 `recvmmsg`；同一接收批次的回复跨 peer 用 `sendmmsg` 发出，同一 peer 的等长数据报合并为 UDP GSO（运行时探测，遇 EIO/EINVAL 永久回退，`FLASH_UDP_GSO=0` 可关闭）；新增 `Conn::send_segments`，flash-quic 每次最多发送 10 个数据报；可选 GRO（`Config::udp_gro`）；`Config::udp_max_peers` 限制 peer 数并计数（`Engine::udp_stats`）。突发发送时每数据报服务端 CPU 降低 30–46%，64 B echo 约 +19%。未完成：无连接的 `DatagramsHandler`；io_uring UDP 经评估暂不值得（recvmmsg/sendmmsg 已按批处理）；真实网卡上的测量
- [x] `flash-tls`：rustls 以 sans-io 方式通过 `Conn` 之下的 `Transport` 层驱动（服务端与客户端；`Tls::server` / `Tls::client` 包装任意 acceptor，handler 看到明文），握手在 IO 线程内完成，握手期间发送的应用数据先缓存，`close_after_send` 发送 close_notify，`tls_info`（ALPN、SNI、版本）。会话票据、SNI 证书选择、客户端认证、版本：通过 rustls 自己的配置。已在 epoll 与 io_uring 上测试：echo（3 MiB）、ALPN/SNI、明文垃圾数据与不受信证书的客户端、TLS 上的 `spawn_blocking` + 有序槽、flash 拨 flash
- [ ] kTLS 评估（未开始）；TLS 1.3 early data 与客户端证书辅助函数留给 rustls 配置
- [x] 测试：整套 engine/offload/stress 测试在 epoll 与 io_uring 上都跑（`FLASH_TEST_BACKEND=uring`，Linux CI 也跑）；跨后端混合 listener。另已完成：阻塞投递测试（IO 线程不被阻塞、完成回调在 IO 线程且带 handler 状态、池满、连接提前关闭、有序、槽丢弃、慢回调）
- **交付**：`examples/blocking-offload`（已完成）、后端对比 benchmark 报告（已完成：[BENCHMARKS.zh-CN.md](BENCHMARKS.zh-CN.md)）

> M2 状态：逻辑池与 io_uring 已完成；21 个 engine/offload/stress 测试在 Linux（内核 6.12，Docker）上两种后端都通过，重复运行无失败。**io_uring 与 epoll 对比（同一台 Docker 虚拟机，echo，64 B，客户端同机）：** 服务端 4 线程/256 连接时两者都被客户端限制（各约 80–100 万 req/s，无法排名）；服务端 1 线程/512 连接（受服务端限制）时 epoll 为 41.6 万和 49.2 万，io_uring 为 52.7 万和 53.8 万，io_uring 领先约 10–25%。最初的 io_uring 实现每收到一段数据都重新提交一次 `PROVIDE_BUFFERS`，只有 epoll 的约 60%；改用 buffer ring 归还缓冲（写内存而不是提交请求）后差距消失。数据来自与客户端共用 CPU 的虚拟机，只能作方向参考，不是正式 benchmark 报告。**M2 已完成。** benchmark 报告：[BENCHMARKS.zh-CN.md](BENCHMARKS.zh-CN.md)。概要：TCP echo 与 fib、tokio 同一量级（所有测过的负载都领先 fib；64 连接与 16 KiB 落后 tokio 约 15%，512 连接领先），该环境下 io_uring 并不比 epoll 快，逻辑池相对在 I/O 线程里阻塞约恢复 58 倍。

### M3 HTTP/1 + WebSocket（6–8 周）
- [x] `flash-http` h1 服务端：`httparse` 解析请求头，自写增量 chunked 解码器（扩展、trailers、任意切分），流水线且按序应答（有序槽），keep-alive/`Connection: close`/HTTP/1.0，`Expect: 100-continue`，限制（头大小、body 大小、头数量），防请求走私（CL+TE、重复 CL），`Context` 支持 `detach()` 之后在任意线程完成应答，优雅关闭时让在途应答先完成。已在 epoll 与 io_uring 上测试
- [x] 流式：请求 body 通过 `Streaming(svc)` + `ctx.on_body`（分块、trailers、无大小限制），响应 body 通过 `ctx.stream_response`（chunked / 以关闭为界，排在更早的流水线响应之后）；文件 body 用 `sendfile(2)`（TLS 下经内存读取）；核心支持：`ResponseStream`、`Part::File`
- [x] h1 后续：HTTP/1 over TLS 测试（`tests/tls.rs`：keep-alive、pipelining、大请求体与 chunked、静态文件、WebSocket 升级）；路由参数在分发时只做一次百分号解码（`Context::param`），原始值可通过 `param_raw` 获取。静态文件：`If-Match`/`If-Unmodified-Since`（412）、按时间比较的 `If-Modified-Since`、`If-Range`，大文件缓存已打开的文件句柄和元数据（`max_open_files`）。未完成：多段 Range 响应、打开文件缓存的淘汰
- [x] Router：静态 > `:param` > `*通配`，带回溯，405 与 `Allow`，HEAD 走 GET 路由，`nest`，每个 router 自己的 layer，自定义 fallback；重复/冲突路由在注册时 panic
- [x] Router 后续：查找过程零分配（参数位置内联存储，参数名与路由树共享），新增 `Router::lookup`/`RouteMatch`；`examples/router-bench.rs` 用 52 条 GitHub 风格路由测试：每次查找约 30 ns、0 次分配，旧实现约 130 ns、4.4 次。正则参数 `{id:[0-9]+}`（默认开启的 `regex` feature），另支持 `{id}`/`{*rest}`；优先级：静态 > 正则 > 普通参数 > 通配符，支持回溯。未完成：段内部分匹配（`/{name}.txt`）
- [x] 中间件：recover、request id、CORS（预检）、访问日志
- [x] 中间件：响应时间、compress（gzip/deflate）、etag + 304、csrf（双重提交 cookie）、按 IP 的令牌桶限流。尚未提供 brotli（还没引入 brotli 依赖）
- [x] 静态文件（`files::Files`）：路径安全、MIME、ETag/Last-Modified/304、单段 Range、index 文件、预压缩 `.br`/`.gz` 同名文件、带 stat 间隔的内存缓存、大文件用 `sendfile`。基于 inotify 的变更跟踪未做（用 stat 间隔代替）
- [x] `flash-ws`：RFC 6455 + permessage-deflate（context takeover、服务端窗口位数）、`PreparedMessage` 广播、子协议、Origin 检查、关闭握手；Autobahn|Testsuite：核心 298 项 OK + 3 项 informational，permessage-deflate 216/216 OK，由 `tools/autobahn/run.sh` 在 CI 中运行。Autobahn 发现了 miniz_oxide 的一个 deflate bug（flate2 现改用 zlib-rs）
- [x] WebSocket 客户端（`flash_ws::client::dial`/`connect`）：通过 `flash::tls` 支持 `ws://`/`wss://`（SNI、自定义 rustls 配置），多地址回退，握手校验（key/accept、子协议、Origin、自定义头），握手与关闭超时，permessage-deflate 协商并遵从服务端选择，帧掩码、符合 RFC 的关闭握手、分片发送。Autobahn 客户端测试（`tools/autobahn/run.sh client`）：517 个用例 514 OK + 3 informational，no-context-takeover 补充轮 216/216；与 fib 的 Go websocket 服务端互通。未完成：系统根证书、代理、重定向、引擎关闭时发送 1001
- [x] HTTP/1 异步客户端（`client::Client`）：回调、`ResponseFuture`（`wait`、`wait_timeout`、`.await`）、按主机复用 keep-alive 连接（复用的连接已失效时重试一次）、chunked/以关闭为界的 body、通过 `flash::tls` 支持 HTTPS、地址回退（先 ::1 再 127.0.0.1）。未做：重定向、单请求超时、把 DNS 解析移出调用线程
- [ ] 与 hyper、fib 的 HTTP/1 对比报告（plaintext、pipelined、json）：放到功能阶段结束后的统一 benchmark 阶段
- **交付**：`examples/http`、`examples/ws-chat`

> M3 状态：**除对比报告外功能已完成**（报告移到 benchmark 阶段）：支持流式与 sendfile 的 h1 服务端、router、9 个中间件、静态文件、通过 Autobahn 全部用例的 flash-ws（核心 298 项 + 3 项 informational，permessage-deflate 216/216）、h1 客户端。示例：`crates/flash-http/examples/{hello,ws-chat,ws-echo}.rs`。

### M4 HTTP/2 + 多协议（8–10 周）
- [x] HTTP/2（`flash-http`，与 HTTP/1 共用 `Service`/`Context`）：帧、流、双向流控、HPACK（`loona-hpack`）、h2c（先验与 `Upgrade`）、TLS ALPN `h2`、server push（`ctx.push`）、双向流式 body、GOAWAY 优雅关闭；h2spec strict 147/147（CI job `h2spec`）；curl 互通（先验、upgrade、POST）；`h2client::H2Client`（多路复用、流控、push、TLS）。顺带发现：rustls 单次写入明文超过 64 KiB 会失败，`flash-tls` 现按记录大小分段加密
- [x] `flash-mux`：首字节嗅探（TLS、HTTP/1、HTTP/2 preface、SOCKS4/5、前缀、自定义规则、fallback）；被选中的 acceptor 像自己 accept 的连接一样接管（回放已读字节、逻辑池回调、优雅关闭）
- [x] `flash-arpc`：lesismal/arpc 线协议；双向调用、notify、带超时的异步调用、detach 后应答、stream、广播（共享同一帧）、客户端重连；与 fib 的 Go arpc 双向互通已验证（`tools/interop/arpc/run.sh`）。未做：中间件/编解码链、客户端连接池
- [x] `flash-grpc`：基于 flash-http 的 HTTP/2，支持一元、服务端/客户端流与双向流（服务端可与普通 HTTP 共用端口），metadata 头与 trailers、trailers-only 错误、deadline（`grpc-timeout`）、拦截器、双向 gzip、消息大小限制、prost 辅助（feature `prost`）；客户端基于 `H2Client::open`（新增的流式请求 API）。与 grpc-go v1.85 双向互通已验证（`tools/interop/grpc/run.sh`）
- [x] `flash-socks`：SOCKS5（无认证 / 用户名密码，IPv4/IPv6/域名在逻辑池中解析）、SOCKS4/4a、HTTP `CONNECT` 代理（通过 `Context::upgrade_raw`）；回调到回调的转发，双向背压（核心新增 `Conn::on_drain`；它暴露了一个在 loop 之外清空队列时丢失唤醒的问题，已修复）。未做：SOCKS BIND / UDP ASSOCIATE、Linux `splice` 路径
- [x] 测试：与 curl（h2 先验、h2c upgrade）、h2spec、grpc-go、fib 的 Go arpc 互通。未测：nghttp2 工具、tonic
- **交付**：`examples/grpc`、`examples/proxy`（对应 `crates/flash-grpc/examples/grpc-interop.rs` 与 `crates/flash-socks` 的测试）

> M4 状态：**已完成。** HTTP/2（h2spec 147/147）、flash-mux、flash-socks、flash-arpc（与 Go 互通）、flash-grpc（与 grpc-go 互通）。

### M5 QUIC/H3 + KCP + eBPF（8–10 周）
- [x] `flash-quic`/`flash-h3`：基于 sans-io QUIC 核心（quinn-proto/quiche 评估后定），QPACK，WebSocket over H3；与 curl/quiche 互通 —— 选定 quinn-proto 0.11。`flash-quic`：每个 UDP listener 一个 `quinn_proto::Endpoint`（按连接 ID 路由，支持连接迁移），`QuicServer` acceptor 与 `dial`，`QuicHandler` 回调（流、reset、stop-sending、datagram、关闭）每连接串行执行，非阻塞写入（按流排队、`Writable` 时续写），共享定时线程，rustls（ring）配置辅助函数。`flash-h3`：HTTP/3 帧、QPACK（静态表 + 字面量，动态表容量为 0，支持 Huffman 解码）、控制流/QPACK 流及其错误规则；通过新增的 `flash_http::transport` 钩子在 H3 上运行任意 `flash_http::Service`（同一个 `Context`，含 `detach`、`stream_response`、trailers），body/字段段限制（413/431），`H3Client`。与 quic-go v0.62 及 fib 自身的 QUIC/HTTP/3 双向互通（`tools/interop/h3/run.sh`）。未完成：curl/quiche 互通（手头没有支持 HTTP/3 的构建）、H3 上的 WebSocket（扩展 CONNECT）、QPACK 动态表、服务器推送、流式请求体
- [x] `flash-kcp`：兼容 skywind3000/kcp 与 kcp-go（加密、XOR、FEC）、按需 flush —— sans-io 的 KCP 核心（移植自 fib），kcp-go 的 Reed–Solomon FEC（klauspost 矩阵），加密 none/xor/aes/aes-128/aes-192/aes-128-gcm；UDP listener 上的 `KcpServer` acceptor（按对端建会话、会话替换、`max_sessions`）、`dial`、在 I/O 线程回调的 `KcpHandler`，按 `next_flush` 驱动的共享定时线程；dead-link 关闭；与 kcp-go v5 双向互通，覆盖六种加密/FEC 组合，并经过每 7 个丢 1 个数据报的中继（`tools/interop/kcp/run.sh`）
- [x] `flash-ebpf`：`SO_REUSEPORT` 调度，按 CPU（`cpu % threads`）或确定性一致性哈希（Maglev，251 槽，按源 IP 或 IP+端口）；经典 BPF 无需特权，TCP/UDP 均可，有特权时用 eBPF（`SK_REUSEPORT` + sockarray）。`Accel::Ebpf(EbpfConfig)` 不可用时降级（`strict` 时报错），`Engine::accel_status()` 查询实际挂载情况。sockmap 转发（以 socket cookie 为键的 `SOCKHASH` + `sk_skb` verdict）：`Relay::splice`/`splice_conns` 在内核中转发两条 TCP 连接；默认要求 Linux 6.15+，因为 6.12 在 psock backlog 遇到 EAGAIN 会丢数据（已复现）。程序手工汇编、原始 `bpf(2)` 加载（不依赖 aya、不需要 nightly；见 ADR-006）。未完成：XDP 限速、I/O 线程绑定 CPU、flash-socks 接入 relay、eBPF 哈希层、eBPF 基准测试
- [x] 测试：eBPF 程序在特权 Docker 容器（eBPF 层、relay）与非特权容器（经典 BPF、降级路径）中运行，覆盖 epoll 与 io_uring；`FLASH_TEST_EXPECT_EBPF=1` 时跳过即失败。未完成：本地 VM 测试
- **交付**：`examples/h3`、`examples/kcp`、eBPF 加速 benchmark

### M6 DPDK + 生产化（6–8 周）
- [ ] `flash-dpdk`：EAL 初始化、mbuf 收发、用户态 TCP/IP 栈选型与集成（先 UDP，再 TCP）、与 Engine 线程组对接
- [x] 生产化：每个 I/O 线程的 relaxed 计数器（连接、字节、读写次数、UDP 数据报、发送队列字节、背压/过载、TLS 握手失败、循环迭代/事件/回调耗时、慢回调）及池统计，`Engine::metrics()` 输出 Prometheus 文本或 JSON；基于 `log` 门面的结构化日志（带键值，无 logger 时回退 stderr，`Config::log_level`）；运行时调试：由事件循环收集的连接表、慢回调环形缓冲、线程循环统计；flash-http 提供 `metrics_handler`、`HttpMetrics`（状态码分类、延迟直方图）、`access_log`、可用 token 保护的 `debug_handler`；`Engine::reload`/`Live` 热更新（空闲超时、慢回调阈值/钩子、队列上限、高水位、新增 `max_connections`、关闭超时、日志级别）。未完成：`tracing` feature、读缓冲/backlog/线程数/UDP 空闲超时的热更新、按路由的 HTTP 标签、在空闲机器上测量开销
- [x] 混沌测试：为引擎（`flash/tests/chaos.rs`）、fd 耗尽（`chaos_fd.rs`）、TLS（`chaos_tls.rs`）和 HTTP/WebSocket（`flash-http/tests/chaos.rs`）新增带种子、可复现的测试：RST 中断、半关闭、慢读与不读客户端、逻辑池饱和、EMFILE、负载下关闭；校验 `on_close` 恰好一次、无卡死、队列有界、无 fd 泄漏。默认只跑少量种子，`FLASH_CHAOS=1 FLASH_CHAOS_SECS=300` 进行浸泡（macOS、Linux epoll 与 io_uring 均无违规）。修复的 bug：EOF 截断未完成的有序响应；超限有序响应被静默丢弃；epoll 在 EMFILE 时空转；io_uring 漏掉数据之后的 RST；io_uring 可能复用仍被未提交 SQE 引用的 fd
- [ ] Prefork（可选）
- **交付**：长稳（≥72h）报告

### M7 重型协议（开放）
- [ ] 流媒体（RTMP/RTSP/SRT/FLV/HLS/WHIP/WHEP + hub）
- [ ] WebRTC（ICE/DTLS-SRTP/DataChannel/TURN）
- [ ] BitTorrent（metainfo/tracker/peer wire/uTP/DHT/MSE）
- 各自独立 crate、独立 README 与测试；视社区与精力并行推进。

### 1.0 稳定化
- [ ] API 审阅与冻结、semver 策略、弃用流程
- [ ] 全量 fuzz 语料与覆盖率报告、`cargo-audit/deny`、unsafe 审查清单 —— 模糊测试已完成：`fuzz/` cargo-fuzz 工程共 21 个目标（HTTP/1、HTTP/2 + HPACK、WebSocket、arpc、gRPC、SOCKS、mux、KCP、HTTP/3 + QPACK、cBPF），最小化语料约 2.6 MB 由 stable 单元测试回放，每个目标在 Linux 上约 14 分钟，提供 `fuzz/run-all.sh` 与 `fuzz/coverage.sh`。已修复：HTTP/2 流式请求被丢弃时的死锁、递归/非法 server push、gRPC `grpc-timeout` panic/溢出、KCP RTT 溢出、SOCKS 握手缓冲无上限。待完成：deny/audit、unsafe 审查
- [x] 文档站 + 迁移指南 + 架构文档：mdBook `book/en` 与 `book/zh-CN`（快速上手、核心概念、每个协议一章、配置参考、可观测性与热更新、性能调优、故障排查），由 `book/build.sh` 构建；所有代码片段来自 14 个可运行的 `guide-*` 示例；从 fib、tokio、hyper/axum 迁移的指南；带 Mermaid 图的 `docs/architecture.md`；各 crate 的 rustdoc 链接到对应章节；根目录 README。未完成：Pages 部署、在 Linux 上运行这些示例

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
