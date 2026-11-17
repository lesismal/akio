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
│  ├─ only-tls/               # 自研 TLS 1.3/1.2，sans-io（kTLS 已评估，未采用）
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
- [x] 慢回调检测（`Config::slow_callback_threshold`，默认 100 ms；`slow_hook` 或 stderr）。指标导出：已随 M6 的生产化条目完成（`Engine::metrics()` 输出 Prometheus 文本或 JSON，only-http 的 `metrics_handler`）
- [x] `only-uring`：multishot accept 与 recv、provided buffer ring、cooperative/deferred task-run + single-issuer 的 ring、eventfd 唤醒、内核探测（5.19+）并自动降级到 epoll（`UringConfig::strict` 可改为拒绝）。写路径走共享的“直接 `write` + 队列”逻辑，积压部分用 `poll(POLLOUT)`
- [x] only-uring 评估（2026-11-16）：测量了注册文件、SEND_ZC、MSG_RING 唤醒、注册 ring fd 与基于 ring 的发送，均未采用（规则：同一轮内 +3% 且不退步；Linux 7.0，Ryzen 7 7800X3D）。SEND_ZC 为 0.73–0.89 倍、每请求 CPU 多 10–36%（回环总是拷贝；需在真实网卡上重测）；MSG_RING（`IORING_REGISTER_SEND_MSG_RING`）在 spawn_blocking 往返上 −1.3% 到 +4.8%，其他场景为噪声；注册 ring fd −3.6% 到 +0.5%；注册文件无可节省之处（稳态下每请求不提交 SQE）。基于 ring 的发送（`IORING_OP_SEND`）在裸 ring 上 +1–4%、每请求 CPU 少 2–6%，但需要重新设计共用的写路径（写来自任意线程）；用户不在时的决定：不排期，作为低优先级后续项。见 docs/BENCHMARKS.zh-CN.md“io_uring 特性评估”；测量工具：only-uring 的 `eval_server` 测试、`tools/bench/uring-eval.sh`。
- [x] **每 listener 选择后端**：Engine 内多后端并存、线程组独立配置（已测试：同一 Engine 里 epoll + io_uring 两个 listener）；不支持的组合返回明确错误
- [x] UDP（服务端）：`Listener::udp`；每个 peer 地址一个 `Conn`，沿用普通 `Handler`（每个数据报一次 `on_data`，`send` 即发一个数据报，可在任意线程调用），空闲淘汰（`Config::udp_idle_timeout`），优雅关闭不等待排空，`spawn_blocking` 与 `close_after_send` 可用；Linux 上每线程一个 `SO_REUSEPORT` socket（同一 peer 固定在一个线程），其他系统单线程；Linux 上用 `recvmmsg` 批量收。已在 macOS 与 Linux 测试
- [x] UDP 客户端：`Engine::dial_udp`（配合 `EngineBuilder::udp_client_threads`，或使用某个 UDP listener 的线程）：每个拨出的连接有自己 `connect` 过的 socket，因此有独立本地端口；`on_open` 立即执行，每个数据报一次 `on_data`，支持空闲超时与 `close()`；收到 ICMP“端口不可达”会以 `ConnectionRefused` 结束连接。已测试：对 only UDP 服务端（30 个并发拨号 = 30 个不同 peer）、关闭的端口、不应答的服务端、跨线程发送
- [x] UDP 批量化（Linux）：服务端与拨号 socket 均用 `recvmmsg`；同一接收批次的回复跨 peer 用 `sendmmsg` 发出，同一 peer 的等长数据报合并为 UDP GSO（运行时探测，遇 EIO/EINVAL 永久回退，`ONLY_UDP_GSO=0` 可关闭）；新增 `Conn::send_segments`，only-quic 每次最多发送 10 个数据报；可选 GRO（`Config::udp_gro`）；`Config::udp_max_peers` 限制 peer 数并计数（`Engine::udp_stats`）。突发发送时每数据报服务端 CPU 降低 30–46%，64 B echo 约 +19%。未完成：无连接的 `DatagramsHandler`；io_uring UDP 经评估暂不值得（recvmmsg/sendmmsg 已按批处理）；真实网卡上的测量
- [x] `only-tls`：rustls 以 sans-io 方式通过 `Conn` 之下的 `Transport` 层驱动（服务端与客户端；`Tls::server` / `Tls::client` 包装任意 acceptor，handler 看到明文），握手在 IO 线程内完成，握手期间发送的应用数据先缓存，`close_after_send` 发送 close_notify，`tls_info`（ALPN、SNI、版本）。会话票据、SNI 证书选择、客户端认证、版本：通过 rustls 自己的配置。已在 epoll 与 io_uring 上测试：echo（3 MiB）、ALPN/SNI、明文垃圾数据与不受信证书的客户端、TLS 上的 `spawn_blocking` + 有序槽、only 拨 only
- [x] kTLS 评估（2026-11-16）：未采用。Linux 7.0 的软件 kTLS 在所有情形下都比 only-tls 自己的记录层慢（TLS 上的 HTTP/1.1，`tools/bench/ktls.sh`：1 KiB 为 0.83 倍，16 KiB 为 0.65 倍，256 KiB 为 0.40 倍，10 MB 文件用 `sendfile` 对比 pread + 加密为 0.48 倍；每字节服务器 CPU 为 1.3–2.5 倍；内核把每个 16 KiB 记录单独推给 TCP）。见 docs/BENCHMARKS.zh-CN.md“内核 TLS（kTLS）评估”。卸载代码保留在 only-tls 的 `experimental-ktls` feature 之后（测试流、ktls-bench、对 OpenSSL/Go 互通 107/107），未接入 `Tls` 或引擎；在支持 TLS 卸载的网卡上值得重测。客户端证书用 only-tls 自己的构建器配置（`client_cert`、`client_auth_required` / `client_auth_optional`）；TLS 1.3 early data 与 QUIC 0-RTT 一起在性能优化第二轮中跟进。
- [x] 测试：整套 engine/offload/stress 测试在 epoll 与 io_uring 上都跑（`ONLY_TEST_BACKEND=uring`，Linux CI 也跑）；跨后端混合 listener。另已完成：阻塞投递测试（IO 线程不被阻塞、完成回调在 IO 线程且带 handler 状态、池满、连接提前关闭、有序、槽丢弃、慢回调）
- **交付**：`examples/blocking-offload`（已完成）、后端对比 benchmark 报告（已完成：[BENCHMARKS.zh-CN.md](BENCHMARKS.zh-CN.md)）

> M2 状态：逻辑池与 io_uring 已完成；21 个 engine/offload/stress 测试在 Linux（内核 6.12，Docker）上两种后端都通过，重复运行无失败。**io_uring 与 epoll 对比（同一台 Docker 虚拟机，echo，64 B，客户端同机）：** 服务端 4 线程/256 连接时两者都被客户端限制（各约 80–100 万 req/s，无法排名）；服务端 1 线程/512 连接（受服务端限制）时 epoll 为 41.6 万和 49.2 万，io_uring 为 52.7 万和 53.8 万，io_uring 领先约 10–25%。最初的 io_uring 实现每收到一段数据都重新提交一次 `PROVIDE_BUFFERS`，只有 epoll 的约 60%；改用 buffer ring 归还缓冲（写内存而不是提交请求）后差距消失。数据来自与客户端共用 CPU 的虚拟机，只能作方向参考，不是正式 benchmark 报告。**M2 已完成。** benchmark 报告：[BENCHMARKS.zh-CN.md](BENCHMARKS.zh-CN.md)。概要：TCP echo 与 fib、tokio 同一量级（所有测过的负载都领先 fib；64 连接与 16 KiB 落后 tokio 约 15%，512 连接领先），该环境下 io_uring 并不比 epoll 快，逻辑池相对在 I/O 线程里阻塞约恢复 58 倍。

### M3 HTTP/1 + WebSocket（6–8 周）
- [x] `only-http` h1 服务端：`httparse` 解析请求头，自写增量 chunked 解码器（扩展、trailers、任意切分），流水线且按序应答（有序槽），keep-alive/`Connection: close`/HTTP/1.0，`Expect: 100-continue`，限制（头大小、body 大小、头数量），防请求走私（CL+TE、重复 CL），`Context` 支持 `detach()` 之后在任意线程完成应答，优雅关闭时让在途应答先完成。已在 epoll 与 io_uring 上测试
- [x] 流式：请求 body 通过 `Streaming(svc)` + `ctx.on_body`（分块、trailers、无大小限制），响应 body 通过 `ctx.stream_response`（chunked / 以关闭为界，排在更早的流水线响应之后）；文件 body 用 `sendfile(2)`（TLS 下经内存读取）；核心支持：`ResponseStream`、`Part::File`
- [x] h1 后续：HTTP/1 over TLS 测试（`tests/tls.rs`：keep-alive、pipelining、大请求体与 chunked、静态文件、WebSocket 升级）；路由参数在分发时只做一次百分号解码（`Context::param`），原始值可通过 `param_raw` 获取。静态文件：`If-Match`/`If-Unmodified-Since`（412）、按时间比较的 `If-Modified-Since`、`If-Range`，大文件缓存已打开的文件句柄和元数据（`max_open_files`）。多区间响应（`multipart/byteranges`，按请求顺序，合并重叠/相近区间，超过 32 个区间或合计超过 1 MiB 时忽略以防 DoS，支持 `If-Range`；用 curl 和 Python MIME 解析器在 HTTP/1.1 与 h2 上验证）；打开文件缓存的 CLOCK 淘汰，大小/修改时间/inode 变化及删除时失效
- [x] Router：静态 > `:param` > `*通配`，带回溯，405 与 `Allow`，HEAD 走 GET 路由，`nest`，每个 router 自己的 layer，自定义 fallback；重复/冲突路由在注册时 panic
- [x] Router 后续：查找过程零分配（参数位置内联存储，参数名与路由树共享），新增 `Router::lookup`/`RouteMatch`；`examples/router-bench.rs` 用 52 条 GitHub 风格路由测试：每次查找约 30 ns、0 次分配，旧实现约 130 ns、4.4 次。正则参数 `{id:[0-9]+}`（默认开启的 `regex` feature），另支持 `{id}`/`{*rest}`；优先级：静态 > 正则 > 普通参数 > 通配符，支持回溯。段内部分匹配 `/{name}.txt`、`/v{major:[0-9]+}.{minor}`（ADR-007：线性匹配，参数止于其后字面文本第一次出现处，段尾字面文本锚定在段尾；静态 > 部分段 > 正则 > 参数 > 通配）；router-bench 同次运行 A/B（gpu51，5 轮中位数）：普通路由表 29.1 → 27.5 ns，正则表 29.9 → 28.6 ns，部分段表 29.0 ns，均为 0 次分配
- [x] 中间件：recover、request id、CORS（预检）、访问日志
- [x] 中间件：响应时间、compress（gzip/deflate）、etag + 304、csrf（双重提交 cookie）、按 IP 的令牌桶限流。尚未提供 brotli（还没引入 brotli 依赖）
- [x] 静态文件（`files::Files`）：路径安全、MIME、ETag/Last-Modified/304、单段与多段 Range、index 文件、预压缩 `.br`/`.gz` 同名文件、带 stat 间隔的内存缓存、大文件用 `sendfile`。基于 inotify 的变更跟踪未做（用 stat 间隔代替）
- [x] `only-ws`：RFC 6455 + permessage-deflate（context takeover、服务端窗口位数）、`PreparedMessage` 广播、子协议、Origin 检查、关闭握手；Autobahn|Testsuite：核心 298 项 OK + 3 项 informational，permessage-deflate 216/216 OK，由 `tools/autobahn/run.sh` 在 CI 中运行。Autobahn 发现了 miniz_oxide 的一个 deflate bug（flate2 现改用 zlib-rs）
- [x] WebSocket 客户端（`only_ws::client::dial`/`connect`）：通过 `only::tls` 支持 `ws://`/`wss://`（SNI、自定义 rustls 配置），多地址回退，握手校验（key/accept、子协议、Origin、自定义头），握手与关闭超时，permessage-deflate 协商并遵从服务端选择，帧掩码、符合 RFC 的关闭握手、分片发送。Autobahn 客户端测试（`tools/autobahn/run.sh client`）：517 个用例 514 OK + 3 informational，no-context-takeover 补充轮 216/216；与 fib 的 Go websocket 服务端互通。系统根证书、HTTP 代理（`CONNECT`）、可选的握手重定向与引擎关闭时发送 1001 随后完成（ADR-010，见下）
- [x] HTTP/1 异步客户端（`client::Client`）：回调、`ResponseFuture`（`wait`、`wait_timeout`、`.await`）、按主机复用 keep-alive 连接（复用的连接已失效时重试一次）、chunked/以关闭为界的 body、通过 `only::tls` 支持 HTTPS、地址回退（先 ::1 再 127.0.0.1）。重定向、单请求超时与把 DNS 解析移出调用线程随后完成（ADR-010，见下）
- [x] 统一基准测试报告（`docs/BENCHMARKS.md`、`tools/bench`：Docker 镜像、wrk/h2load/echo-bench、10k/100k 连接内存、perf 剖析、与其他版本的 A/B；新增 hyper-ref，扩展 tokio-ref/fib-ref）：HTTP/1.1 plaintext/pipelined/JSON、h2c、TCP/UDP/TLS/WebSocket echo，对比 hyper、tokio、tokio-tungstenite、fib。优化：自研 HPACK Huffman 解码（h2c 29 万 → 187 万请求/秒，×6.4）、HTTP/1.1 热路径（plaintext +4–9%，pipelined +17%）、每连接内存（keep-alive 1.6 → 0.9 KB，WebSocket 2.1 → 1.7 KB）。pipelined HTTP/1.1（约 0.8×）与 h2c 仍落后于 fib；数据来自共享、噪声较大的主机
- **交付**：`examples/http`、`examples/ws-chat`

> M3 状态：**除对比报告外功能已完成**（报告移到 benchmark 阶段）：支持流式与 sendfile 的 h1 服务端、router、9 个中间件、静态文件、通过 Autobahn 全部用例的 only-ws（核心 298 项 + 3 项 informational，permessage-deflate 216/216）、h1 客户端。示例：`crates/only-http/examples/{hello,ws-chat,ws-echo}.rs`。

### M4 HTTP/2 + 多协议（8–10 周）
- [x] HTTP/2（`only-http`，与 HTTP/1 共用 `Service`/`Context`）：帧、流、双向流控、HPACK（`loona-hpack`）、h2c（先验与 `Upgrade`）、TLS ALPN `h2`、server push（`ctx.push`）、双向流式 body、GOAWAY 优雅关闭；h2spec strict 147/147（CI job `h2spec`）；curl 互通（先验、upgrade、POST）；`h2client::H2Client`（多路复用、流控、push、TLS）。顺带发现：rustls 单次写入明文超过 64 KiB 会失败，`only-tls` 现按记录大小分段加密
- [x] `only-mux`：首字节嗅探（TLS、HTTP/1、HTTP/2 preface、SOCKS4/5、前缀、自定义规则、fallback）；被选中的 acceptor 像自己 accept 的连接一样接管（回放已读字节、逻辑池回调、优雅关闭）
- [x] `only-arpc`：lesismal/arpc 线协议；双向调用、notify、带超时的异步调用、detach 后应答、stream、广播（共享同一帧）、客户端重连；中间件链（全局与按方法、前/后、中止）、coder（gzip 与值追加器，与 Go arpcex 的标志位相同）、客户端连接池（轮询 / 最少等待、重连、心跳）、等待应答的调用有上限（ADR-023）；与 fib 的 Go arpc 双向互通已验证，包括 coder、中间件可见的值与连接池（`tools/interop/arpc/run.sh`）
- [x] `only-grpc`：基于 only-http 的 HTTP/2，支持一元、服务端/客户端流与双向流（服务端可与普通 HTTP 共用端口），metadata 头与 trailers、trailers-only 错误、deadline（`grpc-timeout`）、拦截器、双向 gzip、消息大小限制、prost 辅助（feature `prost`）；客户端基于 `H2Client::open`（新增的流式请求 API）。与 grpc-go v1.85 双向互通已验证（`tools/interop/grpc/run.sh`）
- [x] `only-socks`：SOCKS5（无认证 / 用户名密码，IPv4/IPv6/域名在逻辑池中解析）、SOCKS4/4a、HTTP `CONNECT` 代理（通过 `Context::upgrade_raw`）；回调到回调的转发，双向背压（核心新增 `Conn::on_drain`；它暴露了一个在 loop 之外清空队列时丢失唤醒的问题，已修复）。2026-11-16 新增 SOCKS5 `BIND` 与 `UDP ASSOCIATE`（ADR-012，需显式开启：每个关联一个经 `Engine::bind_udp` 绑定的 UDP 转发 socket，丢弃分片，依赖端点的过滤，空闲超时；BIND 借助新增的 `Engine::adopt_tcp`），以及覆盖所有命令的访问控制钩子 `Socks::allow`；互操作 `tools/interop/socks/run.sh` 在 Debian arm64 Docker 中 12/12（curl 的 CONNECT/SOCKS4/4a/认证回归、PySocks 的 UDP ASSOCIATE、手写的 BIND 与 UDP 用例，同样的客户端也跑 Dante）。未做：UDP 分片重组、SOCKS4 BIND、GSSAPI、SOCKS 客户端、Linux `splice` 路径
- [x] 测试：与 curl（h2 先验、h2c upgrade）、h2spec、grpc-go、fib 的 Go arpc 互通。未测：nghttp2 工具、tonic
- **交付**：`examples/grpc`、`examples/proxy`（对应 `crates/only-grpc/examples/grpc-interop.rs` 与 `crates/only-socks` 的测试）

> M4 状态：**已完成。** HTTP/2（h2spec 147/147）、only-mux、only-socks、only-arpc（与 Go 互通）、only-grpc（与 grpc-go 互通）。

### M5 QUIC/H3 + KCP + eBPF（8–10 周）
- [x] `only-quic`/`only-h3`：基于 sans-io QUIC 核心（quinn-proto/quiche 评估后定），QPACK，WebSocket over H3；与 curl/quiche 互通 —— 选定 quinn-proto 0.11。`only-quic`：每个 UDP listener 一个 `quinn_proto::Endpoint`（按连接 ID 路由，支持连接迁移），`QuicServer` acceptor 与 `dial`，`QuicHandler` 回调（流、reset、stop-sending、datagram、关闭）每连接串行执行，非阻塞写入（按流排队、`Writable` 时续写），共享定时线程，rustls（ring）配置辅助函数。`only-h3`：HTTP/3 帧、QPACK（静态表 + 字面量，动态表容量为 0，支持 Huffman 解码）、控制流/QPACK 流及其错误规则；通过新增的 `only_http::transport` 钩子在 H3 上运行任意 `only_http::Service`（同一个 `Context`，含 `detach`、`stream_response`、trailers），body/字段段限制（413/431），`H3Client`。与 quic-go v0.62 及 fib 自身的 QUIC/HTTP/3 双向互通（`tools/interop/h3/run.sh`）。未完成：curl/quiche 互通（手头没有支持 HTTP/3 的构建）、H3 上的 WebSocket（扩展 CONNECT）、QPACK 动态表、服务器推送、流式请求体（除服务器推送外后来均已完成：Docker 中的 libcurl/ngtcp2/OpenSSL，以及下方 2026-11-16 条目，ADR-011）
- [x] `only-kcp`：兼容 skywind3000/kcp 与 kcp-go（加密、XOR、FEC）、按需 flush —— sans-io 的 KCP 核心（移植自 fib），kcp-go 的 Reed–Solomon FEC（klauspost 矩阵），加密 none/xor/aes/aes-128/aes-192/aes-128-gcm；UDP listener 上的 `KcpServer` acceptor（按对端建会话、会话替换、`max_sessions`）、`dial`、在 I/O 线程回调的 `KcpHandler`，按 `next_flush` 驱动的共享定时线程；dead-link 关闭；与 kcp-go v5 双向互通，覆盖六种加密/FEC 组合，并经过每 7 个丢 1 个数据报的中继（`tools/interop/kcp/run.sh`）
- [x] `only-ebpf`：`SO_REUSEPORT` 调度，按 CPU（`cpu % threads`）或确定性一致性哈希（Maglev，251 槽，按源 IP 或 IP+端口）；经典 BPF 无需特权，TCP/UDP 均可，有特权时用 eBPF（`SK_REUSEPORT` + sockarray）。`Accel::Ebpf(EbpfConfig)` 不可用时降级（`strict` 时报错），`Engine::accel_status()` 查询实际挂载情况。sockmap 转发（以 socket cookie 为键的 `SOCKHASH` + `sk_skb` verdict）：`Relay::splice`/`splice_conns` 在内核中转发两条 TCP 连接；默认要求 Linux 6.15+，因为 6.12 在 psock backlog 遇到 EAGAIN 会丢数据（已复现）。程序手工汇编、原始 `bpf(2)` 加载（不依赖 aya、不需要 nightly；见 ADR-006）。未完成：XDP 限速、I/O 线程绑定 CPU、only-socks 接入 relay、eBPF 哈希层、eBPF 基准测试
- [x] 测试：eBPF 程序在特权 Docker 容器（eBPF 层、relay）与非特权容器（经典 BPF、降级路径）中运行，覆盖 epoll 与 io_uring；`ONLY_TEST_EXPECT_EBPF=1` 时跳过即失败。未完成：本地 VM 测试
- **交付**：`examples/h3`、`examples/kcp`、eBPF 加速 benchmark

### M6 DPDK + 生产化（6–8 周）
- [x] `only-dpdk`（实验性）：在 only I/O 线程上运行 smoltcp 用户态 TCP/IP 协议栈；按 `EalConfig` 初始化 EAL，每个 rx/tx 队列一个线程，经 C shim 批量收发 mbuf，RSS 并扇出 ARP；另支持 TAP、AF_PACKET 与内存链路。`Backend::Dpdk(DpdkConfig)` 位于 `dpdk`/`dpdk-pmd` feature 之后；支持 UDP/TCP listener 与 `dial`/`dial_udp`；only-kcp 无需修改即可运行。已在 Docker 中与 Linux 内核协议栈互测（DPDK `net_tap` 单/双队列、TAP、veth 上的 AF_PACKET）；重型 CI 任务 `dpdk`。未完成：IPv6、IP 分片与卸载、多队列拨号、SACK/拥塞控制、真实网卡基准（IP 分片、多队列拨号、SACK 与拥塞控制已随自研协议栈完成，见下文第 A 波）
- [x] 生产化：每个 I/O 线程的 relaxed 计数器（连接、字节、读写次数、UDP 数据报、发送队列字节、背压/过载、TLS 握手失败、循环迭代/事件/回调耗时、慢回调）及池统计，`Engine::metrics()` 输出 Prometheus 文本或 JSON；基于 `log` 门面的结构化日志（带键值，无 logger 时回退 stderr，`Config::log_level`）；运行时调试：由事件循环收集的连接表、慢回调环形缓冲、线程循环统计；only-http 提供 `metrics_handler`、`HttpMetrics`（状态码分类、延迟直方图）、`access_log`、可用 token 保护的 `debug_handler`；`Engine::reload`/`Live` 热更新（空闲超时、慢回调阈值/钩子、队列上限、高水位、新增 `max_connections`、关闭超时、日志级别）。未完成：`tracing` feature、读缓冲/backlog/线程数/UDP 空闲超时的热更新、按路由的 HTTP 标签。已在空闲机器上测量开销（2026-11-16，同一轮 A/B，docs/BENCHMARKS.zh-CN.md“遥测开销”）：关闭回调计时或把计数器编译掉后 HTTP/1.1 plaintext/pipelined 为 0.998–1.006×，即无可测开销；echo 在 ±5–10% 的噪声之内
- [x] 可插拔的指标收集器（ADR-015，2026-11-16）：`only::metrics`（`Collector`、可输出 Prometheus/JSON 的 `Families`、`Counter`/`Gauge`/`Histogram`/`Registry`、`fn_collector`），`Telemetry::register_collector`/`collect`/`render_prometheus`，由 `metrics_handler` 输出；`HttpMetrics`（另加按 HTTP 版本的请求数，即 h2/h3 的流数）、`QuicServer`（连接、数据报、字节、发送/丢失的包、拥塞）与 `Tls::stats()`（按版本/角色的握手、会话恢复、早期数据）的收集器。未完成：推送导出（StatsD/OTLP）、按路由的 HTTP 标签、请求数之外的 h2 连接/流 gauge
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
- [x] 全量 fuzz 语料与覆盖率报告、`cargo-audit/deny`、unsafe 审查清单。模糊测试：`fuzz/` cargo-fuzz 工程 21 个目标（HTTP/1、HTTP/2 + HPACK、WebSocket、arpc、gRPC、SOCKS、mux、KCP、HTTP/3 + QPACK、cBPF），最小化语料约 2.6 MB 由 stable 单元测试回放，每个目标在 Linux 上约 14 分钟，每夜 CI 任务；修复 HTTP/2 死锁、递归 server push、gRPC `grpc-timeout` panic/溢出、KCP RTT 溢出、SOCKS 缓冲无上限。供应链：`deny.toml` + `.cargo/audit.toml`，`cargo deny`/`cargo audit` 通过并作为 CI 门禁（一个仅开发依赖的通告带理由忽略，直到 MSRV 1.88）。unsafe：仅限 only-sys、only-uring、only-ebpf，其余 crate 全部 `forbid(unsafe_code)`，缺少安全注释即报错，CI 运行清单 `--check`（`docs/unsafe-review.md`、`SECURITY.md`）；修复 12 个问题（含 `RecvBatch` 堆溢出、io_uring 缓冲区别名及在途操作未结束即释放、bpf(2) 键/值大小未校验）。Miri 扩展到协议 crate，在 zlib-rs 0.6.8 中发现 UB（待向上游报告）。ASan（含 LSan）与 TSan：2026-11-16 首次运行，在 Linux arm64 Docker 中覆盖整个工作区（epoll 与 io_uring），在 x86_64 上覆盖含 unsafe 的 crate 与引擎后端，未报告内存错误、内存泄漏或数据竞争；修复一处 TSan 线程泄漏（only-bittorrent 的 `Client::close` 不等待其线程），并由此修复 only-http 客户端在引擎优雅关闭期间保持空闲 keep-alive 连接的问题（导致等待 10 秒）；`tools/sanitizers/run.sh`（重型 CI 任务也使用它，现覆盖整个工作区）解决了 aarch64 上 `-Zbuild-std` 时 sanitizer 无法启动的问题；调整了两个在 TSan 下挂起或超时的测试
- [x] CI 加固与覆盖率：严格 lint 集（`missing_docs` deny、`unreachable_pub`、库代码 `unwrap_used`、精选 pedantic/nursery），rustdoc `-D warnings`；矩阵：Linux x86_64/arm64 × epoll/io_uring、macOS（尽力而为）、MSRV 1.85、cargo-hack 特性组合、Miri、loom、Autobahn（服务端+客户端）、h2spec、文档书构建与 Pages 部署、重任务（Go 互通、每夜 fuzz）；统一的 `ci-ok` 门禁。覆盖率任务（cargo-llvm-cov，两种后端合并）：行覆盖率 85.9% → 91.6%，每个 crate ≥ 85%。顺带修复：only-quic 在方向错误的流上 panic、15 处持锁调用回调、`--no-default-features` 测试编译、两处测试竞态。尚未在 GitHub 上实际运行验证（Pages 设置、fib 检出、Codecov）
- [x] 文档站 + 迁移指南 + 架构文档：mdBook `book/en` 与 `book/zh-CN`（快速上手、核心概念、每个协议一章、配置参考、可观测性与热更新、性能调优、故障排查），由 `book/build.sh` 构建；所有代码片段来自 14 个可运行的 `guide-*` 示例；从 fib、tokio、hyper/axum 迁移的指南；带 Mermaid 图的 `docs/architecture.md`；各 crate 的 rustdoc 链接到对应章节；根目录 README。未完成：Pages 部署、在 Linux 上运行这些示例

### 1.0.0 发布决定（2026-11-14）
- [x] 项目更名为 **only**：crate 改为 `only`、`only-core`、`only-http` 等（crates.io 上 `flash` 已被占用），涉及代码、文档、手册、工具与 CI：目录与包名 `crates/only-*`、代码路径 `only_*`、环境变量 `ONLY_*`、指标 `only_*`、日志 target 与线程名 `only*`、快照 `api/only-*.txt`、Docker 镜像、两本手册与全部文档；GitHub 仓库已改名为 `lesismal/only`（Pages 为 `lesismal.github.io/only`）；对照表见 CHANGELOG
- [x] 将尚未 1.0 的公开依赖（rustls、quinn-proto、prost、str0m）封装在项目自己的类型之后，原始访问只在 `unstable` feature 中提供，使升级它们不再是破坏性变更：`tls::{ServerConfig, ClientConfig}` 构建器（PEM/DER 证书与私钥、按 SNI 选证书、ALPN、客户端认证、会话缓存与票据、根证书、仅测试用的跳过验证）与 `tls::Error`，供 TLS、HTTP/HTTP-2 客户端、WebSocket 客户端、QUIC 与 HTTP/3 使用；自有 QUIC `ServerConfig` / `ClientConfig` / `TransportConfig`、`StreamId` / `Dir` / `Side`、`ConnectionError`、`ConnectionStats`；gRPC 的 `codec::Message` trait，prost 适配器在 `prost` feature 之后（不在 semver 内）；自有 WebRTC id、媒体、事件、候选、`RtcConfig` 与 `SdpChanges`，`Peer::with_rtc` 移到 `unstable` 之后；API 快照中不再含 rustls/quinn/prost/str0m 类型；迁移表见 CHANGELOG
- 回调名保持各协议自己的术语（QUIC 的 `on_connected`、WebSocket 的 `on_open` 等）

### 长期目标：去掉所有三方依赖
- [x] 逐个自研库中用到的所有三方依赖，每一项保持相同的公开 API（API 快照不变），以已知答案测试向量、互通与模糊测试作为门禁。顺序（每一波依赖前一波）：
  - [x] 第 A 波：`only-crypto`（SHA-1/2、MD5、HMAC、HKDF、PBKDF2、CRC32、AES、CTR、GCM、ChaCha20-Poly1305、base64、系统随机数）替代 sha1/sha2/md-5/hmac/pbkdf2/aes/aes-gcm/ctr/crc32fast/base64/getrandom（已完成：AES 使用 AES-NI / ARMv8 AES，并有常数时间 fixsliced 回退，ctmul64 GHASH，NIST CAVP / RFC / Wycheproof 向量，与旧 crate 的差分测试和模糊测试目标；only-kcp、-turn、-ws、-http、-media、-bittorrent 与 -webrtc 已迁移，线上格式经证明不变；后续：SHA-NI / ARMv8 SHA、PMULL / PCLMULQDQ GHASH 与 CRC32 指令，因为可移植的 SHA-1 约为旧 crate 加速速度的一半，CRC-32 只有其一小部分）；自研 HTTP/1 解析、HPACK 与正则引擎替代 httparse/loona-hpack/regex；自研 deflate/zlib/gzip 替代 flate2；自研用户态 TCP/IP 栈替代 smoltcp；自研 protobuf 运行时替代 prost
    - [x] protobuf：`only-protobuf`（运行时：线格式、消息、开放枚举、未知字段、well-known 类型；无依赖）与 `only-protobuf-build`（自研 `.proto` 解析器与供 `build.rs` 使用的代码生成器，不需要 protoc / syn / quote；生成 only-grpc 服务桩代码）。用 protoc 生成的黄金编码、与 prost 的差分测试和 fuzz 目标 `protobuf_diff`、与 grpc-go 自带 route_guide / helloworld 生成代码的互通（`tools/interop/grpc/run.sh`）做了验证。only-grpc 的 `prost` feature 已弃用（保留，不在 semver 内）。未做：group、extension、edition、JSON 映射、反射
    - [x] HTTP 编解码：`only_ws::http1`（零拷贝、增量、按 RFC 9110/9112 严格校验的头部解析器；安全代码中按字扫描，速度与 httparse 相当）、`only_http::hpack`（编码器与解码器都带动态表，双向 Huffman，大小更新，never-indexed 字段，解码时即应用列表大小限制；RFC 7541 附录 C 向量）、`only_http::re`（路由约束用的线性时间 Thompson NFA，小模式用位并行，其余用 Pike VM）；httparse/loona-hpack/regex 已从库中移除（仅 `fuzz/` 的差分目标与 `tools/codec-bench` 保留）；h2spec 147/147，`regex` feature 变为空操作
    - [x] 自研用户态 TCP/IP 协议栈替代 smoltcp（`only-dpdk/src/net`，`#![forbid(unsafe_code)]`，无依赖）：以太网、带待发队列的 ARP（首个 SYN 不再丢失）、IPv4 分片/重组、ICMP（回显，不可达交付给已拨出的 UDP 连接）、UDP，以及遵循 RFC 9293 的 TCP：RFC 6298 RTO、SACK + RFC 6675 恢复、NewReno 与 CUBIC、窗口缩放 + 时间戳/PAWS、延迟 ACK、keepalive、TIME-WAIT、RFC 5961、SYN cookie；事件驱动的循环与定时器堆；多队列拨号；TAP/AF_PACKET 不再依赖 smoltcp 的 phy。模拟丢包链路测试、Docker 中与内核互测（netem 丢包、窗口缩放、500 条连接），7 个模糊测试目标。未完成：IPv6/NDP、卸载、pacing/ECN
    - [x] Deflate：`only-deflate`（纯安全 Rust，无依赖）替代 only-ws、only-http、only-grpc 中的 flate2/zlib-rs：raw DEFLATE、zlib 与 gzip 的流式解压（任意拆分输入、有界输出、窗口 2^8..2^15、与 zlib 相同的编码检查）与压缩（哈希链、惰性匹配、zlib 级别、限长动态 Huffman、固定或存储块、同步/完全刷新、窗口 2^8..2^15，因此 permessage-deflate 现在也支持 8 位窗口）。与 zlib-rs 和 `gzip(1)` 双向互通、与 zlib-rs 差分模糊测试、Autobahn permessage-deflate 服务端与客户端用例、与 grpc-go 的 gRPC gzip 互通、Miri（zlib-rs 的别名问题随之消失，only-grpc 的 gzip 测试重新在 Miri 下运行）。级别 1/6/9 的压缩率与 zlib-rs 相当或更好；解压吞吐为 zlib-rs 的 0.75-0.85 倍，压缩为 0.25-0.6 倍（无 SIMD、无 `unsafe`）；permessage-deflate 回显吞吐（仅压缩部分）在 64 B 消息时为 zlib-rs 的 1.2 倍，0.5-64 KiB 时为 0.5-0.7 倍
  - [x] 第 B 波：公钥密码学（X25519、P-256 ECDH/ECDSA、Ed25519、RSA PKCS#1/PSS 验签）与 ASN.1/X.509；自研日志门面替代 `log`（可选 `log` 桥接）；自研系统调用与 io_uring 绑定替代 libc/io-uring
    - [x] 日志门面：`only-log`（无依赖，`#![forbid(unsafe_code)]`，以 `only::log` 重新导出）：级别、target、沿用 `log` 宏语法的结构化键值对、原子全局最大级别（禁用语句 0.25-0.29 ns，`log` 为 0.36）、`Logger` / `set_logger` / `set_boxed_logger`、内置 `FmtLogger`（`only::log::init`）与 `StderrLogger`，保留 stderr 兜底。所有 crate 已迁移，`log` 退出库的依赖；target 与键名不变。可选 `log` feature（不在 semver 内）：未安装 only-log logger 时记录转发给 `log` 的 logger，`bridge::route_log_to_only` 反向接入。破坏性变更：`Config::log_level` / `Telemetry::set_log_level` 改用 `only::log::LevelFilter`。2026-11-16 新增（ADR-012）：带 env_logger 风格指令的 `Filter` 与需显式调用的 `init_from_env`（`ONLY_LOG=info,only_http=debug`，只解析一次），`max_level_*` / `release_max_level_*` feature（`STATIC_MAX_LEVEL`，语句被编译掉）；禁用语句开销不变（gpu51 上同轮 A/B：禁用 `trace!` 0.400 → 0.401 ns，`log_enabled!` 0.402 → 0.401，启用的 `info!` 4.250 → 4.251；macOS 上基准二进制逐字节相同；开启 `max_level_info` 后该语句消失）。未完成：`/regex` 消息过滤、`tracing` span
    - [x] 系统调用与 io_uring 绑定：`only_sys::ffi`（自有 C 类型、常量、带编译期布局断言的 `#[repr(C)]` 结构体，Linux 上 C 库与 macOS 上 libSystem 函数的 `extern "C"` 声明；`bpf`/`io_uring_*` 经 `syscall(2)` 按架构区分调用号；errno/EINTR 语义不变）与 `only-uring` 的 `ring`（setup/enter/register、按内核内存序访问的 mmap SQ/CQ ring、SQE 构造、CQE 标志、probe 与特性检查、SQPOLL）；only-ebpf 与 only-dpdk 已迁移；`libc`/`io-uring` 已从各库移除（`libc` 仍是 dev-dependency：在 macOS aarch64、Linux aarch64 与 x86_64 上将每个布局与常量与之对比）。未做：裸 `asm!` 系统调用（C 库仍经 `std` 链接）、musl 专门的布局测试
    - [x] 公钥密码学与 X.509：`only-crypto` 新增 X25519、Ed25519、P-256/P-384 的 ECDH 与 ECDSA（RFC 6979）、RSA PKCS#1 v1.5/PSS 签名与验证（2048–8192 位，CRT + 盲化）、严格 DER/PEM 以及 PKCS#8/SEC1/PKCS#1/SPKI 密钥（`pkey`）；新的 `only-x509` 解析证书、构建并校验证书链（有效期、CA/pathLen、KU/EKU、名称约束、RFC 6125 名称匹配），并能生成自签名 / CA 签发的证书。常数时间域运算、完备公式、全表查表；Wycheproof/RFC 向量，与 ring/RustCrypto/rcgen/rustls-webpki 交叉验证，真实与 OpenSSL 证书链，模糊测试目标 `x509_parse` 与 `crypto_sig_verify`。相对 ring 的速度：Ed25519/X25519 0.7–0.85 倍，P-256 约 0.3 倍（ring 用汇编），P-384 0.8–2 倍，RSA-2048 约 0.4 倍。后续：专用 P-256 域（Solinas/fiat）、wNAF 验签、RSA 密钥生成、CRL/OCSP
  - [x] 第 C 波：自研 TLS 1.2/1.3 与 DTLS 替代 rustls（及 ring）
    - [x] DTLS：`only-dtls`（sans-io，`#![forbid(unsafe_code)]`，只依赖 only-crypto / only-x509）：DTLS 1.2（RFC 6347）客户端与服务端，包括 epoch、48 位序列号与 64 条记录的防重放窗口，按路径 MTU 分片/重组握手消息，按指数退避重传 flight（对端重发上一 flight 时也重传），无状态的 HMAC HelloVerifyRequest cookie（也以独立的 `HelloVerifier` 提供给监听方），ECDHE（X25519、P-256、P-384）配合 ECDSA/Ed25519/RSA(-PSS) 与 AES-128/256-GCM 或 ChaCha20-Poly1305，扩展主密钥（默认必需），拒绝重协商，双向认证（指纹固定或回调），`use_srtp`（AEAD-AES-128/256-GCM、AES-CM-HMAC-SHA1-80/32）并在连接建立时给出 SRTP 密钥，RFC 5705 导出器，close_notify/告警；定时器由 `poll_timeout` / `handle_timeout` 驱动。测试：MTU 256 下模拟丢包（25%）、重复、乱序链路，负面用例（指纹、重放、cookie、超时、告警）；与 OpenSSL 3.5 / 4.1 `s_client`/`s_server -dtls1_2`（`-use_srtp`，导出的密钥材料逐字节一致）和 pion/dtls v3 双向互通（`tools/interop/dtls/run.sh`），并在内存中与 str0m 的 `dimpl` 互通；fuzz 目标 `dtls_record` 与 `dtls_handshake`。在第 D 波 WebRTC 协议栈采用它之前属于内部层级。未完成：DTLS 1.3（RFC 9147）及其 ACK、连接 ID（RFC 9146）、会话恢复、PSK
    - [x] TLS 1.2/1.3：`only-tls` 在 API 不变的前提下运行自研 TLS（`#![forbid(unsafe_code)]`，基于 only-crypto / only-x509，无依赖）：TLS 1.3（HRR、KeyUpdate、票据 + PSK 恢复、客户端证书、兼容模式、拒绝 0-RTT）与 TLS 1.2（仅 ECDHE + AEAD、EMS、拒绝重协商、会话 ID 与票据），三个 TLS 1.3 与六个 TLS 1.2 AEAD 套件，X25519/P-256/P-384，ECDSA/Ed25519/RSA 证书由 only-x509 验证。为 QUIC 提供不经记录层的 TLS 1.3 内核（`only_tls::quic`，内部：按级别的握手字节与密钥、传输参数、RFC 9001 密钥辅助函数）。RFC 8448 跟踪向量、内存矩阵测试、OpenSSL/Go/curl 互通（`tools/interop/tls/run.sh`，107 个用例）与 gRPC 的 TLS 一环，fuzz 目标 `tls_server`/`tls_client`/`tls_record`。握手约为 rustls+ring 的 0.7 倍，大块吞吐约 0.45 倍（GHASH 为可移植实现；P-256/X25519 慢于 ring）。tlsfuzzer：33 个适用脚本（985 个探测，5 个已知失败记录在 `tools/interop/tls/tlsfuzzer.sh` 中）。未完成：BoGo 测试运行器（rustls 已在第 D 波随 quinn-proto 一起从 only-quic 移除）；0-RTT、record_size_limit、证书压缩与 OCSP stapling 后来完成（见下文）
  - [x] 第 D 波：自研 QUIC 替代 quinn-proto（及 bytes）；自研 WebRTC 栈（ICE、DTLS-SRTP、SCTP、RTP/RTCP）替代 str0m/dimpl/p256
    - [x] QUIC：`only-quic` 在 API 不变的前提下运行自研 QUIC v1（RFC 9000/9001/9002 + RFC 9221 数据报；sans-io 核心，`#![forbid(unsafe_code)]`，基于 `only_tls::quic` 与 only-crypto，无依赖），以 `only_quic::Bytes` 替代 `bytes::Bytes`（唯一的签名变化，迁移说明见 CHANGELOG）；quinn-proto、rustls/ring 与 bytes 已从 only-quic 和 only-h3 移除。长/短包头、三个包号空间、AES/ChaCha20 包头保护、AEAD、合并与填充、版本协商、Retry（完整性标签、令牌）与 NEW_TOKEN、无状态重置、密钥更新、RFC 9000 全部帧与 DATAGRAM、流级/连接级流量控制与流数量上限、RFC 9002 丢包恢复（RTT、包序/时间阈值、PTO、持续拥塞、NewReno、CUBIC、pacing、3 倍放大限制）、空闲超时、保活、探测到 1452 的 DPLPMTUD、由 endpoint 路由的连接 ID、经路径验证的迁移、会话恢复；GSO 批量发送，回调中的写入先攒后发。测试：RFC 9001 附录 A 向量、单元测试、模拟丢包/乱序/重复链路（握手、大块传输、多流、迁移、密钥更新、Retry、重置、超时）；互通：与 quic-go 的原生 QUIC 双向回显，含 Retry、密钥更新与 150 MB（新增 `tools/interop/quic/run.sh`），与 quic-go、fib 的 HTTP/3 双向互通，Docker 中 ngtcp2（libcurl-gnutls）与 OpenSSL 3.5 QUIC（curl、`s_client -quic`）客户端（`tools/interop/quic/docker.sh`）；fuzz 目标 `quic_packet`/`quic_frame`/`quic_conn`。与 quinn-proto 版本相比（Ryzen 7 7800X3D，回环）：握手约 1.0 倍，单流大块吞吐约 0.72 倍（3.1-3.6 对 4.6-4.7 Gbit/s），HTTP/3 每秒请求数约 2.9 倍（17.1 万对 5.8 万）。 未完成：0-RTT、ECN 标记、客户端主动迁移、preferred_address、BBR（`Congestion::Bbr` 实际运行 CUBIC）、QUIC v2，以及以 quiche 和 ngtcp2/quiche 服务端为对端的互通
    - [x] WebRTC：`only-webrtc` 在 API 不变的前提下运行自研 sans-io 协议栈，没有第三方依赖（str0m、dimpl、p256 与 RustCrypto crate 均已移除）：新的内部 crate `only-ice`（RFC 8445 完整与 lite agent、prflx、常规提名、角色冲突、consent freshness、trickle、重启）、`only-srtp`（RFC 3711 / RFC 7714，AES-CM-HMAC-SHA1-80/32、AEAD-AES-128/256-GCM）、`only-rtp`（RTP/RTCP、NACK + RTX、PLI/FIR、REMB、TWCC 与带宽估计、Opus/G.711/G.722/VP8/VP9/H.264/H.265/AV1 载荷格式、组帧器）和 `only-sctp`（基于 DTLS 的 SCTP，拥塞控制、PR-SCTP、流重置、DCEP），以及 `only-webrtc` 中基于 `only-dtls` 的 SDP offer/answer 与重新协商。测试：RFC 5769 / 3711 / 7714 向量、与 pion 逐字节比对、各层及端到端的模拟丢包链路；与 pion（DC + Opus/VP8 回显 + PLI 双向、TURN 中继）、fib 双向和无头 Chrome 双向互通（`tools/interop/webrtc/run.sh`、`browser.sh`）；fuzz 目标 `ice_stun`、`srtp_unprotect`、`rtp_rtcp`、`rtp_codec`、`sctp_packet`、`webrtc_sdp`。未完成：为 `Endpoint` 提供 relay 候选的 TURN 客户端、simulcast 发送、FEC、RTCP XR、I-DATA、DTLS 1.3、only-media 中 WHIP/WHEP 的媒体接入
  - 仅测试用的工具（loom、rcgen 等）最后替换，或保留
  - 用户不在时做出的决定（2026-11-16，之后再审阅）：库已不再有必需的三方依赖。三个可选或仅测试用的依赖有意保留：`loom`（only-core 的模型检查测试，正常构建不会用到）、only-grpc 已弃用的 `prost` 特性（与现有 prost 消息互通）、only-log 的可选 `log` 桥接（与 `log` 生态互通）。去掉它们只会去掉这些桥接，而不是库本身的依赖。

### 性能优化阶段（第 D 波之后；完成后再考虑发布 1.0.0）
- [x] `only-crypto` CPU 指令加速：SHA-NI / ARMv8 SHA、PMULL / PCLMULQDQ GHASH、CRC32 指令（TLS 大块传输与 BitTorrent 哈希），更快的 P-256（专用域运算）与 RSA（乘法），X25519（已完成：运行时检测的 AES-NI / ARMv8 AES CTR 一次 8 个分组，PCLMULQDQ / PMULL GHASH 与 CTR 单趟融合的 AES-GCM，SHA-NI / ARMv8 SHA，PCLMULQDQ 折叠 / SSE4.2 / ARMv8 CRC32，AVX2 ChaCha20，44 位 limb 的 Poly1305，P-256 专用约简 + 求逆加法链 + 有符号仿射梳形表 + Jacobian wNAF 验签，Ed25519 wNAF 验签，Curve25519 专用平方，带专用平方的定长 RSA Montgomery；unsafe 仅限五个 `hw` 模块，`ONLY_CRYPTO_PORTABLE=1` 强制使用可移植实现。在 Ryzen 7800X3D 上：SHA-1/SHA-256 达到 RustCrypto 的速度（3.6 倍 / 6.5 倍），AES-128-GCM 6.5 GB/s（17.8 倍，TLS 16 KiB 记录为 rustls+ring 的 0.64 倍），CRC-32 7 倍，P-256 验签 1.67 倍 / 签名 1.46 倍，TLS 1.3 握手 1.5 倍（rustls+ring 的 0.60 倍）；见 docs/BENCHMARKS.zh-CN.md。未完成：VAES/VPCLMULQDQ 内核（intrinsic 比 MSRV 新）、SIMD Poly1305、更便宜的 P-256 秘密标量倍点、RSA Karatsuba）
- [x] `only-deflate` 匹配器提速（4 字节哈希、medium 策略），缩小与 zlib-rs 0.25–0.6 倍的差距：采用 zlib-ng 的级别表与 quick/fast/medium/slow 策略（级别 9 用 3 字节哈希与跳链搜索）、每次比较 8 字节、不保留上下文时的廉价重置；解码器快速路径（64 位补充比特、每次补充解码三个字面量或一个长度/距离对、分块复制匹配）。仍为不用 SIMD 的安全 Rust。在 x86-64 上与 flate2/zlib-rs 相比：各级别输出最多大 0.5%（45 组级别 × 语料中 36 组完全相同），压缩 0.94–1.48 倍，解压 0.82–1.23 倍（存储块 0.42 倍），permessage-deflate 回显在 64 B / 512 B / 4 KiB / 64 KiB 时为 1.84 / 1.04 / 1.00 / 0.98 倍（见 docs/BENCHMARKS.zh-CN.md）。级别 1 现在与 zlib-ng 一样以压缩率换速度（输出比之前最多大 40%）。未完成：存储块仍经过窗口（复制两次）
- [x] 自研替换完成后重新剖析 TLS / QUIC / HTTP 热路径；h2 与 pipelined HTTP/1 对比 fib（Ryzen 7800X3D）：
  - HTTP：h2 帧原地解析、HPACK 平铺缓冲、每次读只写一次（一个 TLS 记录）、接收窗口按四分之一归还；HTTP/1 请求头先用小存储解析。h2c 228 万 → 405 万请求/秒（fib 的 1.25 倍，原 0.70 倍），TLS 上的 h2 158 万 → 403 万（fib 的 1.33 倍，原 0.52 倍），HTTP/1.1 流水线 +7%（fib 的 1.14–1.17 倍）；h2spec 147/147。
  - QUIC：pacer 改用测得的 RTT 并整批补满令牌，不再逐包唤醒。单流大块 3.4–3.7 → 5.7–5.8 Gbit/s（quinn-proto 的 1.25 倍，原 0.72 倍），HTTP/3 每秒请求 17.1 万 → 41.5–42.6 万。
  - TLS：完整记录直接解密进调用方缓冲区（+5–7%；16 KiB 为 rustls+ring 的 0.64–0.69 倍，其余差距在 AES-GCM 内核）；握手 98% 以上为曲线运算（0.61 / 0.45 倍）。新增 `only-tls/examples/tls-bench.rs`。
  - 未完成：VAES GCM、recvmmsg 接收复制、默认 GRO 与 QUIC 按批 ACK、受内核限制的 keep-alive HTTP/1。
- [x] 在空闲机器（DPDK 用真实网卡）上重跑基准并更新 `docs/BENCHMARKS.md`：在安静的 Ryzen 7800X3D 主机上基于同一提交 10070cff 重跑，并重写中英文 BENCHMARKS（先写主机与方法，写明局限）。HTTP/1.1、h2c、TLS 上的 h2、WebSocket、TCP/UDP/TLS echo 与每连接内存（epoll 与 io_uring，对比 hyper、tokio、tokio-tungstenite、fib），以及 QUIC/HTTP/3、TLS、密码学、deflate、编解码与用户态协议栈微基准；各领域优化数字在 1–2% 内复现。测试脚本现会跳过被之前运行占用的端口。DPDK 未测（主机无真实网卡）。WebSocket 每连接内存曾回退到 3.5 KB（only-deflate 编解码状态内联存放，未协商压缩时也占用）；改为 Box 后降到 1.4 KB（替换前为 1.66 KB）。
- [x] 宽 AES-GCM / CRC：VAES + VPCLMULQDQ + AVX-512 `asm!` 内核（512 位；Zen 4 上所有长度均快于 256 位；MSRV 保持 1.85，用 CPUID/XGETBV 检测），融合短尾部，TLS 记录非原地加解密，512 位 CRC 折叠。AES-128-GCM 16 KiB 6.5 → 15.0 GB/s（ring 的 1.19 倍），TLS 1.3 记录 16 KiB 相对 rustls+ring 0.69 倍 → 1.65 倍（1 KiB 1.53 倍），CRC-32 相对 crc32fast 0.27 倍 → 1.02 倍。未完成：无 AVX-512 的 CPU 用的 VAES-AVX2 内核、宽内核内的掩码尾部处理。
- [x] TLS 握手提速：P-256 域与群阶运算（`ec::hw`）及 X25519 阶梯（`curve25519::hw`）改用 BMI2/ADX `asm!`，常数时间 Jacobian 标量乘法（ECDH 用 Booth w=5，生成密钥/签名用有符号梳形表加混合加法），X25519 公钥由 Edwards 基点表计算。握手：X25519 3,055 → 5,027 次/秒（rustls+ring 的 1.00 倍，原 0.61 倍），secp256r1 2,306 → 4,552 次/秒（0.89 倍，原 0.45 倍）；P-256 签名/验签/ECDH/生成密钥为 ring 的 0.79/0.96/0.91/0.96 倍。未完成：寄存器内完成的倍点、更宽的梳形表、aarch64 汇编、RSA、dudect 式计时测试。
- [x] P-256 整点优化（x86_64）：倍点 / 加法 / 混合加法各为一个 BMI2+ADX `asm!` 块（连续倍点共用一帧），6 位 Booth 梳形表（43×32 个仿射点，88 KiB）与 ECDH 窗口表用 AVX2 掩码扫表，常数时间 safegcd（Bernstein–Yang）求逆，divsteps 用汇编。相对 ring：签名 1.25 倍，生成密钥 1.33 倍，验签 1.04 倍，ECDH 0.96 倍；secp256r1 TLS 握手为 rustls+ring 的 1.12 倍（比例来自同一轮 A/B；主机有外部负载）。ECDH 后来在空闲主机上测得为 1.08 倍；0.96 倍是有负载时测得。
- [x] x86_64 上 P-256 ECDH 不低于 ring：改用 OpenSSL ecp_nistz256 的点运算公式（加法 12M+4S、混合加法 8M+3S、倍点从 2Y 出发并用无分支模减半），约简每步 7 条指令。空闲的 Zen 4、同一轮 A/B：ECDH 为 ring 的 1.08 倍 → 1.12 倍，签名 1.38 倍，验签 1.10 倍，生成密钥 1.40 倍；倍点 348、加法 721、混合加法 508 个周期，可变基点乘法 140.6k。握手在噪声范围内不变（secp256r1 为 rustls+ring 的 1.07 倍，X25519 1.08 倍）。约简交织进乘积各行实测无收益，未采用。

### 性能优化第二轮（后续项，2026-11-16）
用户不在时按建议方案做出的决定（之后再审阅）：
- aarch64 汇编只用测试验证；在有 ARM 基准主机之前不给出 aarch64 性能数字（用户选择）。
- 基准测试只在安静主机 .51 上用 `quiet.sh` 运行；有外部负载时报告同一轮 A/B 的比例，而不是绝对数字。
- 新的 SIMD/汇编代码通过 `asm!` 加 CPUID/XGETBV 检测保持 MSRV 1.85，不提高 MSRV。

条目：
- [x] P-256 域/群阶运算与 X25519 阶梯的 aarch64 `asm!`（仅测试）：P-256 模 p 只用移位的约简、模 n、加减/2ᵏ·a/3·a，`P256A` 孪生曲线配 safegcd 求逆；X25519 域为 4×64 limb、按 38 折叠；MUL/UMULH + ADDS/ADCS + CSEL，`Feature::Umulh`。差分、运算链、孪生曲线测试，RFC 7748 百万次迭代与 Wycheproof 在 macOS 与 arm64 Linux 上通过；已反汇编检查常数时间。尚未做性能测试（没有 ARM 基准主机）；aarch64 上的整点汇编、divsteps 汇编与扫表未做。
- [x] x86_64 上的 RSA 签名/验签（2048 位签名原为 ring 的 0.49 倍，验签 0.59 倍）：BMI2+ADX 的 Montgomery `asm!`（16–64 个 limb），AVX-512 IFMA 以 2⁵² 为基数计算 2048–4096 位密钥 CRT 两半的模幂，带 AVX2 查表的 5 位窗口，R² 用平方（秘密模数）或一次除法（公开模数）。Zen 4：签名为 ring 的 1.61 / 1.85 / 2.19 倍（2048/3072/4096），验签 1.22 / 1.10 / 1.09 倍，含密钥解析的验签 1.02 / 0.95 / 0.95 倍，RSA-2048 证书 TLS 握手相对 rustls+ring 0.43 倍 → 1.44 倍；只有 BMI2+ADX（无 IFMA）时签名约 0.99 倍。之后（2026-11-16）把 CRT 两半交错放进同一个 IFMA 循环（`amm*_x2`，每次迭代两半各推进一个数字步，用满 32 个向量寄存器，零掩码移位，输出指针暂存在 `k7`）：每一半的模幂 1.37 / 1.19 / 1.17 倍（1024/1536/2048 位），签名为 ring 的 2.20 / 2.19 / 2.55 倍，RSA-2048 TLS 握手为 rustls+ring 的 1.69 倍；验签不变。之后（2026-11-16）公开运算移到 IFMA 上（`Mont::pow_public`：新增单模数 AMM `amm64`（走 60 步）与 `amm80`（用 30 个向量寄存器），e = 65537 只需 18 次乘积，R² mod n 用带 Möller–Granlund 倒数的除法求得、不做 Montgomery 乘法）：验签为 ring 的 3.07 / 3.30 / 3.70 倍，含密钥解析 2.35 / 2.64 / 2.90 倍（原代码的 2.31 / 2.76 / 3.04 倍），签名 2.26 / 2.24 / 2.60 倍，RSA-2048 TLS 握手为 rustls+ring 的 1.82 倍；可移植验签 0.59 倍 → 0.70 倍。
- [x] ChaCha20-Poly1305 大块性能（TLS 记录原为 rustls+ring 的 0.55 倍）：ChaCha20 AVX-512 `asm!`（zmm 每次 16 个分组，余下部分用 ymm/xmm），Poly1305 用 AVX-512 IFMA（每步 8 个分组，256 B 起）加 2⁶⁴ 进制标量实现，TLS 记录非原地加解密。Zen 4：加密 16 KiB 1,752 → 4,597 MB/s（ring 的 1.30 倍），1400 B 0.96 倍，64 B 0.83 倍；TLS ChaCha 记录 16 KiB 相对 rustls+ring 0.55 倍 → 1.42 倍，1 KiB 0.64 倍 → 1.02 倍。判断在 Zen 4 上把 ChaCha20 与 Poly1305 缝合不值得。之后（2026-11-16）优化短消息：四个分组每个 zmm 寄存器存一行（用于开头与短尾部），不完整的最后一组在字节掩码下处理而不经缓冲区，开头按实测内核耗时取四个或八个分组，AEAD 的 Poly1305 不再经流式缓冲区；加密 64 B 相对 ring 0.83 倍 → 0.98 倍，1 KiB 1.00 倍 → 1.08 倍，1400 B 0.99 倍 → 1.21 倍，解密 64 B 0.76 倍 → 0.85 倍；TLS ChaCha 记录 1 KiB 相对 rustls+ring 1.09 倍 → 1.15 倍。之后（2026-11-16）为没有 IFMA 的 CPU 做了 AVX2 Poly1305（以 2²⁶ 为基数每步 4 个分组，512 B 起）：AVX2 路径加密 16 KiB +20%，1 KiB +7%（在 Zen 4 上通过 AVX2 密钥测量）。未完成：64 字节消息的解密（ring 的 0.85 倍）。
- [x] QUIC 数据通路遗留项：默认开启 UDP GRO（`Config::udp_gro`，Linux 上内核支持时）；UDP 循环内部的批次结束钩子（`Handler::on_batch_end`，`#[doc(hidden)]`；epoll、io_uring 与 macOS），only-quic 每个接收批次只确认一次；收到的包在每线程池化缓冲区中解密，`Bytes` 共享该缓冲区；已发送包改用环形缓冲；每个数据报只读一次时钟。批量传输 6.4 → 16.1 Gbit/s（2.5 倍；quinn-proto 的 3.5 倍），HTTP/3 +4%（quinn-proto 的 7.6 倍），握手持平。未完成：完全不从 `recvmmsg` 槽位复制（需要拥有缓冲区的 `on_data`）、对端/连接 ID 表上的 SipHash、HTTP/3 剖析中占主导的 only-h3/only-http 分配。
- [x] HTTP/3 请求路径：帧原地读取，QPACK 字段解码进复用的扁平缓冲区、只复制一次进 `Headers`，HEADERS 直接编码进输出，每个响应只写一次 QUIC，一次收全的请求不进流表；only-quic 的连接 ID 表、连接表与对端地址表改用每表独立密钥的乘法折叠哈希（抗 HashDoS），按序 ACK 不经过区间树，第一块发送数据内联。HTTP/3 42.9 万 → 83.9 万请求/秒（1.95 倍），批量传输 +5%，握手持平；API 不变。剩下的几项（QPACK、`Context` 与每次发送的 `Bytes` 分配）由下文的减少分配一项完成。
- [x] only-quic 第 D 波遗留：ECN（标记、按 RFC 9000 13.4 验证、CE 响应、Linux TOS/TCLASS 控制消息通路；`TransportConfig::ecn`、`ONLY_UDP_ECN=0`）、BBR（BBRv1 模型加 v2/v3 式丢包/ECN 上限，实验性；netem 100 Mbit/s 40 ms：1% 丢包时 73 对 CUBIC 5 Mbit/s，60 包缓冲 75 对 35）、客户端主动迁移（`Connection::migrate`）与 `preferred_address`、QUIC v2（RFC 9369）含版本协商后重新开始与 RFC 9368 防降级检查；与 quic-go 的 v2（仅短连接：quic-go 用 v1 标签派生 v2 密钥更新）、迁移与 ECN 互通。only-quic 与 only-sys 有新增的公开 API（快照已更新）。代价：批量、HTTP/3 与握手因每个数据报的 ECN 控制消息与簿记慢 1–2%。剩余：0-RTT（only-tls 早期数据加 QUIC 0-RTT，需显式开启并带防重放）、兼容版本协商（RFC 9368 第 4 节）。
- [x] TLS 1.3 早期数据（only-tls）与 QUIC 0-RTT（only-quic），双方均需显式开启：绑定票据的第一个 PSK、套件、ALPN 与 SNI（QUIC 另绑传输限额）；TCP 上以 EndOfEarlyData 结束；被拒数据由服务端跳过、客户端重发；`TlsInfo::early_data` / `early_data_len`、`Connection::early_data` / `is_early`。开启后防重放始终生效（用户不在时的决定：用有界防重放窗口而非一次性票据）：10 秒票据年龄新鲜度加每个配置一份已接受 ClientHello binder 的记录（20 秒、10 万条，满则拒绝）；不在进程或机器之间共享。only-h3 与 only-http（HTTP/1.1 精确、HTTP/2 按连接）给早期请求加 `Early-Data: 1`（RFC 8470）。互通：与 quic-go 双向 0-RTT（v1、v2），与 OpenSSL 双向早期数据。新增公开 API 均为增量（快照已更新）。无可测量代价；回环上恢复会话的拨号到应答 259 → 220 µs。剩余：兼容版本协商（RFC 9368 第 4 节）；共享票据的多个服务端需要共享的防重放存储（均已完成，见下一条）。
- [x] 共享的 0-RTT 防重放存储与 QUIC 兼容版本协商（2026-11-16，ADR-013）：only-tls 的 `AntiReplayStore`（对 ClientHello binder 带 TTL 的检查并插入，可失败，须原子），默认实现 `MemoryAntiReplay` 即原有的有界内存窗口；存储出错时拒绝早期数据（失败即关闭）；`ServerConfigBuilder::anti_replay_store` 与 `session_ticket_key`（多个进程或多台机器上的服务端可互认票据并共享防重放；书中有 Redis `SET NX PX` 示意）。only-quic 的 `ServerConfig::prefer_version`：握手内的兼容版本协商（RFC 9368 第 4 节），服务端在 TLS 应答前读完整个首个 ClientHello（ClientHello 跨多包、Retry、0-RTT 按 RFC 9369 4.1 保持首个版本），客户端跟随任何能解密的兼容切换；默认关闭。测试：共享票据密钥与模拟远程存储的两台服务端拒绝从一台重放到另一台的 ClientHello（TLS 与 QUIC），存储失败时拒绝早期数据，模拟链路上的兼容协商（丢包、Retry、0-RTT、v2 切 v1、伪造 Initial）；fuzz 连接对切换到 v2，并 fuzz ClientHello 预读。互通：quic-go 未实现 RFC 9368（不发 version_information，丢弃其他版本的包），因此检查它在偏好另一版本的服务端上保持原版本（`tools/interop/quic/run.sh`）；ngtcp2 1.11 与 only-quic/only-h3 双向切换，含 0-RTT（`tools/interop/quic/ngtcp2-cvn.sh`，Docker，由 Debian 源码包构建）。新增公开 API 均为增量（快照已更新）。代价：未测出（默认配置下同次 A/B：QUIC 完整握手 9,496 → 9,497/秒，0-RTT 恢复的拨号到应答 228 → 226 µs，TLS 完整握手 1.00×；docs/BENCHMARKS.zh-CN.md）。剩余：异步存储接口；多把有效密钥并存的票据密钥轮换。
- [x] QUIC 票据与令牌绑定到 QUIC 版本（2026-11-17，ADR-014，RFC 9369 第 5 节）：only-tls 会话携带 QUIC 版本（格式 3），只在该版本中出示与恢复，兼容切换后为协商出的版本；Retry 与 NEW_TOKEN 令牌同样携带版本。客户端以该服务端最新票据（没有票据时看令牌）的版本开始，因此被偏好 v2 的服务端切到 v2 的 v1 客户端以 v2 带 0-RTT 恢复，而不是每次都完整握手。测试覆盖 only-tls、endpoint 与模拟链路；与 quic-go 的互通不变，与 ngtcp2 1.11 双向检查（其客户端以 v1 重用 v2 票据，现在按 RFC 要求被拒）。公开 API 无变化。代价：无（每个票据与令牌多四字节）。
- [x] 应用自建的中继（2026-11-16 经用户同意已添加：公开的 `Conn::set_relayed(bool)` 与 `RawConn::set_relayed`，在背压指南中 `hold_reads` 旁有说明，测试 `relayed_connection_keeps_reading_past_the_watermark`）：引擎在连接自身写队列高于 `write_high_watermark` 时暂停读取，这会让双向中继死锁（only-socks 的 SOCKS5 / HTTP CONNECT 隧道已用内部 `relayed` 标志修复）。应用用公开的 `Conn::hold_reads` / `on_drain` 自建中继时仍有此隐患。建议（因新增公开 API，待用户审阅）：增加 `Conn::set_relayed(bool)`（或 `Listener`/拨号选项），让连接不受写水位暂停读取的影响，并在 `hold_reads` 旁写明。
- [x] 宽 AES-GCM 遗留项：AVX-512 内核处理整条消息（AAD、用字节掩码处理的最后一个不完整组、长度块与 E(J0)；短消息只做一次归约），无 AVX-512 的 CPU 使用新的 VAES-AVX2 内核（8 个 ymm 处理 16 个分组）。AES-128-GCM 加密 1 KiB 为 ring 的 1.00 倍 → 1.32 倍，1400 B 1.10 倍 → 1.46 倍，64 B 1.11 倍 → 1.29 倍；AVX2 内核为 128 位路径的 1.55–2.35 倍（在关闭 AVX-512 的 Zen 4 上测得，无 Zen 3 主机）；TLS 1.3 记录 1 KiB 为 rustls+ring 的 1.51 倍 → 1.58 倍。TLS 记录的预先清零后来已去掉（2026-11-16，用户批准 unsafe）：only-crypto 新增 `fill` 模块与隐藏的 `encrypt_append` / `decrypt_append`（AES-GCM 全部内核、ChaCha20-Poly1305），直接写入调用方的空闲容量，only-tls 仍为 `#![forbid(unsafe_code)]`。Zen 4 上 TLS 1.3 记录：AES-128-GCM +6.9–8.3%（16 KiB 为 rustls+ring 的 1.58 倍 → 1.72 倍），AES-256-GCM +7.4–8.7%，ChaCha20-Poly1305 +3.3–6.4%；可移植路径经 Miri 检查。未完成：AVX2 内核的掩码尾部。
- [x] 对依赖秘密数据的路径做 dudect 式统计计时测试（CI 任务，不作为门禁）：`tools/ct-dudect`（Welch t 检验，固定对随机秘密，rdtsc / cntvct_el0，分位数裁剪加二阶检验），覆盖 P-256 ECDH/生成密钥/签名、X25519、Ed25519、RSA-2048、AES-GCM / ChaCha20-Poly1305 / HMAC 标签校验、`ct_eq` 与 `ct.rs` 原语，并有 A/A 与两个故意泄漏的自检目标；CI 任务 `ct-dudect`（continue-on-error，不属于 `ci-ok`，上传 t 值）。Zen 4 两条路径：无稳定泄漏。两处细小且时有时无的差异记录在 docs/constant-time.zh-CN.md（仅全零标量的 x25519 生成密钥，≤60 ppm；P-256 可移植签名处于 4.5 阈值边缘），需在安静主机上重测。
- [x] 每个 HTTP/3 请求的内存分配（2026-11-16）：`quic-bench h3` 两端合计 21.6 → 8.6 次。only-quic 交付流数据不再经过临时向量，并有一个隐藏的池化 `Bytes` 构造函数；only-h3 把较小的头写进其中，原地加宽 HEADERS 长度，写 `:status` / `content-length` / date 行（每秒缓存一次）时不查 QPACK 表；only-http 的 `Context` 自己持有请求直到需要共享（detach、WebSocket），`Headers` 在向量的 niche 中内联保存两个字段位置（仍为 48 字节；内联四个时为 80 字节，让 HTTP/2 每请求 CPU 增加约 3%），没有需要应用的内容时跳过响应收尾。HTTP/3 820,741 → 883,127 请求/秒（1.08 倍，同一次运行的 A/B，主机空闲）；HTTP/1.1 与 h2c 在噪声范围内持平（服务端每请求 CPU ±0.4%）；没有公共 API 变化。剩余：每个请求装箱的 `ResponseSink` 与请求目标 `String`（属于公共 API）、QPACK 解码（约 2%）。
- [x] `only-deflate` 存储块解码只复制一次：直接写入输出，`decompress_vec` 追加时不填零，只有最后 32 KiB 进窗口。随机数据级别 6 解压 15.5 → 34.3 GB/s（zlib-rs 的 0.43 倍 → 0.94 倍）；以字面量为主的解码不变（试过每次补充解码 5 个字面量，无收益）。
- [x] TLS 扩展（2026-11-16，ADR-008）：record_size_limit（RFC 8449，TLS 1.3 与 1.2：客户端总是发送自己的值，服务端被请求时回以自己的值，受保护记录按对方的限制切分，超过我方限制的记录以 `record_overflow` 拒绝，早期数据遵循票据的限制，QUIC 中不使用，限制较小时拒绝 kTLS 卸载）、证书压缩（RFC 8879，TLS 1.3，仅 zlib，由 only-deflate 提供：没有自研 brotli/zstd；服务端默认开启，客户端默认关闭（解压一次约 1–2 µs，约为内存中握手的 1%）；服务端证书链只压缩一次并复用，CertificateRequest 提供时客户端证书也压缩；最多解压到 128 KiB，长度须完全一致）与 OCSP stapling（`ocsp_response` / `sni_ocsp_response` 装订 DER 响应，TLS 1.3 放在 CertificateEntry 中、TLS 1.2 用 CertificateStatus；`ocsp_stapling(true)` 请求，`TlsInfo::ocsp_response` 公开收到的响应，**不验证**：only-x509 尚无 OCSP）。增量 API（`record_size_limit`、`certificate_compression`、`ocsp_response`、`sni_ocsp_response`、`ocsp_stapling`、`TlsInfo::ocsp_response`；快照已更新）。测试：带扩展的内存矩阵、反例、fuzz 语料与解析器；互通 `tools/interop/tls/run.sh`（Debian Docker 中 arm64 与 x86_64 均为 132/132，Ubuntu 上原生 OpenSSL 3.0 为 125/125，macOS 上 OpenSSL 4.1 为 123/123；工具缺少相应功能时跳过新用例）：OpenSSL（s_client 验证 OCSP，与 Debian 的 OpenSSL 3.5 双向 zlib 压缩服务端与客户端证书，忽略 max_fragment_length 请求）、Go（双向 OCSP）、GnuTLS 3.8（双向 record_size_limit 与 OCSP；Debian 的 GnuTLS 不支持 zlib 证书压缩）；tlsfuzzer 36 个脚本、1,096 个探测（新增 test-record-size-limit、test-tls13-certificate-compression、test-tls13-client-certificate-compression；test-ocsp-stapling 只提供 CBC 套件）。顺带修复：长度不对的 KeyUpdate 报 `decode_error`（tlsfuzzer 的超大 KeyUpdate 探测会随机失败）。握手 不变（安静主机上同批 A/B：X25519 1.00 倍、secp256r1 1.00 倍、RSA-2048 1.00 倍；客户端开启压缩时为 0.99 倍，因此客户端默认关闭）。未完成：OCSP 验证、brotli/zstd、`status_request_v2`、TLS 1.3 客户端认证中客户端的 OCSP 响应。
- [x] HTTP/3 功能（2026-11-16，ADR-011）：HTTP/3 上的 WebSocket（RFC 9220 extended CONNECT，服务端经 `Context::upgrade_websocket` 且由 GET 路由应答，客户端 `H3Client::websocket`；only-ws 通过隐藏的 `WsLink` 接缝写出）、QPACK 动态表（RFC 9204：带 encoder/decoder stream 的解码器，被阻塞的字段段按顺序暂存，上限为 `qpack_blocked_streams`，确认、增量和取消，默认 4 KiB / 16；从不阻塞对端的编码器默认关闭，`qpack_encoder_capacity`）、流式请求 body（从不暂存 DATA 负载的读取器，`BodyMode::Stream` 经 `Context::on_body`，客户端 `H3Client::upload`）。互通：quic-go 双向（WebSocket、流式上传）、fib、Docker 中的 libcurl ngtcp2/nghttp3 与 OpenSSL QUIC（nghttp3 会填充我方解码器的表；curl 不提供解码器动态表，所以没有第三方解码器验证我方编码器）。新增 fuzz 目标 `qpack_dynamic`。`quic-bench h3` 同轮 A/B（编码器关闭）：为 main 46c3c9ab 的 1.001 倍（88.32 万 vs 88.27 万 请求/秒，CPU 2-5，两次各 7 轮交替：0.998 倍和 1.003 倍；最初的完整版本为 0.956 倍，靠内联每请求的调用、把附加状态装箱回到持平，用 callgrind 测量）；合并 main 2d1f5720（客户端上限、QUIC 发送上限）后起初为它的 0.980 倍，经完整到达的请求与响应走快速路径、请求截止时间按下标索引、客户端每请求只加一次锁后为 1.025 倍（88.13 万 vs 85.96 万，1.024 倍和 1.027 倍，14 轮全部更快；x86 callgrind 每请求 18525 vs 18826 条指令；此前每请求约 250 条指令分散在请求路径上）。两端都开启 QPACK 编码器慢 18%。未完成：HTTP/2 上的 WebSocket（RFC 8441）、我方编码器的 Duplicate / 动态名称引用、客户端流式响应、服务器推送。
- [x] 引入 fit 规则（2026-11-17，docs/rules.zh-CN.md，ADR-009）：按新的数据面规则审查整个工作区，分七个并行分支修复。所有上限都有安全默认值（引擎写/连接超时和 UDP 对端、流水线响应、TLS 握手、HTTP 读头/keep-alive/消息体超时、HTTP/2 重置与洪泛预算、客户端响应上限与连接池、gRPC/arpc 截止时间与流、WebSocket 压缩消息、RTMP/HLS/hub/WHIP/SRT/WebRTC、QUIC 发送缓冲与连接数、KCP 会话、SOCKS 默认只允许公网目标（用户决定）、mux 嗅探、BitTorrent tracker 表、DTLS cookie 前重组）；阻塞工作移出 I/O 线程（静态文件、h3 文件消息体、tracker 与 CONNECT 的 DNS）；热路径不再有共享引用计数、全局锁或每请求格式化。实测：带截止时间的 gRPC/arpc 调用 ×17 / ×278，TURN 中继 3.7 倍，WebSocket 1 KiB 回显 +7–11%，流水线 HTTP/1.1 和 h2c +3–4%，QUIC 批量 −2.7%（4 MiB 每流发送缓冲）。only-log 默认仍为同步（用户决定；`non_blocking` 需显式开启）。详见 CHANGELOG。
- [x] HTTP/WebSocket 客户端补齐（2026-11-16，ADR-010）：HTTP/1 客户端可选的重定向（`RedirectPolicy`：301/302/303/307/308，方法与请求体按 RFC 9110 15.4，相对 `Location`，跨源删除 `Authorization`/`Cookie`/`Proxy-Authorization`，默认拒绝 https→http，跳数上限终止循环；`ClientResponse::url`）以及 WebSocket 握手重定向（`DialOptions::max_redirects`）；覆盖整个交换的单请求超时（`ClientRequest::timeout`、`Client::with_timeout`；`H2Client` 以 CANCEL 重置流）；在调用线程之外解析域名（`only::dns`，无依赖、最多 4 个线程）；系统根证书（`RootCerts::system()`：SSL_CERT_FILE/DIR、通过 `security` 读取 macOS 钥匙串、Linux/BSD 证书包与目录；现在是客户端 https/wss 的默认值）；HTTP 代理（`Proxy`，显式启用的 `from_env`，支持 NO_PROXY/CIDR，http 用绝对形式，https/ws/wss 用叠在 TLS 之下的 `CONNECT` 隧道，`ProxyRefused`）；engine 停机时 WebSocket 客户端以 1001 关闭。only、only-tls、only-ws、only-http 的 API 均为新增（快照已更新）。测试：重定向链、循环、方法规则、跨源删除凭据、超时（h1 与 h2）、本地测试代理（绝对形式、CONNECT、407、NO_PROXY）、WebSocket 重定向/代理/1001；在 macOS、Linux arm64 Docker 与 x86_64（epoll 与 io_uring）上通过。未做：cookie 容器、TLS/SOCKS 代理、PAC、Happy Eyeballs、DNS 缓存、macOS 信任设置、Windows 证书库。

## 4. 工程规范
- **数据面规则**：[docs/rules.zh-CN.md](rules.zh-CN.md)（绝不阻塞 I/O 线程、消息体和队列有界、背压联动、超时与带安全默认值的上限、热路径工作放到构建时、验证与改动相称）；默认值见 ADR-009。
- CI（用户 2026-11-16 决定）：GitHub Actions 只在发布预发布版本或手动运行时执行；普通提交、推送与 PR 不触发。每次改动在推送前于本地验证：macOS、Docker 中的 Linux arm64（epoll 与 `ONLY_TEST_BACKEND=uring`），以及原生 x86_64 Linux（x86 汇编、真实 io_uring 与基准测试）。
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
