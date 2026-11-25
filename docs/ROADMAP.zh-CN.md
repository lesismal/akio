# akio Roadmap

[English](ROADMAP.md) | 简体中文

> 状态：**已审核通过**（2026-11-13）。eBPF 采用“加速/调度层（+可选 AF_XDP）”，文末其余提议全部同意；下文标注 `⚠ 待确认` 的条目均按文中写法定案。
>
> 原说明：标注 `⚠ 待确认` 的条目是我对原始设计做了调整或存在歧义、需要你拍板的地方，汇总在文末「待确认清单」。

akio 是 [fib](../../fib)（Go）的 Rust 版：功能面对齐 fib，实现方式遵循 Rust 习惯（所有权、`Send/Sync` 边界、零成本抽象、feature 开关、sans-io 协议层）。

## 1. 目标与非目标

**目标**
1. 协议与特性覆盖 fib（见第 3 节对齐矩阵），按优先级分期交付。
2. 多种 IO 后端：epoll、io_uring、eBPF、DPDK；**每个 listener 可独立选择后端**。
3. `Connection` 句柄可跨线程使用（带锁，`Send + Sync + Clone`），任意线程可 `send/close/...`。
4. 逻辑线程池：回调默认**非阻塞、直接在 IO 线程执行**；阻塞型工作由用户显式投递到逻辑池，完成后回调回到连接所属 IO 线程。
5. 性能目标：同机 benchmark 不低于 fib，并与 tokio+hyper、monoio、glommio 同档或更优。

**非目标（至少 1.0 前）**
- 不做 async/await 运行时（不是 tokio 替代品）；可在 1.0 后提供 `Future` 适配层。
- 不追求 Windows 支持（IOCP）。Linux 为一等平台，macOS 提供 kqueue 后端用于开发与测试。
- 不自己重写成熟的、sans-io 的密码学/协议实现（见 4.4）。

## 2. 核心设计（相对 fib 的关键差异）

### 2.1 线程模型：thread-per-core，连接归属某个 IO 线程
- 每个 IO 线程一个 reactor，拥有自己的连接表、缓冲池、定时器轮；`SO_REUSEPORT`（可选 eBPF 选择）把新连接分到各线程。
- 与 fib 的区别：fib 每一轮读事件可以落到任意空闲 worker（无亲和）；akio 因为回调**直接在 IO 线程执行**，连接必然归属某个 IO 线程，这样 `Handler` 的每连接状态无需 `Sync`、无锁访问。
- 代价：单连接的重回调会拖慢同线程其它连接——这正是逻辑线程池存在的理由（见 2.3）。文档里必须明确“回调不得阻塞”的契约，并提供慢回调检测（可配置阈值，超时打日志/指标）。

### 2.2 Connection：句柄 + 内部锁
```text
Conn  (Clone + Send + Sync)  ──►  Arc<ConnInner>
                                    ├─ id / generation（防 fd 复用后的误操作）
                                    ├─ owner: LoopHandle（所属 IO 线程的唤醒通道）
                                    ├─ Mutex<WriteState>（发送队列、cork、水位、关闭状态）
                                    └─ 原子状态位（open/closing/read-paused）
```
- **IO 线程上**：`send` 优先直写（队列空时 `write`/`writev`），写不完入队并注册 EPOLLOUT / 提交 uring SQE。
- **其它线程**：加锁入队，再通过 eventfd / uring `MSG_RING` 唤醒所属 loop 去刷出。锁只保护发送队列，**绝不在持锁时调用用户回调**（避免死锁）。
- 连接关闭后对句柄调用返回 `Err(Closed)`，不会 UB，也不 panic。
- 提供 fib 同款能力：`cork`、`send_owned/send_shared`、`send_file`（sendfile）、`splice_to`、`close_after_send`、`hold_reads`、`attachment`、`notify_output(limit, cb)` 背压通知。

### 2.3 逻辑线程池
```rust
// 默认：回调在 IO 线程内联执行，不阻塞
fn on_data(&mut self, c: &Conn, data: &[u8]) { c.send(b"pong"); }

// 需要阻塞操作（DB/文件/远程调用）：显式投递，结果回到连接所属 IO 线程
fn on_data(&mut self, c: &Conn, data: &[u8]) {
    let req = parse(data);
    c.spawn_blocking(move || db.query(req), |c, st, result| {   // 回调回到 IO 线程
        c.send(encode(result));
    });
}
```
- 回调在**连接所属 IO 线程**执行，因此 `st`（连接状态）仍可无锁访问；若连接在此期间已关闭，回调不执行（或以 `Err(Closed)` 执行，可配置）。
- 有界队列 + 过载策略（拒绝/丢弃/回压 `hold_reads`），池支持自适应伸缩（对标 fib taskpool 的 adaptive）。
- 对 HTTP/1.1 pipelining、arpc 等需要“顺序应答”的协议，提供**有序应答槽**（response slot），防止异步完成乱序。
- `⚠ 待确认`：是否同时提供 `Conn::spawn(async_fut)` 之类的异步桥？（建议 1.0 后。）

### 2.4 后端抽象与每 listener 选后端
```rust
Engine::builder()
    .listen(Listener::tcp("0.0.0.0:8080").backend(Backend::IoUring).handler(http))
    .listen(Listener::tcp("0.0.0.0:9000").backend(Backend::Epoll).handler(rpc))
    .listen(Listener::udp("0.0.0.0:443").backend(Backend::Dpdk(cfg)).handler(h3))
    .build()?.run()
```
- 内部定义 `Reactor` trait（accept / read / write / timer / wake / close），各后端实现；上层协议只依赖 `Conn` 与 `Handler`，不感知后端。
- 同一 Engine 内多个后端并存时，**每个后端有自己的一组 IO 线程**（线程数按 listener 配置，默认每核一个）。逻辑池、定时器、缓冲池可在 Engine 级共享。
- 统一的数据所有权约定：`on_data(&[u8])` 借用，回调返回后失效（epoll 借 loop 缓冲，io_uring 借 provided buffer ring，DPDK 借 mbuf）。需要保留就拷贝或 `data.to_owned_buf()`。

### 2.5 各后端定位
| 后端 | 定位 | 要点 |
| --- | --- | --- |
| epoll | 基线、默认 | 边沿触发；`accept4`、`writev`、`sendfile`、`splice`、`recvmmsg/sendmmsg`、UDP GRO/GSO |
| kqueue | macOS/BSD 开发与回归 | 与 epoll 共享大部分 reactor 逻辑；不追求极限性能 |
| io_uring | 高性能 Linux 后端 | multishot accept/recv、provided buffer ring、registered files/buffers、`SEND_ZC`、SQPOLL 可选、`MSG_RING` 跨线程唤醒；内核版本探测 + 自动降级到 epoll |
| eBPF | `⚠ 待确认` 见下 | 不是独立 IO 后端，而是**加速/调度层**：`SO_REUSEPORT` BPF 选线程（按 CPU/一致性哈希）、sockmap/`sk_msg` 的内核态转发（代理/relay 场景）、可选 XDP 过滤/限速 |
| DPDK | 内核旁路，极限性能 | 需要用户态 TCP/IP 栈（评估 smoltcp / f-stack 绑定）；先做 UDP 与基础 TCP，再扩展；独占网卡/大页，部署门槛高，放最后期 |

> **关于 eBPF 的歧义**：eBPF 程序本身不做用户态收发，把它和 epoll/io_uring/DPDK 并列为“Engine”需要先定义含义。我的建议是上表的“加速/调度层 + 可选 AF_XDP 数据面”：`Backend::Epoll + Accel::Ebpf(..)`，AF_XDP 作为 DPDK 之外的轻量旁路选项。请确认是否符合你的预期。

### 2.6 其它设计决策
- **sans-io 协议层**：HTTP/1、HTTP/2、WebSocket、QUIC、KCP 等解析/状态机写成纯函数式 sans-io 状态机，再由 akio 的 Handler 驱动。便于 fuzz、便于脱离 Engine 单测、便于在不同后端复用。
- **buffer**：size-class 缓冲池，每 IO 线程本地缓存 + 全局回收；`Bytes`-like 的引用计数共享缓冲，用于广播（对标 fib 的 `PreparedMessage`/`SendShared`）。
- **背压**：每连接写水位暂停读，Engine 级 `max_pending_bytes`，`hold_reads`。
- **优雅关闭**：`Engine::shutdown()` 通知各 handler，等待连接排空。
- **依赖策略**：fib 是零依赖，Rust 下改为“**少而精**”：`libc`、`io-uring`（或自研薄封装）、`aya`（eBPF）、`rustls`/`quinn-proto` 等 sans-io 成熟库按 feature 引入，核心 crate 保持近零依赖。`⚠ 待确认`
- **unsafe 治理**：unsafe 只出现在 `akio-sys`/后端/缓冲池内部，带 SAFETY 注释；核心并发结构用 `loom` 验证，协议解析用 `cargo-fuzz`，`miri` 跑纯 Rust 部分。

## 3. 与 fib 的功能对齐矩阵

优先级：P0 = 1.0 必须；P1 = 1.0 强烈建议；P2 = 1.0 后。

| 能力 | fib | akio 优先级 | 里程碑 | 说明 |
| --- | --- | --- | --- | --- |
| TCP / Unix socket、异步 dial | ✓ | P0 | M1 | sendfile / splice / writev / cork / 半关闭 |
| UDP（每 peer 一连接、批量收发） | ✓ | P0 | M2 | recvmmsg/sendmmsg、GRO/GSO |
| TLS 1.2/1.3 | ✓（自研） | P0 | M2 | 自研 sans-io TLS（`akio-tls`，已取代 rustls）；软件 kTLS 已评估、默认关闭（更慢，见 docs/BENCHMARKS.zh-CN.md）；引擎连接的内核 TLS，`Ktls::Hardware` 面向 TLS 卸载网卡（ADR-067） |
| HTTP/1.x（含 pipelining、chunked、sendfile） | ✓ | P0 | M3 | 参考 httparse 的 SIMD 思路，自研或复用 |
| Router / Middleware / 静态文件缓存 | ✓ | P0 | M3 | chi 风格，零分配路由 |
| WebSocket（RFC 6455 + permessage-deflate） | ✓ | P0 | M3 | Autobahn 测试套件进 CI |
| HTTP/2（h2/h2c、server push） | ✓ | P0 | M4 | h2spec 进 CI；HPACK 复用或自研 |
| mux（同端口多协议嗅探） | ✓ | P0 | M4 | |
| arpc | ✓ | P1 | M4 | 线协议兼容 lesismal/arpc |
| gRPC | ✓ | P1 | M4 | 与 prost/tonic 生态打通（codec 可插拔） |
| SOCKS4/4a/5、HTTP CONNECT 代理 | ✓ | P1 | M4 | 用 splice / sockmap 加速转发 |
| HTTP/3 + QUIC | ✓（自研） | P1 | M5 | 基于 quinn-proto 或 quiche 的 sans-io 核心 |
| KCP | ✓ | P1 | M5 | 兼容 skywind3000/kcp、kcp-go（含 FEC/加密） |
| 异步 HTTP 客户端（h1/h2/h3/ws） | ✓ | P1 | M4–M5 | 回调 / future 两种结果通道 |
| Prefork（多进程 SO_REUSEPORT） | ✓ | P2 | M6 | Rust 无 GC，收益小，降级为可选；已实现，2026-11-25 删除（ADR-121） |
| 流媒体（RTMP/RTSP/SRT/FLV/HLS/WHIP/WHEP） | ✓ | P2 | M7 | 体量大，拆独立 crate |
| WebRTC（ICE/DTLS-SRTP/DataChannel/TURN） | ✓ | P2 | M7 | 自研 sans-io 协议栈（DEV-PLAN 第 D 波） |
| BitTorrent（含 DHT/uTP/MSE） | ✓ | P2 | M7 | 独立 crate，最后做 |
| eBPF 加速 | — | P1 | M5 | 见 2.5 |
| DPDK 后端 | — | P2 | M6 | 见 2.5 |

## 4. 里程碑

> 工期按“1 位主力开发者”粗估，仅用于排序与风险感知，**不是承诺**。AI 辅助开发可显著压缩编码时间，但 benchmark 调优和协议一致性测试的时间不会同比压缩。

| 里程碑 | 版本 | 主题 | 退出标准（Definition of Done） | 粗估 |
| --- | --- | --- | --- | --- |
| **M0** | — | 立项与骨架 | workspace、CI（fmt/clippy/test/miri/loom）、设计文档（ADR）定稿、echo benchmark 脚手架 | 1–2 周 |
| **M1** | 0.1 | 核心引擎（epoll + kqueue） | TCP echo 跑通；`Conn` 跨线程 send/close；缓冲池、定时器；10k+ 连接稳定；与 fib echo 同档 | 4–6 周 |
| **M2** | 0.2 | 多后端 + 逻辑池 + UDP + TLS | io_uring 后端；**每 listener 选后端**；逻辑线程池 `spawn_blocking`+回调；UDP；rustls 集成；io_uring 对 epoll ≥ 提升 | 6–8 周 |
| **M3** | 0.3 | HTTP/1 + WebSocket | Router/中间件/静态文件；Autobahn 全绿；与 hyper、fib 的 HTTP/1 benchmark 对比报告 | 6–8 周 |
| **M4** | 0.4 | HTTP/2 + 多协议 | h2spec 全绿；mux；arpc；gRPC；SOCKS/CONNECT；异步客户端 | 8–10 周 |
| **M5** | 0.5 | QUIC/H3 + KCP + eBPF | HTTP/3 互通（curl/quiche）；KCP 与 kcp-go 互通；eBPF REUSEPORT 选择 + sockmap relay | 8–10 周 |
| **M6** | 0.6 | DPDK + 生产化 | DPDK UDP/TCP 基础路径；指标/日志/pprof 等价物；长稳与混沌测试 | 6–8 周 |
| **M7** | 0.7+ | 重型协议 | 流媒体、WebRTC、BitTorrent（各自独立 crate，可并行/社区化） | 开放 |
| **1.0** | 1.0 | 稳定化 | API 冻结、semver 承诺、安全审计（fuzz 覆盖、`cargo-audit`、unsafe 审查）、文档与示例齐全 | — |

## 5. 质量与性能保障
- **正确性**：Autobahn（WS）、h2spec（H2）、与 curl / nghttp2 / quiche / kcp-go 的互通测试进 CI。
- **并发**：`loom` 覆盖 Conn 发送队列/关闭状态机；压力测试覆盖“跨线程 send 与 close 竞争”。
- **模糊测试**：每个 sans-io 解析器至少一个 `cargo-fuzz` target。
- **性能门禁**：固定基线（akio 自身历史 + fib + hyper/tokio + monoio），CI 夜间跑，回退超过阈值报警。场景：echo、HTTP/1 plaintext、pipelined、HTTP/2 multiplexed、WS echo、TLS、10 万空闲连接内存。
- **平台矩阵**：Linux x86_64/aarch64（io_uring 需 ≥5.19 的特性分级探测）、macOS arm64（kqueue）。

## 6. 主要风险
| 风险 | 影响 | 缓解 |
| --- | --- | --- |
| 范围过大（fib 体量极大） | 永远到不了 1.0 | P0/P1/P2 分级；重型协议独立 crate，不阻塞 1.0 |
| 回调直接在 IO 线程执行，用户写了阻塞代码 | 同线程所有连接卡死 | 慢回调检测 + 文档 + lint 友好的 API（阻塞型 API 要求显式 `spawn_blocking`） |
| 跨线程 `Conn` 锁带来死锁/性能抖动 | 稳定性 | 持锁不回调、loom 测试、锁粒度仅限发送队列 |
| io_uring 内核碎片化、DPDK 部署门槛 | 兼容性 | 特性探测+自动降级；DPDK 放后期并标注实验性 |
| eBPF 需要特权/内核版本 | 部署受限 | 作为可选 feature，缺失则降级为 SO_REUSEPORT 默认哈希 |
| 自研 TLS/QUIC 的安全风险 | 安全 | 不自研密码学，复用 rustls/quinn-proto 等成熟 sans-io 库 |

## 7. 待确认清单
1. **eBPF 的含义**：采用“加速/调度层（REUSEPORT 选线程、sockmap 转发、可选 AF_XDP）”还是你另有所指？
2. **TLS/QUIC/HPACK 等是否复用成熟 crate**（rustls、quinn-proto…）而不是像 fib 一样全部自研？我建议复用，理由是安全性与工期。
3. **线程模型**：同意“连接归属单个 IO 线程（thread-per-core）”，放弃 fib 那种“每轮任意 worker”的无亲和模型吗？
4. **平台**：Linux 一等 + macOS(kqueue) 开发后端，不做 Windows，是否可以？
5. **异步桥**（`Future` 适配）是否放到 1.0 之后？
6. **P2 的重型协议**（流媒体 / WebRTC / BitTorrent）和 Prefork 是否接受放在 1.0 之后、独立 crate？（Prefork：2026-11-25 已删除，ADR-121。）
7. **许可证与 MSRV**：沿用 fib 的 LICENSE？MSRV 策略（建议 edition 2024，跟随 stable-2）。
