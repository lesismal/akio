# only

[English](README.md) | 简体中文

only 是 Rust 的事件驱动、每核一线程网络库，是 Go 库 [fib](https://github.com/lesismal/fib) 的
Rust 对应物。回调直接在连接所属的 I/O 线程上执行，可克隆的 `Conn` 句柄可以在任何线程使用，
阻塞任务交给显式的逻辑线程池，每个 listener 独立选择后端（epoll/kqueue 或 io_uring），并可选
eBPF 分流。没有异步运行时。（原名 *flash*，在 1.0.0 之前更名，见 [CHANGELOG.zh-CN.md](CHANGELOG.zh-CN.md)。）

**文档：** [only 指南](https://lesismal.github.io/only/zh-CN/) ·
[架构](docs/architecture.zh-CN.md) · [从 fib、tokio、hyper/axum 迁移](https://lesismal.github.io/only/zh-CN/migration/from-fib.html) ·
API 参考：`cargo doc --workspace --no-deps --open`

## 功能

| 方面 | 内容 |
|---|---|
| 引擎 | 按 listener 选择后端：epoll（Linux）、kqueue（macOS）、io_uring（Linux 5.19+，不可用时回退到 epoll）；每核一线程的 I/O 线程；`SO_REUSEPORT` 分发连接；eBPF/经典 BPF 分流（`Accel::Ebpf`）以及内核内 sockmap 转发 |
| 连接 | `Conn` 是 `Clone + Send + Sync`；任意线程非阻塞 `send`，支持直接写、cork、`writev`、`sendfile`；背压（水位线、`hold_reads`、`on_drain`、`max_queued_bytes`）；空闲超时；异步 dial；优雅停机 |
| 阻塞任务 | 自适应、有界的逻辑线程池，`Conn::spawn_blocking` 的完成回调回到 I/O 线程，有序响应槽位，慢回调检测 |
| UDP | 每个对端一个 `Conn`，或按批交给 `DatagramsHandler` 的无连接方式（没有对端表），`recvmmsg`/`sendmmsg`，UDP GSO/GRO，对端数量上限，UDP dial，共享端口上的组播组（IPv6 组按接口加入：`Engine::bind_udp_multicast_on`） |
| TLS | 自研 TLS 1.3 / 1.2（`only-tls`，无第三方代码）作为连接 transport：服务端与客户端、ALPN、SNI、客户端证书、会话恢复 |
| HTTP | 同一端口上的 HTTP/1.1 与 HTTP/2（h2spec 147/147），流水线，双向流式，Router（静态/正则/参数/通配），9 个中间件，基于 `sendfile` 的静态文件，HTTP/1 与 HTTP/2 客户端 |
| WebSocket | 服务端与客户端，permessage-deflate，Autobahn 100%（服务端与客户端） |
| HTTP/3 与 QUIC | 自研 QUIC v1（RFC 9000/9001/9002，数据报、迁移、Retry、密钥更新、GSO），HTTP/3 提供同一个 `Router`（QPACK 动态表、HTTP/3 上的 WebSocket、流式请求 body），H3 客户端（流式上传与流式响应）；与 quic-go、fib、curl（ngtcp2、OpenSSL）互通 |
| RPC | gRPC（unary 与流式，与 grpc-go 互通），arpc（与 lesismal/arpc 和 fib 线路兼容） |
| 代理 | SOCKS5/4/4a（用户名/密码或 GSS-API 认证）、HTTP CONNECT、按首字节嗅探的端口复用（only-mux） |
| KCP | 与 skywind3000/kcp 和 kcp-go 线路兼容（FEC、加密） |
| BitTorrent | tracker（HTTP/UDP，客户端与服务端）、带 MSE 的 peer wire、Fast 扩展、元数据交换与 PEX、uTP（LEDBAT）、主线 DHT、客户端；与 libtorrent 和 aria2 互通 |
| 流媒体 | only-media：统一的流 hub（GOP 缓存、慢播放者丢帧、鉴权钩子、统计），前接 RTMP（digest 握手、Enhanced RTMP 的 H.265/Opus）、RTSP 服务端（TCP 与 UDP，推流与播放）、SRT live（ARQ、TSBPD、AES 加密、主叫推拉流）、HTTP-FLV、WS-FLV、HLS（MPEG-TS 或 fMP4、LL-HLS 分片、阻塞式刷新）以及承载 WebRTC 媒体的 WHIP/WHEP，另有用于转发的 RTMP 与 RTSP 客户端；已与 ffmpeg、mediamtx 与 pion 互通测试 |
| WebRTC、STUN、TURN | 自研、sans-io、无第三方依赖的 WebRTC（ICE-lite 服务端与完整 ICE agent、DTLS-SRTP、SCTP 数据通道、带 NACK/RTX、TWCC 与带宽估计的 RTP/RTCP 媒体）；STUN 与 TURN 服务器；与 pion、fib、Chrome、coturn 互通 |
| 运维 | Prometheus 指标、连接表、慢回调记录、JSON 调试端点、基于 `log` 的结构化日志、运行时设置热更新；多进程 prefork 服务，支持 worker 重启与不停机重载（[only-prefork](crates/only-prefork/README.zh-CN.md)） |

实测性能（单台机器，请先看注意事项）：[docs/BENCHMARKS.zh-CN.md](docs/BENCHMARKS.zh-CN.md)。

## 快速上手

```toml
[dependencies]
only = { git = "https://github.com/lesismal/only" }
```

```rust
use only::{Conn, Engine, Handler, Listener, fn_acceptor};

struct Echo;

impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data); // 非阻塞，直接在 I/O 线程上执行
    }
}

fn main() -> std::io::Result<()> {
    let engine = Engine::builder()
        .listen(Listener::tcp("127.0.0.1:7000".parse().unwrap())
            .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)))
        .build()?;
    engine.run()
}
```

更多示例：`cargo run -p only --example guide-basics`、`cargo run -p only-http --example hello`，
以及指南[快速上手](https://lesismal.github.io/only/zh-CN/getting-started.html)中列出的其他
`guide-*` 示例。

## 状态

里程碑 M0–M5 已完成，生产可观测性（M6）已就绪；DPDK、混沌测试以及 M7 协议（流媒体、WebRTC、
BitTorrent）尚未完成。Linux 是第一等平台；macOS 用于开发；不支持 Windows。计划与进度：
[docs/ROADMAP.zh-CN.md](docs/ROADMAP.zh-CN.md)、[docs/DEV-PLAN.zh-CN.md](docs/DEV-PLAN.zh-CN.md)，
设计决策见 [docs/adr](docs/adr/README.zh-CN.md)。

当前版本为 `1.0.0-rc.1`：API 已冻结以供评审。从 1.0.0 起 only 遵循 semver，具体见
[docs/api-stability.zh-CN.md](docs/api-stability.zh-CN.md)（受保护的 crate、MSRV 1.85、平台级别）
与 [docs/deprecation.zh-CN.md](docs/deprecation.zh-CN.md)；变更记录见
[CHANGELOG.zh-CN.md](CHANGELOG.zh-CN.md)。

## 构建文档

```console
$ cargo install mdbook --locked --version 0.4.52
$ book/build.sh          # 检查并编译所有代码片段，构建 target/book/{en,zh-CN}
```

见 [book/README.zh-CN.md](book/README.zh-CN.md)。

## 许可证

MIT
