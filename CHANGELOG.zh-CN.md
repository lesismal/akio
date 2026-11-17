# 变更日志

[English](CHANGELOG.md)

only 的所有重要变更都记录在这里。格式遵循
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，only 从 1.0.0 起遵循
[语义化版本](https://semver.org/lang/zh-CN/)，具体定义见
[docs/api-stability.zh-CN.md](docs/api-stability.zh-CN.md)。弃用遵循
[docs/deprecation.zh-CN.md](docs/deprecation.zh-CN.md)。workspace 中所有 crate 共用一个版本号。

## [Unreleased]

### 新增：arpc 中间件、coder 与客户端连接池（only-arpc）

均为新增（ADR-023，docs/adr/023-arpc-middleware-coders-pools.zh-CN.md）：

- **中间件**：`Routes::middleware`（所有请求和通知）与 `Routes::method_middleware(method, ..)`
  接受 `Fn(&mut Context, Next)`；`next.run(ctx)` 执行调用链的其余部分（其后的代码在 handler 之后
  执行），不调用它直接返回即中止。顺序固定（全局、方法、handler），与注册先后无关。新增
  `Context::values` / `values_mut` / `responded`。没有中间件的路由直接调用 handler。
- **Coder**（`only_arpc::coder`）：作用于整帧的 `Coder` trait，`Routes::coder`，按添加顺序编码、
  逆序解码，与 Go 的 `MessageCoder` 相同。`Gzip::new(threshold)`（保留位第 7 位，解压量受
  `max_body_bytes` 限制）与 `Appender::new(name, bit)`（tracing 用第 0 位）与
  `arpcex/extension/middleware/coder` 线路兼容。`Values` 通过 `Peer::call_with` /
  `call_async_with` / `notify_with` 携带，应答用请求的值编码。已与 fib 的 Go arpc 双向验证
  （`tools/interop/arpc/run.sh`）；新增模糊测试目标 `arpc_coders`。
- **连接池**：`Pool::builder()`（`size`、`balance`：`Balance::RoundRobin` / `LeastPending`、
  `heartbeat`、`reconnect_interval`、`connect_timeout`）`.dial(..)`；调用发往在线的连接，心跳会
  关闭并替换沉默的连接。
- **等待应答的调用有上限**：`Routes::max_pending_calls`（默认每连接
  `DEFAULT_MAX_PENDING_CALLS` = 65536）；超出时调用以新增的 `CallError::Overloaded` 失败。新增
  `Peer::pending_calls`、`Peer::ping`。
- 实测（gpu51，同轮 A/B，10 轮中位数）：无中间件的调用为之前的 0.98 倍，一个中间件为无中间件的
  1.00 倍，均在约 4% 的噪声内；每次调用的用户态指令 +1.5%，周期数不变。

### 新增：HTTP/3 上的 WebSocket、QPACK 动态表、流式 HTTP/3 请求 body

均为新增（ADR-011，docs/adr/011-h3-websocket-qpack-streaming.zh-CN.md）：

- **HTTP/3 上的 WebSocket**（RFC 9220）。服务端宣告 extended CONNECT；
  `Context::upgrade_websocket` 以与 HTTP/1.1 相同的检查、子协议和 `permessage-deflate` 接受它，
  应答 `200`，并在请求流上承载 WebSocket，`WsHandler` / `WsSender` 不变。`Router` 把
  `websocket` 的 extended CONNECT 路由到该路径的 GET 路由，所以一个 `.get("/ws", ...)` 同时服务
  HTTP/1.1 和 HTTP/3。新增 `Request::protocol`（`:protocol`）。客户端：`H3Client::websocket` /
  `websocket_blocking` 与 `H3WsOptions`；被拒绝时返回 `H3Error::Status`。
- **QPACK 动态表**（RFC 9204），服务端在 `H3Config`、客户端在 `H3ClientOptions`（`H3Client::dial_with`）中配置：
  `qpack_max_table_capacity`（4096）和 `qpack_blocked_streams`（16）用于我方解码器（encoder/decoder
  stream、按顺序暂存被阻塞的字段段、确认、增量和取消），`qpack_encoder_capacity`（0，关闭）用于我方
  编码器，它只引用已确认的条目，因此从不阻塞对端。新增错误码 `code::QPACK_ENCODER_STREAM_ERROR` /
  `QPACK_DECODER_STREAM_ERROR`。服务端现在宣告 4 KiB 动态表：nghttp3（curl）和 OpenSSL QUIC 会立即
  使用。
- **HTTP/3 流式请求 body**：`BodyMode::Stream` 的 service 与 HTTP/1、HTTP/2 一样通过
  `Context::on_body` 随到随收，不受 `max_body_bytes` 限制；请求读取器从不暂存 DATA 负载。客户端：
  `H3Client::upload` 返回 `H3Upload`（`write`、`finish`、`queued_bytes`）。
- 互通：quic-go（双向 HTTP/3 WebSocket 与流式上传），Docker 中通过 libcurl 的 ngtcp2/nghttp3 和
  OpenSSL QUIC（nghttp3 会填充我方解码器的表）。新增 fuzz 目标 `qpack_dynamic`；`h3_frame` 和
  `h3_request` 覆盖 QPACK 流、被阻塞的字段段、extended CONNECT 和流式读取器。
- 编码器关闭时的 HTTP/3 吞吐：`quic-bench h3` 同轮 A/B 为不含这些功能的版本的 1.025 倍（gpu51 上
  88.13 万 vs 85.96 万 请求/秒，两次各 7 轮交替：1.024 倍和 1.027 倍，14 轮全部更快），每请求少约
  300 条指令（x86 callgrind）。完整到达的请求或响应（一个 HEADERS 帧、至多一个 DATA 帧）不经帧读取器
  和每流状态直接读取，客户端在加锁前解码；请求截止时间按 token 下标索引队列而不再哈希；请求在已持有的
  锁下直接打开流。两端都开启 QPACK 编码器时在该
  基准上慢 18%（请求很小，每个都要确认一次），这正是编码器默认关闭的原因。

### 变更：处处安全默认值、不阻塞事件循环的 I/O、更精简的热路径（ADR-009，docs/rules.zh-CN.md）

新的开发规则（docs/rules.zh-CN.md，改编自 fit）：绝不阻塞 I/O 线程、消息体流式且有界、背压联动、处处有超时和
带安全默认值的上限、热路径上构建时优先于请求时、验证与改动相称。代码已按这些规则审查；下列每个上限都有安全
默认值，0 / `None` 仍是显式的关闭方式。

**引擎（only-core、事件循环、only-tls）**
- `Config::write_timeout` 60 s（原为 `None`）；`Config::udp_max_peers` 65536（原为 `None`）；新增
  `Config::connect_timeout`（10 s），用于 epoll、kqueue 和 io_uring 上的 `Engine::dial`。
- 新增 `Config::max_pending_responses`（32）：排在未完成响应之后的流水线响应会暂停读取（并计入写水位线 /
  `max_queued_bytes`），不再无限堆积。
- TLS 握手超时：`ServerConfigBuilder::handshake_timeout` / `ClientConfigBuilder::handshake_timeout`
  （10 s），由事件循环通过新的 `Transport::handshake_timeout` 执行。
- 热路径：cork 状态改为原子量，无人等待时跳过 drain 锁，命令队列保留容量；每个流水线请求的无竞争加锁操作
  约从 7 次降到 4 次。

**HTTP 服务端（only-http）**
- `HttpConfig::head_timeout` 10 s（slowloris；408）、`keep_alive_timeout` 75 s、`body_timeout` 60 s；
  HTTP/2 的 preface/SETTINGS 截止时间和空闲 GOAWAY。
- HTTP/2 Rapid Reset 与洪泛预算：`H2Config::max_resets`（每 30 s 100 次，含 MadeYouReset）、
  `max_control_frames`（每窗口 1000）→ GOAWAY ENHANCE_YOUR_CALM；所有流合计的 `max_conn_pending_bytes`
  （32 MiB）。
- 静态文件只在线程池上访问磁盘（16 线程、4096 排队，满时 503）；缓存命中留在 I/O 线程，压缩副本（及其不存在）
  被缓存，响应头每个条目只格式化一次，缓存分为 16 个 RwLock 分片。
- 请求路径：每个路由请求不再增减共享 `Arc`，405 的 `Allow` 预先计算，带消息体的请求只路由一次，metrics 的
  `in_flight` 按分片，响应过滤器内联存放，CORS / compress / limiter / csrf / request_id 不再每请求格式化或
  使用全局锁。流水线 HTTP/1.1 和 h2c 约 +3–4%（同一轮 A/B），普通 HTTP/1.1 在 1% 以内。

**HTTP 客户端（only-http、only-h3）**：HTTP/1 响应头 64 KiB、消息体 64 MiB、请求超时 30 s、空闲连接池每主机
32 个 / 总计 256 个、空闲 90 s 过期；HTTP/2 在缓冲前检查帧大小，头块上限 2 × `max_header_list`，消息体 64 MiB，
每个请求最多 32 个 push；HTTP/3 消息体 8 MiB、字段段 64 KiB、请求超时 30 s。新增 `ClientError::TimedOut` /
`TooLarge`、`H3Error::TooLarge`。

**gRPC 与 arpc**：全局 `Mutex<Vec>` 截止时间线程被可取消、分片的截止时间服务取代（带截止时间的调用：gRPC ×17、
arpc ×278 调用/秒；不带：+1%）。`grpc-timeout` 限制在 `GrpcServer::max_deadline`（24 h）以内，
`GrpcClient::default_timeout`（30 s），`max_collect_bytes`（64 MiB）；arpc `Routes::max_streams_per_conn`
（1024）和 `call_timeout`（30 s）；每条消息更少的复制和加锁。

**WebSocket、媒体、WebRTC**：压缩（permessage-deflate）消息也受限（关闭码 1009）；帧头在栈上编码、缓冲区复用
（1 KiB 普通回显 +7–11%）。RTMP 分块读取器原地解析（原为 O(n²) 复制），未完成消息上限 32 MiB；没有关键帧时
HLS 分段在 `max_bytes` 处切分；hub 每路径 1024 个流 / 1000 个订阅者，WHIP 256 个会话，SRT 1024 个连接，RTMP
握手 10 s / 空闲 60 s，RTSP 会话超时被执行（60 s）且请求超时 10 s；`RtcServer` / `Endpoint::max_peers`（1024）。

**QUIC、HTTP/3、KCP**：每流（4 MiB）和每连接（16 MiB）的 QUIC 发送缓冲区上限，配合 `Error::Overloaded` 和
`QuicHandler::on_stream_writable`；`receive_window` 10 MB（原为不限）；`ServerConfig::max_connections`
（10,000，无状态 CONNECTION_REFUSED）。HTTP/3 文件消息体只在流有空间时在线程池上读取。KCP `max_sessions` 4096
和 `KcpHandler::on_writable`。在 4 MiB 每流默认值下 QUIC 单流批量传输 −2.7%。

**SOCKS、mux、TURN、BitTorrent、log、DTLS**
- SOCKS / HTTP CONNECT：**目标地址默认只允许公网**（解析后拒绝回环、私网、链路本地、CGNAT、组播和保留地址，
  包括映射形式；BIND 和 UDP ASSOCIATE 同样适用）；握手 10 s、空闲 5 min、早期数据上限 256 KiB、CONNECT 的
  DNS 在有界线程池上解析。
- only-mux 嗅探超时 5 s。TURN 分配按客户端分片（中继吞吐约 140k → 513k 数据报/秒）。BitTorrent tracker 的 DNS
  移出 I/O 线程，tracker 服务端 10 万个 swarm / 每 swarm 1000 个对端并带淘汰，uTP 入站表 1024。only-dtls 在
  cookie 交换前限制重组缓冲。
- only-log：可选的 `FmtLogger::non_blocking`（有界队列，满时丢弃并计数）；默认仍为同步。

### 新增：HTTP 与 WebSocket 客户端的重定向、超时、代理、系统根证书（ADR-010）

- 重定向，需显式开启：`client::RedirectPolicy`（默认 `none()`、`limit(n)`、`allow_https_downgrade`），
  配合 `Client::with_redirects`。跟随 301/302/303/307/308，方法与请求体遵循 RFC 9110 第 15.4 节，支持相对
  `Location`，重定向到其他源时删除 `Authorization` / `Cookie` / `Proxy-Authorization`，默认不跟随
  https → http，超过上限时返回 `ClientError::TooManyRedirects`；`ClientResponse::url` 是最终应答的 URL。
  WebSocket 握手通过 `DialOptions::max_redirects`（默认 0；`WsClientError::TooManyRedirects`）跟随重定向。
- 单请求超时：`ClientRequest::timeout` / `.timeout(d)` 与 `Client::with_timeout`，覆盖解析、连接、TLS、
  响应与重定向（`ClientError::Timeout`，连接被关闭）。`H2Client` 通过重置流来遵守它。
- 在调用线程之外解析域名：新增 `only::dns::resolve`（无依赖的解析线程池，最多 4 个线程；IP 字面量直接应答），
  HTTP/1 与 WebSocket 客户端使用它。
- 系统根证书：`only::tls::RootCerts::system()`（`SSL_CERT_FILE` / `SSL_CERT_DIR`、通过 `/usr/bin/security`
  读取 macOS 钥匙串、Linux/BSD 的 CA 证书包与目录）。**行为变化：**没有 `with_tls` 的 `Client` 和
  `DialOptions::tls = None` 现在对 `https://` / `wss://` 使用它，而不是报错。
- HTTP 代理：`only_ws::proxy::Proxy`（在 `only_http::client::Proxy` 重新导出；`all`、`http`、`https`、
  `no_proxy`，以及需显式调用的 `from_env`，读取 `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`）、
  `Client::with_proxy`、`DialOptions::proxy`。`http://` 用绝对形式，`https://`、`ws://` 和 `wss://` 经
  `CONNECT`；代理 URL 中的凭据变成 `Proxy-Authorization: Basic`；被拒绝时是携带 `ProxyRefused` 的
  `io::Error`。
- 客户端所在 engine 优雅停机时，WebSocket 客户端以 1001（going away）关闭已打开的连接（以前以 1006 结束）。

### 新增：SOCKS5 BIND 与 UDP ASSOCIATE、SOCKS 访问控制钩子、`Engine::adopt_tcp`

- `only-socks` 支持 SOCKS5 `BIND` 与 `UDP ASSOCIATE`（RFC 1928），默认均关闭
  （`Socks::bind(true)`、`Socks::udp_associate(true)`；`bind_timeout`、`udp_idle_timeout`）。
  UDP：每个关联一个转发 socket（engine 需要 `udp_client_threads`），按 IP 和端口识别客户端，丢弃
  分片，只转发来自客户端发送过的目的地的应答，随控制连接或空闲超时结束。BIND：在代理地址上监听，
  两次回复，接受到的连接带背压转发。
- `Socks::allow(|request| ..)`：覆盖 `CONNECT`（SOCKS5/4/4a）、`BIND`、`UDP ASSOCIATE` 以及每个 UDP
  目的地的访问控制钩子，新增 `Command`、`Dest`、`Request` 类型。拒绝时回复 2（SOCKS4：0x5b）或丢弃
  数据报。
- `Engine::adopt_tcp(stream, acceptor, on_error)` 把在 engine 之外 accept 的 TCP 流当作拨号连接来
  服务（epoll 与 io_uring）。
- 互操作：`tools/interop/socks/run.sh`（curl、PySocks、BIND 与 UDP 边界情况；以 Dante 作为参考
  服务器）。ADR-012。新增 API（`api/only-socks.txt`、`api/only.txt`）。

### 新增：`ONLY_LOG` 过滤指令与编译期日志级别上限

- `only::log::Filter`：从 env_logger 风格的指令（`info,only_http=debug,only_quic::conn=trace,only_http::access=off`）
  得到按 target 的级别，只解析一次。`only::log::init_from_env(default)` 安装按 `ONLY_LOG` 过滤的格式化
  logger；需显式调用，否则没有代码读取环境变量。`FmtLogger::filter` / `init_filtered` 接受在代码中
  构造的过滤器。
- only-log 的 cargo feature `max_level_*` / `release_max_level_*` 与 `STATIC_MAX_LEVEL`，与 `log`
  crate 相同：超出上限的语句被编译掉。不开启时生成的代码不变（禁用的 `trace!`：x86_64 上
  0.400 → 0.401 ns，macOS 上二进制相同）。ADR-012。新增 API（`api/only-log.txt`）。

### 新增：共享的 0-RTT 防重放存储（only-tls）与兼容版本协商（only-quic）

新增 API（ADR-013，docs/adr/013-shared-anti-replay-and-compatible-vn.zh-CN.md）：

- **`AntiReplayStore`**（only-tls）：服务端记录已接受早期数据的 ClientHello 的地方。只有一个方法
  `check_and_insert(binder, ttl) -> io::Result<bool>`，须为原子操作，只针对本会接受早期数据的 ClientHello 在
  握手路径上调用。出错时**失败即关闭**（拒绝早期数据，客户端在握手后重发）。默认实现 `MemoryAntiReplay`（即原有
  的每配置一份、有界的记录，10 万条）现已公开。`ServerConfigBuilder::anti_replay_store(Arc<dyn AntiReplayStore>)`
  接入共享存储（Redis `SET key 1 NX PX ttl`，示意见本书 TLS 章节）；`ServerConfigBuilder::session_ticket_key([u8; 48])`
  让多个进程或多台机器上的服务端能接受彼此的票据。QUIC 服务端经由其 TLS 配置获得这两项。已接受的 ClientHello 现保留 30 秒（原为 20 秒）：10 秒新鲜度窗口的两倍，再加一个窗口
  容许共享存储的服务端之间时钟有偏差。
- **兼容版本协商**（only-quic，RFC 9368 第 4 节）：`ServerConfig::prefer_version(Version)` 让以另一版本开始、
  并在 version_information 中列出偏好版本的客户端在握手内切换过去，不多花往返；ClientHello 跨多个包、Retry
  之后以及 0-RTT 时同样可用（0-RTT 包保持客户端的首个版本，RFC 9369 第 4.1 节）。默认关闭：服务端用客户端的
  版本应答。only-quic 客户端总会跟随这种切换（无法解密的、伪造的另一版本 Initial 不会让它切换）。
- 测试：共享票据密钥与“远程”存储的两台 TLS 服务端拒绝从一台重放到另一台的 ClientHello（各自记录时则被接受），
  存储失败时拒绝早期数据，在模拟链路上对 QUIC 做同样的检查；模拟链路上的兼容协商（无额外往返、Retry 加 15%
  丢包、跨两个包的 ClientHello、跨切换的 0-RTT、v2 切到 v1、无偏好或客户端列表无 v2 时不切换、伪造的 Initial）。
  Fuzz：`quic_conn` 的连接对现在会切换到 v2，`tls_server` 也会运行 ClientHello 预读。互通：新增
  `tools/interop/quic/ngtcp2-cvn.sh`，在 Docker 中与实现了 RFC 9368 的 ngtcp2 1.11 双向验证（其客户端被 only-h3
  切到 v2，含 0-RTT；only-quic 被其服务端切到 v2 与 v1）；quic-go 未实现 RFC 9368，因此
  `tools/interop/quic/run.sh` 检查其客户端在偏好另一版本的服务端上保持原版本。
- 代价：未测出（BENCHMARKS.zh-CN.md，握手 A/B）。

### 变更：QUIC 会话票据与令牌绑定到 QUIC 版本（only-tls、only-quic）

RFC 9369 第 5 节（ADR-014，docs/adr/014-quic-version-bound-resumption.zh-CN.md）：

- 会话票据或 NEW_TOKEN 令牌属于签发它的连接所用的 QUIC 版本，兼容版本协商之后即协商出的版本。服务端只用
  客户端起始版本的票据恢复会话（其他版本的票据走不带 0-RTT 的完整握手），也只用该版本的令牌验证地址；
  Retry 令牌同样绑定版本。
- 客户端绝不在 v2 中出示 v1 的票据或令牌，反之亦然：只要自己支持，就以该服务端最新票据（没有票据时看
  令牌）的版本开始，而不是 `ClientConfig::version`。配置为 v1、被偏好 v2 的服务端切到 v2 的客户端，下次
  直接以 v2 开始并带 0-RTT 恢复，无需切换。
- 升级：此前签发的票据与令牌未绑定版本，QUIC 服务端不再接受（每个客户端多一次完整、地址未验证的握手）。
  TCP 上的 TLS 不受影响（格式 2 的会话仍可解码）。公开 API 无变化（隐藏的 `only_tls::quic` 接口新增
  带版本的构造函数）。
- 测试：only-tls 按版本区分票据（出示、拒绝、由 `set_ticket_version` 改版本、未绑定的握手互不使用）；
  only-quic 按版本校验令牌；模拟链路上被切到 v2 的客户端以 v2 带票据、令牌与 0-RTT 恢复，v1 的票据不在
  v2 中使用。互通：`tools/interop/quic/ngtcp2-cvn.sh` 另外检查 ngtcp2 1.11 的客户端（它对被切到 v2 的
  连接得到的票据仍以 v1 重新开始）得到完整握手，以 v2 开始时带 0-RTT 恢复（跨切换的 0-RTT 仍有检查，
  使用共享票据密钥的孪生端口签发的 v1 票据）。

### 变更：没有 AVX-512 IFMA 的 CPU 上 Poly1305 使用 AVX2

在没有 AVX-512 IFMA 的 x86_64 CPU（Zen 2 与 Zen 3、大多数 Intel 客户端处理器）上，only-crypto 的 Poly1305（因而
ChaCha20-Poly1305）对 512 字节及以上的连续分组在 AVX2 上以 2²⁶ 为基数每步吸收四个分组，原先是标量循环。在 Zen 4 上
通过 AVX2 路径测量：ChaCha20-Poly1305 加密 16–64 KiB +20%，1 KiB +7%（docs/BENCHMARKS.zh-CN.md）。有 IFMA 的 CPU
与 512 字节以下的消息不变。公开 API 无变化。

### 新增：静态文件多区间响应、打开文件缓存淘汰、段内部分匹配路由

- `files::Files` 对多个区间（`Range: bytes=0-9,500-599`）返回 `206` 与 `multipart/byteranges` 响应体
  （RFC 9110 14.6 节），各部分按请求顺序排列。重叠的区间及相距不足 80 字节的区间会被合并（14.2 节）；
  超出文件末尾的区间被丢弃，全部丢弃时才返回 `416`；超过 32 个区间、或各部分合计超过 1 MiB 的请求头会被
  忽略，直接发送整个文件。`If-Range` 与单区间时一样生效。格式错误的区间仍返回 `416`。
- 打开文件缓存（`Files::max_open_files`）满时淘汰最近最少使用的句柄（CLOCK），不再对新文件不经缓存直接
  发送；能发现被 rename 覆盖的文件（除大小与修改时间外还比较设备号与 inode），并移除已删除文件的条目。
- `Router` 模式可在一段内混合字面文本与参数：`/{name}.txt`、`/v{major:[0-9]+}.{minor}`、
  `/{owner}/{repo}.git`（ADR-007）。匹配为线性、段内不回溯；优先级为 静态 > 部分段 > 正则 > 参数 > 通配。
  查找仍不分配内存。含 `{…}` 组的静态段现在是模式，花括号不配对时注册即 panic。

无公共 API 变化（`api/only-http.txt` 不变）。

### 新增：TLS record_size_limit、证书压缩与 OCSP stapling（only-tls）

增量配置（ADR-008，docs/adr/008-tls-extensions.zh-CN.md）：

- **record_size_limit**（RFC 8449，TLS 1.3 与 1.2）：`ServerConfigBuilder::record_size_limit` /
  `ClientConfigBuilder::record_size_limit`（64 到 16385，默认 16385）。客户端总是发送自己的值，服务端在客户端
  发送时回以自己的值；之后双方写出的受保护记录按对方的限制切分，收到超过自己限制的记录报 `record_overflow`。
  早期数据遵循签发票据的那条连接上的限制。QUIC 中不使用。对端限制小于 16 KiB 时拒绝（实验性的）内核 TLS 卸载。
- **证书压缩**（RFC 8879，TLS 1.3，zlib 由 only-deflate 提供；没有自研 brotli/zstd，因此只提供 zlib）：两个构建器
  上的 `certificate_compression(bool)`，**服务端默认开启**（证书链只压缩一次并复用，每次握手无额外开销），
  **客户端默认关闭**（解压收到的证书链约需 1–2 µs，约为内存中握手的 1%）。服务端的 CertificateRequest 提供压缩时
  客户端证书也会压缩。收到的消息最多解压到 128 KiB，长度必须与声明的一致。
- **OCSP stapling**：`ServerConfigBuilder::ocsp_response(der)` / `sni_ocsp_response(name, der)` 为请求它的客户端
  装订 DER 响应（TLS 1.3 放在 CertificateEntry 中，TLS 1.2 用 CertificateStatus；会话恢复时不发送）；
  `ClientConfigBuilder::ocsp_stapling(true)` 请求响应，新增的 `TlsInfo::ocsp_response` 保存收到的响应。**不做验证**
  （only-x509 尚无 OCSP）；服务端只检查配置的值在结构上是成功的 `OCSPResponse`。
- ClientHello 现在带有 record_size_limit（6 字节）。`only-tls` 依赖 `only-deflate`。
- 修复：长度不对的 TLS 1.3 KeyUpdate 报 `decode_error`（原为 `illegal_parameter`；tlsfuzzer 的
  “large KeyUpdate message” 探测会随机失败）。
- 测试：带扩展的内存矩阵（两个版本、各密钥类型、双向低至 64 字节的限制、任一方关闭压缩、带 SNI 与会话恢复的
  OCSP）、反例、fuzz 语料；互通（`tools/interop/tls/run.sh`）覆盖 OpenSSL（OCSP 由 s_client 验证，与 Debian 的
  OpenSSL 3.5 双向 zlib 压缩，忽略 max_fragment_length）、Go（双向 OCSP）与 GnuTLS（双向 record_size_limit 与
  OCSP）；tlsfuzzer 的 `test-record-size-limit.py`、`test-tls13-certificate-compression.py` 与
  `test-tls13-client-certificate-compression.py`。握手性能不变（同批 A/B，docs/BENCHMARKS.zh-CN.md）。

### 新增：可插拔的指标收集器（ADR-015）

应用与协议指标出现在 engine 的 `/metrics` 端点上，不依赖第三方 crate。新模块 `only::metrics`
（`only_core::metrics`）：`Collector` trait、`Families` 快照（Prometheus 文本 0.0.4 或 JSON，或通过
`iter` / `get` 读取）、度量工具 `Counter`、`Gauge`、`Histogram` 与具名工具的 `Registry`、`fn_collector`、
`DEFAULT_BUCKETS`。`Telemetry::register_collector(collector, labels)` / `unregister_collector`、
`Telemetry::collect` 与 `Telemetry::render_prometheus`（先 engine 序列，再收集器），`observe::metrics_handler`
现在输出后者。现成的收集器：only-http `HttpMetrics`（新增族 `only_http_requests_by_version_total{version}`、
字段 `HttpSnapshot::by_version`、`observe::VERSION_LABELS`）、only-quic `QuicServer`（`only_quic_*`：连接、
两个方向的数据报与字节、发送与丢失的包、拥塞事件；总数包含已关闭的连接）以及 only-tls `Tls::stats()` →
`TlsStats` / `TlsCounts`（`only_tls_handshakes_total{side, version}`、`only_tls_resumed_total`、
`only_tls_early_data_total{outcome}`）。只有新增 API；engine 自身的序列不变。示例：
`cargo run -p only-http --example guide-metrics`。

在安静主机上测量了 engine 遥测的开销（同一轮 A/B，docs/BENCHMARKS.zh-CN.md“遥测开销”）：HTTP/1.1
上没有可测的开销（关闭回调计时或把计数器编译掉为 0.998–1.006×）；echo 各行在噪声之内。带新版本计数的
`HttpMetrics::middleware()` 为原中间件的 0.997–1.005×。

### 变更：AVX-512 上短消息的 ChaCha20-Poly1305 更快

在具备 AVX-512 的 x86_64 上，only-crypto 的 ChaCha20 处理四个分组时每个寄存器存放每个分组的一行（用于消息开头与
短尾部），不完整的最后一组在字节掩码下直接经内核处理而不经缓冲区，并按实测内核耗时为开头选四个或八个分组；
AEAD 的 Poly1305 不再经过流式缓冲区。Zen 4，同批 A/B：加密 64 B 408 → 481 MB/s（ring 的 0.83 倍 → 0.98 倍），
1 KiB 1.00 倍 → 1.08 倍，1400 B 0.99 倍 → 1.21 倍；解密 64 B 0.76 倍 → 0.85 倍；1 KiB 的 TLS 1.3
ChaCha20-Poly1305 记录相对 rustls + ring 1.09 倍 → 1.15 倍（docs/BENCHMARKS.zh-CN.md）。16 KiB 及以上不变。
公开 API 无变化。

### 变更：RSA 验签在 AVX-512 IFMA 上计算，约快 2.5–3.4 倍

在支持 AVX-512 IFMA 的 x86_64 上，RSA 公开运算 `sᵉ mod n`（验签，以及每个签名发出前的校验）对 2048、3072 与
4096 位模数改为以 2⁵² 为基数计算（新增 3072 与 4096 位的几乎 Montgomery 乘法），`e = 65537` 只需 18 次乘积
（原为 21 次）；构造公钥时用更快的长除法求 `R² mod n`，不再做 Montgomery 乘法。Zen 4，空闲机器上同一次运行的
A/B 对比：RSA-2048 / 3072 / 4096 PKCS#1 验签快 2.51 / 3.00 / 3.39 倍（ring 的 1.22 / 1.10 / 1.09 倍 → 3.07 /
3.30 / 3.70 倍），含密钥解析的验签快 2.31 / 2.76 / 3.04 倍（1.02 / 0.95 / 0.95 倍 → 2.35 / 2.64 / 2.90 倍），
签名快 2–4%；使用 RSA-2048 证书的 TLS 1.3 握手为 rustls + ring 的 1.67 倍 → 1.82 倍（docs/BENCHMARKS.zh-CN.md）。
没有 IFMA 时（以及 `ONLY_CRYPTO_PORTABLE=1`）更少的乘积与更快的除法同样有效：2048 位可移植验签为 ring 的
0.59 倍 → 0.70 倍。私钥模幂及其常数时间性质不变。没有公共 API 变化。

### 变更：每个 HTTP/3 请求的内存分配更少

`quic-bench h3` 两端合计，一个 HTTP/3 请求及其响应的分配次数从 21.6 降到 8.6：only-quic 把流数据交给应用时
不再经过临时向量；only-h3 把较小的响应头与请求头写进 only-quic 的每线程池化缓冲区（隐藏的 `Bytes::pooled`，
不是公共 API），并原地加宽 HEADERS 帧的长度字段；only-http 的 `Context` 自己持有请求，直到 `Detached` 或
WebSocket 升级需要共享它，`Headers` 内联保存前两个字段的位置（仍是 48 字节）。QPACK 写 `:status`、
`content-length` 与 date 行（每秒编码一次）时不再查静态表，请求头只做一次 UTF-8 检查。Zen 4，空闲机器上同一次
运行的 A/B 对比：HTTP/3 GET，单连接，64 个并发 820,741 → 883,127 请求/秒（1.08 倍）；HTTP/1.1 与 h2c 在噪声
范围内不变（docs/BENCHMARKS.zh-CN.md）。没有公共 API 变化。

### 修复：`only_bittorrent::Client::close` 等待其线程退出

TSan 的首次运行（见下）报告了一处线程泄漏：`close` 关闭引擎与磁盘线程池后立即返回，因此之后 I/O 线程回调与 `Storage` 调用仍可能执行，而丢弃 client 会使这些线程脱离（detach）。现在 `close` 在引擎的 I/O 线程、磁盘线程池与维护线程都退出后才返回，因此不能在 client 自己的线程中调用（例如在 `Storage` 方法内）。

### 修复：HTTP 客户端不再拖住引擎的优雅关闭

`only_http::client::Client` 在引擎优雅关闭期间仍把空闲的 keep-alive 连接留在连接池中，因此只要客户端发过请求，`Engine::wait` 就要等满整个 `Config::shutdown_timeout`（默认 10 秒）。现在空闲连接在关闭开始时立即关闭；有请求在途的连接先交付响应，然后关闭而不再放回连接池。

### 新增：AddressSanitizer 与 ThreadSanitizer 运行（`tools/sanitizers/`）

2026-11-16 首次用 ASan（含 LeakSanitizer）与 TSan 运行工作区测试：所有 crate 在 Linux arm64 Docker 中覆盖 epoll 与 io_uring，含 unsafe 代码的 crate 与引擎后端在 x86_64 上运行（包括 AVX-512/IFMA/VAES/BMI2 汇编路径）。没有内存错误、内存泄漏或数据竞争；上述线程泄漏是唯一的报告。`tools/sanitizers/run.sh` 按 crate 运行，可在 Docker 中或原生运行；重型 CI 任务 `sanitizers` 现在用它覆盖整个工作区，而不是原先的八个 crate。其中的 `rustc-wrapper.sh` 让 `compiler_builtins` 不插桩构建，否则在 aarch64 上使用 `-Zbuild-std` 时所有插桩二进制都会在启动时崩溃。为 TSan 调整了两个测试：`only-sys` 的 `signal_to_pipe` 改为在等待的线程上触发信号（信号若落在阻塞于裸 futex 等待的线程上，TSan 永远不会执行其处理函数），only-ws 的客户端测试按 `ONLY_TEST_TIMEOUT_SCALE` 缩放其 10 秒期限。

### 变更：RSA 签名在同一个 AVX-512 IFMA 循环中计算 CRT 两半

在支持 AVX-512 IFMA 的 x86_64 上，RSA 私钥运算的两个半模幂（模 p 与模 q）现在同步推进：同一个汇编循环的
每次迭代各推进一个数字步，两条串行约简链因此重叠，不再各自等待。Zen 4，空闲机器上同一次运行的 A/B 对比：
RSA-2048 PKCS#1 签名 3,867 → 5,231 次/秒（ring 的 1.63 倍 → 2.20 倍），RSA-3072 1,436 → 1,691（2.19 倍），
RSA-4096 753 → 870（2.55 倍）；使用 RSA-2048 证书的 TLS 1.3 握手为 rustls + ring 的 1.45 倍 → 1.69 倍
（docs/BENCHMARKS.zh-CN.md）。验签、其他 CPU 以及两个素数位数不同的密钥不变。仍是常数时间（没有依赖秘密数据的
分支，已在反汇编中检查）。没有公共 API 变化。

### 变更：TLS 记录加密和解密前不再预先清零输出

TLS 记录层在 AEAD 写入记录的密文或明文之前不再清零那段空间：only-crypto 的 AES-GCM 与
ChaCha20-Poly1305 新增隐藏的 `encrypt_append` / `decrypt_append`，直接写入 `Vec<u8>` 的空闲容量（经由一个
很小的 `unsafe` 模块 `only_crypto::fill`，只有每个字节都写入后才扩展向量；打开失败时不追加任何内容，并把已写
的字节清零）。only-tls 仍是 `#![forbid(unsafe_code)]`。Zen 4 上的 TLS 1.3 记录（加密 + 解密，同一次运行
A/B）：AES-128-GCM +6.9–8.3%，AES-256-GCM +7.4–8.7%，ChaCha20-Poly1305 +3.3–6.4%（docs/BENCHMARKS.zh-CN.md）。
公开 API 不变。

### 新增：供应用自建转发使用的 `Conn::set_relayed`

基于 `hold_reads` / `on_drain` 自建的转发现在可以用 `Conn::set_relayed(true)` 跳过引擎按写水位暂停
读取的行为（`CONNECT` / 协议升级后的转发用 `only_http::raw::RawConn::set_relayed`）。否则，转发到
只有能写时才读的对端会死锁：与 only-socks 内部已修复的问题相同，现在应用代码也能避免。立即生效；
`Config::max_queued_bytes` 仍然适用。公开 API 为增量（快照已更新）。

### 更名：项目现在叫 `only`

crates.io 上的 `flash` 名称已被占用，因此项目从 **flash** 更名为 **only**（DEV-PLAN“1.0.0 发布决定”）。
所有 crate、路径、标识符与名称随之改变；下面的条目已经使用新名称。

| 之前 | 之后 |
|---|---|
| crate `flash`（`use flash::...`） | `only`（`use only::...`） |
| crate `flash-*`（代码中为 `flash_*`），目录 `crates/flash-*` | `only-*`（`only_*`）、`crates/only-*`：`flash-sys` → `only-sys`、`flash-buf` → `only-buf`、`flash-timer` → `only-timer`、`flash-pool` → `only-pool`、`flash-core` → `only-core`、`flash-epoll` → `only-epoll`、`flash-uring` → `only-uring`、`flash-tls` → `only-tls`、`flash-http` → `only-http`、`flash-ws` → `only-ws`、`flash-mux` → `only-mux`、`flash-socks` → `only-socks`、`flash-arpc` → `only-arpc`、`flash-grpc` → `only-grpc`、`flash-kcp` → `only-kcp`、`flash-quic` → `only-quic`、`flash-h3` → `only-h3`、`flash-ebpf` → `only-ebpf`、`flash-prefork` → `only-prefork`、`flash-dpdk` → `only-dpdk`、`flash-turn` → `only-turn`、`flash-webrtc` → `only-webrtc`、`flash-media` → `only-media`、`flash-bittorrent` → `only-bittorrent` |
| 环境变量 `FLASH_*`（`FLASH_TEST_BACKEND`、`FLASH_UDP_GSO`、`FLASH_UDP_GRO`、`FLASH_PREFORK_*`、`FLASH_CHAOS*`、`FLASH_DPDK_*` 等） | `ONLY_*` |
| Prometheus 指标 `flash_*`（`flash_connections_open`、`flash_http_requests_total`、`flash_tls_handshake_failures_total` 等） | `only_*` |
| 日志 target `flash`、`flash_http::access`、`flash_webrtc` 等 | `only`、`only_http::access`、`only_webrtc` 等 |
| 线程名 `flash-io-*`、`flash-pool`、`flash-quic-timer` 等 | `only-io-*`、`only-pool`、`only-quic-timer` 等 |
| `flash_media::srt` 中的别名 `FlashConn` | `OnlyConn` |
| API 快照 `api/flash-*.txt`、工具的 Docker 镜像与卷 `flash-*` | `api/only-*.txt`、`only-*` |

在仓库本身改名之前，GitHub 仓库与文档站点仍使用 `lesismal/only` 的 URL。

### 评估：io_uring 注册文件、`SEND_ZC`、`MSG_RING` 唤醒、基于 ring 的发送（未采用）

- 在 Linux 7.0 / Ryzen 7 7800X3D 上按“同一轮内提升至少 3%、其他场景不退步”的规则测量
  （docs/BENCHMARKS.zh-CN.md，“io_uring 特性评估”）；没有一项达标，因此 io_uring 后端保持不变。`SEND_ZC`
  在 16 KiB 到 256 KiB 时慢 12–27%，每请求 CPU 多 10–36%（回环总是拷贝）；没有 ring 的线程发出的
  `MSG_RING` 唤醒（`IORING_REGISTER_SEND_MSG_RING`）在 `spawn_blocking` 往返上 +1.5–4.8%，其他场景
  −1.3% 到 +0.2%；注册 ring fd 为 −3.6% 到 +0.5%；注册文件在引擎中没有可节省的东西（稳态下每个请求
  不提交任何条目）。基于 ring 的发送（`IORING_OP_SEND`）在裸 ring 上 +1–4%、每请求 CPU 少 2–6%，但需要
  重新设计共用的写路径（写来自任意线程），留作后续工作。
- 新的测量工具：only-uring 中被忽略的 `eval_server` 测试（`src/eval.rs`，直接在 ring 上运行的最小
  HTTP/1.1 应答程序：`write` / `SEND` / `SEND_ZC`，可选 direct accept 与注册文件）以及
  `tools/bench/uring-eval.sh`。它用到的额外 io_uring 绑定（`SEND`、`SEND_ZC`、direct accept、固定文件
  close、稀疏 `REGISTER_FILES`、`MSG_RING` 与 `REGISTER_SEND_MSG_RING`）只在测试中编译。公共 API 不变。

### 新增：TLS 1.3 早期数据与 QUIC 0-RTT（需显式开启，带防重放）

- **`only-tls`**：早期数据（RFC 8446 第 4.2.10 节），双方默认关闭。
  `ServerConfigBuilder::early_data(max_bytes)` 签发带 `max_early_data_size` 的票据，并在票据的第一个
  PSK、密码套件、ALPN 协议与 SNI 名都一致时接受早期数据（HelloRetryRequest 之后绝不接受；超量为
  `unexpected_message`）；它在握手完成前被读取，以 EndOfEarlyData 结束。`ClientConfigBuilder::early_data(true)`
  把应用在握手前写入的数据作为早期数据发送（不超过票据上限），服务端拒绝时（包括 HelloRetryRequest
  之后）在握手后重发。新增 `EarlyData`（`NotAttempted`、`Pending`、`Accepted`、`Rejected`）与
  `TlsInfo::early_data` / `early_data_len`。
- **防重放**（开启早期数据时始终生效）：票据年龄的 10 秒新鲜度窗口（RFC 8446 第 8.3 节），以及每个
  `ServerConfig` 一份被接受 ClientHello 的 PSK binder 记录，保留 20 秒、上限 100,000 条（第 8.2 节）：
  重放的 ClientHello 其早期数据被拒绝，记录满时拒绝早期数据直到条目过期。不覆盖共享票据的多个进程或
  机器（已在文档中说明）。
- **`only-quic`**：0-RTT（RFC 9001 第 4.6 节），`ServerConfig::zero_rtt` / `ClientConfig::zero_rtt`
  （默认关闭）。恢复会话的客户端从记住的传输参数起步（RFC 9000 第 7.4.1 节），`dial` 后立即打开流并以
  0-RTT 包发送（v1 与 v2），合并在 Initial 之后。服务端只在限额与签发票据时相同的情况下接受 0-RTT，
  以 0.5-RTT 应答；客户端重发被拒或丢失的 0-RTT 数据（Retry 之后以 0-RTT，否则以 1-RTT）。新增
  `Connection::early_data` 与 `Connection::is_early(stream)`。
- **HTTP**：only-h3 给以 0-RTT 到达的请求加上 `Early-Data: 1`（RFC 8470），配置开启时 `H3Client` 以 0-RTT
  发送请求；TLS 上的 only-http 标记作为早期数据到达的 HTTP/1.1 请求（以及以早期数据开始的连接上的每个
  HTTP/2 请求）。处理函数对不能安全重复的请求回 `425 Too Early`。
- 测试：TLS 状态机（接受、拒绝、HelloRetryRequest、重放、过期的票据年龄、ALPN/SNI 绑定、
  `max_early_data` 上限），模拟网络上的 QUIC（接受、拒绝、0-RTT 包丢失、Retry、重放的首批包、v2），
  回环上的 QUIC、HTTP/3 与 TLS 上的 HTTP/1.1。互通：与 quic-go 双向的 v1 与 v2 0-RTT
  （`tools/interop/quic/run.sh`），与 OpenSSL `s_client` / `s_server -early_data` 双向的早期数据，接受与
  拒绝两种情况（`tools/interop/tls/run.sh`）。0-RTT 包与早期数据握手的 fuzz 种子。
- 另外：等待密钥后才处理的包、0-RTT / 0.5-RTT 包不再产生 RTT 样本；在途的 0-RTT 包不会推迟握手的探测
  定时器。
- 安全：早期数据与 0-RTT 没有前向保密，并且可能被单个服务端的记录之外的方式重放；README 与指南说明了
  何时（不）应开启。

### 新增：`only-quic` 的 ECN、BBR、客户端迁移、preferred_address 与 QUIC v2

- **ECN**（RFC 9000 第 13.4 节、RFC 9002 第 7.1 节），`TransportConfig::ecn`（默认开启）：Linux 上
  以 ECT(0) 发送，在 ACK_ECN 帧中报告收到的码点；用十个包的测试期和对端计数验证路径，CE 标记视为
  拥塞事件，清除、改写或丢弃带标记包的路径回退为不带标记发送。新增
  `ConnectionStats::ecn_capable` / `ecn_ce_events`。UDP 层逐个数据报传递码点：接收时用
  `IP_RECVTOS` / `IPV6_RECVTCLASS`，发送时每条 `sendmmsg` 消息带一个 `IP_TOS` / `IPV6_TCLASS`
  控制消息（`only_sys::enable_ecn`、`ecn_available`、`RecvBatch::ecn`、`Batch::push_ecn`；
  `ONLY_UDP_ECN=0` 关闭）。
- **BBR**：`Congestion::Bbr` 不再运行 CUBIC，而是基于投递速率采样的 BBRv1 模型与状态机，加上
  BBRv2/v3 对丢包或 CE 标记超过 2% 的轮次的上限。在测试机上用网络命名空间加 netem（100 Mbit/s、
  40 ms RTT、双向各回显 40 MB）：1% 丢包时 73 对 CUBIC 的 5 Mbit/s，60 个包的缓冲时 75 对 36 Mbit/s，
  干净的深缓冲上都是 84 Mbit/s。实验性。
- **客户端迁移**：`Connection::migrate(&engine)` 把客户端连接迁到新的本地 UDP socket 或服务端的
  首选地址，先用一个未用过的连接 ID 探测新路径；探测无回应时留在原路径。新增
  `Connection::preferred_address()`、`Error::Migration`。
- **preferred_address**：`ServerConfig::preferred_address(addr)` 提供首选地址（连接 ID 序号 1 及其
  重置令牌）；`QuicServer` 现在实现 `Clone`，同一个服务端可在第二个监听器上服务该地址。
- **QUIC 版本 2**（RFC 9369）：`Version`、`ClientConfig::version`、`ServerConfig::versions`、
  `Connection::version()`。服务端接受 1 和 2；收到版本协商包的客户端在双方都支持的版本上重新开始
  一次，并以 RFC 9368 的 version_information 参数防降级。未实现兼容版本协商（在握手中切换版本）。
- 互通（`tools/interop/quic/run.sh`）：与 quic-go 双向的版本 2（停在 quic-go 第一次密钥更新之前：
  quic-go v0.62 对版本 2 的密钥更新用了版本 1 的标签，与 RFC 9369 第 3.3.2 节不符）、双向客户端迁移
  （我方使用 BBR），以及 Linux 上与 quic-go 的 ECN 验证。
- 对来自其他地址的路径探测的回应现在使用单独的连接 ID（RFC 9000 第 9.5 节）；quic-go 的迁移客户端
  需要这一点。
- 未完成：0-RTT。

环回基准上的开销（`quic-bench`，测试机，CPU 2–5，与合并基点交替五轮取中位数）：bulk 18,704 →
18,288 Mbit/s（−2.2%；`ONLY_UDP_ECN=0` 时 −1.5%），HTTP/3 839,148 → 824,949 req/s（−1.7%；
−1.0%），完整握手 9,725 → 9,615/s（−1.1%；−0.8%）。ECN 的部分来自每个数据报的控制消息与 ACK_ECN
计数。

### 评估：内核 TLS 卸载（未采用，实验性 feature）

- 在 Linux 7.0 / Ryzen 7 7800X3D 上用 TLS 上的 HTTP/1.1 测量了握手后把 only-tls 的记录密钥交给 Linux
  内核（kTLS）的方案（`tools/bench/ktls.sh`）：内核的软件 TLS 在 1 KiB 响应时为 only-tls 自己记录层的
  0.83 倍，16 KiB 时 0.65 倍，256 KiB 时 0.40 倍，用 `sendfile` 发送 10 MB 文件对比 only-tls 的 `pread`
  加加密为 0.48 倍，每字节服务器 CPU 为 1.3 到 2.5 倍（docs/BENCHMARKS.zh-CN.md，“内核 TLS（kTLS）
  评估”）。它没有接入 `Tls` 或引擎。
- 卸载代码保留下来以便重新测量，放在 `only-tls` 新增的**实验性** feature `experimental-ktls` 之后（默认
  关闭，不在 semver 承诺之内，无公共 API）：阻塞测试流（`only_tls::stream`，隐藏）可在握手后卸载
  （TLS 1.3 与 1.2，AES-128/256-GCM 与 ChaCha20-Poly1305，告警、close_notify、NewSessionTicket，以及
  Linux 6.14+ 上的双向 KeyUpdate，回退到用户态），并配有 `ktls-bench` 示例、`tls-interop --ktls` /
  `ONLY_INTEROP_KTLS=require tools/interop/tls/run.sh`（对 OpenSSL 与 Go 107/107 通过）以及
  `crates/only-tls/tests/ktls.rs`（没有 `tls` 内核模块时跳过）。`only-sys` 新增隐藏的 `ktls` 模块
  （`TCP_ULP`、`SOL_TLS`、记录类型 cmsg），`linux/tls.h` 的结构体在布局测试中与 `libc` 对照。
- 文档：README、book 的 crate 列表与 fib 迁移指南中过时的“底层为 rustls”说法，以及 ROADMAP 的 TLS 行，
  已改为实际情况（自研 TLS 1.3 / 1.2）。

### 性能：`only-crypto` 中基于 VAES-AVX2 的 AES-GCM，AVX-512 内核内的掩码尾部

公开 API 不变（新增仅供测试与基准测试使用的 `#[doc(hidden)]` `AesGcm::with_cipher_avx2` 与 `AesGcm::kernel`）。

- 具备 VAES、VPCLMULQDQ 与 AVX-512 的 x86_64：整条消息在 512 位内核的一次调用中完成。不超过 256 字节的
  AAD 在内核中做 GHASH，最后一个不完整的组（1 到 255 字节）用 AVX-512 字节掩码加载与存储，不再走 128 位路径，
  长度块与 `E(J0)` 在同一次调用中给出标签；256 字节以下的消息把 AAD、数据与长度块放在一次归约里。
  AES-128-GCM 加密 1 KiB 7,902 → 10,433 MB/s（ring 的 1.00 倍 → 1.32 倍），1400 B 8,356 → 10,632（1.10 倍 →
  1.46 倍），64 B 1,204 → 1,383（1.11 倍 → 1.29 倍）；解密 1 KiB 1.04 倍 → 1.22 倍；16–64 KiB 不变（1.16–1.18 倍）。
- 具备 VAES 与 VPCLMULQDQ 但没有 AVX-512 的 x86_64（Zen 3、Alder Lake / Raptor Lake）：新增 VAES-AVX2 内核，
  每次迭代用 8 个 256 位寄存器处理 16 个分组，每组一次 GHASH 归约，处理完整的 256 字节组（其余部分走 128 位
  路径）。在关闭 AVX-512 内核的 Zen 4 上测得（没有 Zen 3 可用）：为这些 CPU 之前所用 128 位内核的 1.55–2.35 倍
  （AES-128 加密 16 KiB 6,310 → 12,671 MB/s）。
- `only-tls` 的 TLS 1.3 记录随之提升：AES-128-GCM 1 KiB 为 rustls + ring 的 1.51 倍 → 1.58 倍，16 KiB 1.56 倍 →
  1.60 倍。记录层在 AEAD 写入之前仍先把输出清零：把明文复制进来再原地加密在 16 KiB 上慢 6%，复用缓冲区只是把
  memset 换成复制，而跳过清零（16 KiB 快 10%）需要在 `#![forbid(unsafe_code)]` 的 crate 中使用 `unsafe`，因此
  没有这样做（docs/BENCHMARKS.zh-CN.md）。
- 测试：每个内核（AVX-512、AVX2、128 位、可移植）在 0..=600 的每个长度、若干大长度、0..=300 及 512 以上的每种
  AAD 长度上互相比较，覆盖未对齐、原地与非原地，并跑 CAVP 与 Wycheproof 向量；`crypto_aead` 模糊测试目标也比较
  AVX2 内核。在 Zen 4 上原生运行，也设置 `ONLY_CRYPTO_PORTABLE=1` 运行。
- `unsafe`：`gcm::hw` / `gcm::hw::vaes` 增加 5 个块与 1 个 `unsafe fn`（AVX2 内核的两个 `asm!` 块、整条消息的
  调用），见 docs/unsafe-review.zh-CN.md。Miri 永远不会执行到 `asm!`。

### 修复：io_uring 在读取暂停后仍调用 `on_data`

- `only-uring`：连接的输出队列达到 `Config::write_high_watermark`，或处理器调用了
  `hold_reads(true)` 后，后端会取消多次接收（multishot recv），但在取消生效前已到达的完成事件（机器
  快、对端持续灌数据时可达十几个 16 KiB 的读取）仍会交给 `on_data`。echo 类处理器于是越过水位线一直
  排队到 `max_queued_bytes`，得到 `Error::Overloaded`；`hold_reads` 也没有真正暂停读取。这使得在
  16 线程、Linux 7.0 的机器上用 io_uring 运行时 `chaos_engine` 每次都失败（"echo send failed:
  overloaded"）。现在这些输入按顺序留在连接里（其后的 EOF 也一样），读取恢复时再交付，与 epoll、
  kqueue 直接停止读取的行为一致。API 不变。

### 修复：SOCKS 与 HTTP CONNECT 隧道在背压下可能卡死

- `only-socks`：隧道（SOCKS5/4/4a 或 HTTP `CONNECT`）在转发大量数据时可能永久停住。引擎的写背压
  （`Config::write_high_watermark`）在上游连接有排队的客户端数据时会暂停读取该上游，但这些读取的数据
  是发往客户端的，并不进入这个队列。上游如果在自己的写被阻塞时不读（echo 服务器、大多数请求/响应式
  服务器），就会等代理，而代理也在等它。表现为负载较高时 `socks5_ipv4_domain_and_backpressure` 偶尔
  卡住 10 秒（kqueue、epoll 与 io_uring 都会）；先发送再读取的上游则每次都会卡住。现在隧道两端只由
  转发自身的暂停/恢复来调节。各后端（epoll、kqueue、io_uring、DPDK）都遵循新增的隐藏方法
  `ConnInner::set_relayed`。公共 API 不变。

### 性能：`only-h3` 的 HTTP/3 请求处理，`only-quic` 中带密钥的快速哈希

单连接 64 个请求在途的 HTTP/3 GET 从 429,038 升到 838,721 请求/秒（1.95 倍，交替运行七轮取中位数；
AMD Ryzen 7 7800X3D，回环，CPU 2–5）；QUIC 批量传输 +5%，握手持平。profile 中内存分配器从 31.8% 降到
11.2% 的采样，SipHash 从 7.3% 降到 0.1%。API 不变；与 quic-go 和 fib 双向互通测试通过。

- only-h3：请求与响应的帧直接在收到的流数据上原地读取（只缓冲末尾不完整的帧）；字段段解码到一个复用的
  扁平缓冲区，一次性做 UTF-8 校验，再复制一次进请求或响应的 `Headers`；以前每个字段要两个 `Vec`，
  每个名字和值各一个 `String`，外加第二份头部列表。
- only-h3：HEADERS 帧直接用 QPACK 编码进输出缓冲区，`:status`、`date`（每线程每秒格式化一次）和
  `content-length` 直接写在那里，不再先加进响应头；静态表引用按名字长度查找，不再用两个 SipHash
  映射；响应的 HEADERS、不超过 16 KiB 的响应体和 trailer 一次写给 QUIC（更大的响应体随后发送，不复制）。
- only-h3：一次收全的请求不进入流表就读完；流表改用乘法折叠哈希（大小受我们授予的流数量上限约束）。
- only-quic：endpoint 的连接 ID 表、连接表与客户端 socket 表（按对端地址）改用每张表各取新随机密钥的
  哈希（64×64→128 位乘法折叠），不再用 SipHash；客户端可以选择第一个 Initial 的连接 ID，密钥使得
  无法预先算出相互碰撞的 ID。连接 ID 只对实际使用的字节做哈希。单看这一项，批量传输 +3%（每个数据报
  查一次表）；HTTP/3 一个数据报承载许多请求，几乎看不出差别。
- only-quic：按序到达的流确认直接前移发送缓冲区的头部，不再经过已确认区间树（每次确认分配并释放一个
  节点）；流发送缓冲区的第一块数据内联保存，只写一次的流不需要分配队列。
- only-http：`Response::text` 与 `Response::with_body` 一次分配好头部存储，不再逐个字段扩容。

### 性能：`only-crypto` 中基于 AVX-512 与 IFMA 的 ChaCha20-Poly1305，TLS 记录非原地加解密

在 x86_64 上，ChaCha20-Poly1305 加密 16 KiB 为 4,597 MB/s（之前 1,752，ring 的 1.30 倍），1400 B 为
2,541（1,070，ring 的 0.96 倍），64 B 为 412（283，0.83 倍）；使用 TLS_CHACHA20_POLY1305_SHA256 的
TLS 1.3 记录在 16 KiB 时从 rustls + ring 的 0.55 倍提升到 1.42 倍，1 KiB 时从 0.64 倍提升到 1.02 倍
（AMD Ryzen 7 7800X3D；docs/BENCHMARKS.zh-CN.md）。API 不变。

- ChaCha20 在 zmm 寄存器中每次迭代处理 16 个分组，使用 `vprold` 循环移位，消息余下部分用一组 16、8（ymm）
  或 4（xmm）个分组处理，均为 `asm!` 内核（`chacha::hw::avx512`；AVX-512 intrinsic 在 MSRV 上不稳定）。
  没有 AVX-512 的 CPU 仍走 AVX2 路径。
- 对 256 字节及以上的连续分组，Poly1305 在 AVX-512 IFMA 上每步处理 8 个分组（`chacha::hw::ifma`，在 44 位
  limb 上使用 `vpmadd52luq` / `vpmadd52huq`），经 `Feature::Ifma` 检测；其余情况，以及其他 CPU 与 aarch64
  上，用 2⁶⁴ 进制的标量循环替换 44 位两分组循环（AVX2 路径上 16 KiB 快 1.3 倍）。
- `ChaCha20Poly1305::encrypt_detached_from` / `decrypt_detached_from`（`#[doc(hidden)]`，与 AES-GCM 的相同）：
  only-tls 非原地加解密 ChaCha20-Poly1305 记录，不再先复制。`new_avx2` / `new_portable`（`#[doc(hidden)]`）
  把密钥固定在较窄的路径上，供测试、`crypto_aead` 模糊测试目标与 `examples/chacha-sizes.rs`（按长度与 ring
  对比）使用。
- 正确性：0..=600 的每个长度与若干大长度经过 AVX-512 / IFMA、AVX2 与可移植三条路径，覆盖未对齐、原地与
  非原地、伪造标签、接近回绕的计数器，Poly1305 覆盖全 1 分组与极端的 `r` / `s`，在 Zen 4 上分别在设置与不设置
  `ONLY_CRYPTO_PORTABLE=1` 时原生运行。`unsafe`：+6 个块，+2 个 `unsafe fn`（docs/unsafe-review.zh-CN.md）。

### 新增：`only-crypto` 中 P-256 与 X25519 的 aarch64 汇编（尚未做性能测试）

aarch64 上 P-256 的域与群阶运算以及 X25519 阶梯的域运算改用内联汇编（`ec::hw_aarch64`、
`curve25519::hw_aarch64`），与 x86_64 的 BMI2 + ADX 代码对应；API 不变。

- P-256：模 `p` 与模 `n` 的 Montgomery 乘法与平方、加法、减法、`2ᵏ·a` 与 `3·a`，四个 64 位 limb，
  `MUL`/`UMULH` 求积，`ADDS`/`ADCS`/`SUBS`/`SBCS` 进位链，`CSEL` 修正；模 `p` 的约简只用移位与减法（同
  OpenSSL 的 `ecp_nistz256-armv8`），模 `n` 的约简中四个 limb 乘积有两个用移位代替。与 x86_64 一样，`P256`
  分派到建立在这个域上的孪生曲线；求逆是 safegcd（可移植的 divsteps），最后一次乘法用汇编，孪生曲线沿用
  `Curve::jac_*` 钩子的可移植默认实现（点运算公式、查表、4 位梳形表），运行在汇编域运算之上。
- X25519：阶梯的域运算使用四个 64 位 limb（每次乘积 16 个 `MUL` + 16 个 `UMULH`，而 2⁵¹ 进制需要 25 个
  128 位乘积），用 `CSEL` 按 `2²⁵⁶ ≡ 38` 折叠，交换用掩码。
- 所有 ARMv8.0 CPU 都有这些指令：aarch64 上 `hardware_features()` 报告 `umulh`；
  `ONLY_CRYPTO_PORTABLE=1` / `set_portable(true)` 切回可移植实现，Miri 永不执行这些汇编。
- 正确性：在随机值、边界值以及 20,000–50,000 次相互依赖的运算链上与可移植域运算做差分测试，孪生曲线与
  可移植曲线比较（密钥生成、ECDH、签名、验签），RFC 7748 向量（包括 1,000,000 次迭代，`--ignored`）与
  Wycheproof，均在 macOS（Apple 芯片）与 arm64 Linux 上运行。已反汇编秘密路径的 release 代码：汇编中没有
  条件分支，周围代码只有循环计数、公开边界、CPU 特性检查与最后的无穷远点判断。
- **尚未做性能测试**：设计依据指令数；在实测之前不声称 aarch64 上有任何加速。

### 性能：`only-http` 中 HTTP/2 与流水线 HTTP/1 的热路径

在自研替换完成后重新剖析（DEV-PLAN“性能优化”）；API 不变。

- HTTP/2：帧直接在读缓冲区中原地解析（不再每帧复制一次，剩余字节每次读只移动一次）；解码出的头部字段放进
  一个复用的缓冲区，而不是每个字段两个 `Vec`；头部块直接 HPACK 编码进输出缓冲区，`:status`、`date` 与
  `content-length` 也直接写在那里；能放进一个 DATA 帧且不超过流控窗口的响应体不再经过流的发送队列；
  流表用乘法折叠哈希代替 SipHash。
- HTTP/2：一次读所产生的一切（包括服务在 I/O 线程上发出的响应）在这次读处理结束时一次性交给连接写出
  （一批只产生一个 TLS 记录，而不是每个响应一个）；处理读期间其他线程发出的响应并入这一批，其余时候立即发出。
- HTTP/2 流控：连接与流的接收窗口在欠下四分之一时才归还，而不是每个 DATA 帧两个 WINDOW_UPDATE。
- HTTP/1：请求头先按最多 32 个字段解析（只在需要时才用 100 个），分帧所需的字段（`Host`、`Connection`、
  `Content-Length`、`Transfer-Encoding`、`Expect`）一次遍历找出。
- Ryzen 7 7800X3D，服务端 4 个线程（epoll）：h2c 64 连接 × 16 流 2.28M → 4.05M 请求/秒（1.78 倍，
  现为 fib 的 1.25 倍），h2c 16 × 128 2.37M → 4.71M，TLS 上的 HTTP/2 1.58M → 4.03M（2.5 倍，fib 的 1.33 倍），
  HTTP/1.1 流水线 ×16 3.99M → 4.26M（+7%，fib 的 1.14 倍）。h2spec：147/147。表格见 docs/BENCHMARKS.zh-CN.md；
  压测脚本（`tools/bench`，新增 README）在没有 wrk 时用 `h2load --h1` 驱动 HTTP/1.1，并新增了 TLS 上的
  HTTP/2 与多流用例。

### 性能：`only-crypto` 的 CPU 指令加速

`only-crypto` 现在在 CPU 支持时使用 CPU 指令（运行时检测），每条路径都以常数时间的可移植实现作为回退
（DEV-PLAN“性能优化”）；API 不变。

- x86_64：SHA-1 / SHA-256 使用 SHA-NI，AES-NI CTR 一次 8 个分组，AES-GCM 的 PCLMULQDQ GHASH（每次归约
  8 个分组）与 CTR 单趟融合，CRC-32 与 CRC-32C 使用 PCLMULQDQ 折叠以及 SSE4.2 `crc32` 指令，AVX2 ChaCha20
  （8 个分组）。
- aarch64：ARMv8 SHA1/SHA2、ARMv8 AES CTR、与 CTR 融合的 PMULL GHASH、ARMv8 CRC32 指令；ChaCha20 使用由
  编译器向量化的 4 分组并行布局（其他平台的可移植路径也是它）。
- 安全 Rust：44 位 limb 的 Poly1305（每步两个分组）；P-256 的专用 Montgomery 约简、加法链求逆、`[k]G` 的
  有符号仿射点梳形表以及无需求逆的 Jacobian wNAF 验签；Ed25519 交错 wNAF 验签；Curve25519、NIST 域与 RSA
  的专用平方；定长 RSA Montgomery 乘法；其余求逆使用窗口幂运算。
- `unsafe` 仍只出现在指令模块（`aes::hw`、`gcm::hw`、`hash::hw`、`crc::hw`、`chacha::hw`）中，每次调用前
  都经过检测（docs/unsafe-review.zh-CN.md）。`ONLY_CRYPTO_PORTABLE=1` 强制使用可移植实现（测试、基准）；
  Miri 运行的也是它。
- Ryzen 7 7800X3D 单核：SHA-1 3.6 倍、SHA-256 6.5 倍（与 RustCrypto crate 持平），AES-128-GCM
  364 → 6 484 MB/s，CRC-32 2.7 → 20 GB/s，ChaCha20-Poly1305 3 倍，P-256 验签 1.67 倍 / 签名 1.46 倍，Ed25519
  验签 1.49 倍，RSA-2048 签名 1.38 倍；TLS 1.3 握手 1.5 倍，16 KiB AES-GCM 记录 15 倍（分别为 rustls + ring
  的 0.60 倍与 0.64 倍）。表格见 docs/BENCHMARKS.zh-CN.md。

### 性能：更快的 TLS 1.3 握手（`only-crypto` 中的 P-256 与 X25519）

握手的性能剖析中曲线运算占 98% 以上；API 不变（`tools/api/public-api.sh` 无变化）。在基准主机上单核、
内存中与 rustls 0.23 + ring 对比：X25519 完整握手 3,055 → 5,027 次/秒（rustls 的 0.61 倍 → 1.00 倍），
secp256r1 2,306 → 4,552 次/秒（0.45 倍 → 0.89 倍）。

- x86_64 上带 BMI2 + ADX 时（运行时检测，`cpu` 新增特性 `adx`）的 P-256：模 `p` 与模群阶的 Montgomery
  乘法与平方、加法、减法与小倍数运算用内联汇编实现（`mulx`、`adcx`/`adox`、`cmov`；新的硬件模块
  `ec::hw`）。这些运算在一个“孪生”曲线类型上执行，它与可移植实现共享 Montgomery 表示和基点预计算表，
  因此每次操作只分派一次。
- 常数时间的标量乘法改用 Jacobian 坐标与 `a = -3` 公式：可变基点（ECDH）用 Booth 重编码的有符号
  5 位窗口，固定基点（密钥生成、签名）用有符号梳形表加混合加法。无穷远点的情形用掩码选择处理；对
  `[1, n)` 中的标量不会出现两个相同的操作数（代码中给出证明，测试检查 `n mod 32 ≥ 17`）。倍点为
  4M + 4S，并融合了 `2ᵏ·a`/`3·a`。
- P-256 标量求逆使用专用加法链（255 次平方、40 次乘法）；ECDSA 验签对公开的 `s` 用二进制扩展欧几里得
  算法求逆，并直接用射影坐标的公钥建表而不求逆。`SecretKey::public_key` 得到的公钥在编码前保持射影
  坐标（编码时做一次常数时间求逆）。
- X25519：公钥按 edwards25519 上的 `[k]B` 计算再映射为 `u = (1 + y)/(1 - y)`（使用 Ed25519 基点表，
  现在是带有符号数字的仿射 Niels 表项：每个数字 7M）；x86_64 带 BMI2 + ADX 时 Montgomery 阶梯在四个
  64 位 limb 上用内联汇编运行（`curve25519::hw`），2⁵¹ 进制的阶梯仍是可移植路径。
- 与 ring 对比的微基准（`--example pk_bench`，次/秒，优化前 → 优化后）：P-256 签名 34,152 → 59,837
  （0.45 倍 → 0.79 倍），验签 13,404 → 25,138（0.51 倍 → 0.96 倍），ECDH 10,380 → 27,288（0.35 倍 →
  0.91 倍），密钥生成 54,581 → 108,263（0.49 倍 → 0.96 倍）；X25519 30,696 → 36,488（0.84 倍 → 1.00 倍）；
  Ed25519 签名从 ring 的 1.15 倍到 1.53 倍；P-384 签名、验签、ECDH 与密钥生成比之前快 1.13–1.47 倍。
  RSA 不变。
- 常数时间证据：秘密标量路径的反汇编（x86_64 含汇编，aarch64 为可移植代码）中，条件分支只出现在循环
  计数、公开下标、求逆加法链的公开指数位、CPU 特性检查以及“结果为无穷远点”的判断上（见 `ct.rs`）。
  每个汇编例程都在随机值与边界值上与可移植代码比较，所有已知答案测试都在设置与不设置
  `ONLY_CRYPTO_PORTABLE=1` 时各跑一遍。
- `unsafe`：`only-crypto` 新增 13 个 `asm!` 块（`ec::hw` 8 个，`curve25519::hw` 5 个；见
  docs/unsafe-review.zh-CN.md）。

### 性能：`only-crypto` 的宽 AES-GCM 与 CRC，TLS 记录非原地加解密

公开 API 不变（只新增 `#[doc(hidden)]` 辅助函数）。

- 具备 VAES、VPCLMULQDQ 与 AVX-512 的 x86_64（Zen 4、Ice Lake 及更新；通过 CPUID 与 XCR0 检测）：AES-GCM
  加密与解密以一趟 512 位处理完成，每次循环 16 个分组，AES 轮函数与上一组的 GHASH 交织，每 16 个分组归约
  一次（BoringSSL / Linux `aes-gcm-avx10` 的设计；因为这些 intrinsic 比 MSRV 新，用 `asm!` 编写）。在
  Zen 4 上 512 位内核在所有长度上都快于同一内核的 256 位寄存器版本，因此只保留它；其他 CPU 继续使用
  AES-NI + PCLMULQDQ 内核。CRC-32 / CRC-32C 从 512 字节起在 512 位寄存器上每步折叠 256 字节。
- 所有具备 AES 与无进位乘法指令的 CPU：消息的最后几个字节与 `J0` 一次通过 AES，短 AAD、尾部密文与长度块
  一次通过 GHASH（64 字节消息快 1.8–2.1 倍）。
- `only-tls` 非原地加解密记录：AEAD 直接读取调用方的明文或收到的记录，只写一次输出，不再先复制再原地处理
  （复制占 16 KiB 记录的 30%）。
- Ryzen 7 7800X3D 单核：AES-128-GCM 加密 16 KiB 6,455 → 15,048 MB/s（ring 的 0.51 倍 → 1.19 倍），
  1400 B 4,249 → 8,163，64 B 611 → 1,185；TLS 1.3 记录加密 + 解密 16 KiB 2,739 → 6,603 MB/s（rustls + ring
  的 0.69 倍 → 1.65 倍）；CRC-32 16 KiB 20.0 → 74.9 GB/s（crc32fast 的 0.27 倍 → 1.02 倍）。表格见
  docs/BENCHMARKS.zh-CN.md。
- `unsafe`：新的 `gcm::hw::vaes` 内核、`asm!` CRC 折叠以及 CPUID / XGETBV（`cpu::hw`），均记录在
  docs/unsafe-review.zh-CN.md 中。Miri 永远不会执行到 `asm!`（检测不到任何特性）。

### 性能：`only-crypto` 中 P-256 的整点汇编、宽梳形表与 safegcd

无 API 变化（`tools/api/public-api.sh` 不变）。在基准机的单个核心上与 ring 0.17 / rustls 0.23 在同一次运行中
对比（交替运行五轮取中位数；机器同时被另一个基准测试占用，绝对速率偏低 20–30%，见 docs/BENCHMARKS.zh-CN.md）：
P-256 签名为 ring 的 0.77 倍 → 1.25 倍，生成密钥 0.94 倍 → 1.33 倍，验签 0.98 倍 → 1.04 倍，ECDH 0.94 倍 →
0.96 倍；TLS 1.3 secp256r1 握手为 rustls 的 0.94 倍 → 1.12 倍。

- x86_64 上带 BMI2 + ADX 时：P-256 孪生曲线的 Jacobian 倍点（`a = -3`）、加法与混合加法各是一个作用于小栈帧
  的 `asm!` 块，乘法与约简和周围的模加、模减、模倍融合（累加值留在寄存器中；每个乘积的低半部分单独约简，
  再加上高半部分）。连续的倍点（ECDH 每个窗口五次，验签中两次加法之间的若干次）共用一个帧。一次倍点约
  355 个周期，原来约 480 个。曲线 trait 增加了这些例程与查表的钩子，aarch64 的孪生曲线可以用同样方式接入。
- 固定基点（生成密钥、签名）在孪生曲线有 AVX2 时：Booth 重编码的有符号 6 位数字，作用于 43 行、每行 32 个
  仿射点的梳形表（88 KiB，首次使用时构造），43 次混合加法代替 65 次；每行都用 256 位读取与 `vpcmpeqq`
  掩码完整扫描。6 位与 7 位梳形表测得持平，5 位与 8 位更慢。ECDH 的窗口表也这样扫描。没有 AVX2 时仍用
  4 位梳形表。
- 模 P-256 素数与群阶的求逆改用 safegcd（libsecp256k1 形式的 Bernstein–Yang divsteps，新模块 `safegcd`），
  常数时间，x86_64 上 divsteps 用汇编，其他平台用带掩码的 Rust：签名中的标量求逆 20.9k → 7.0k 个周期，
  域求逆约 12.7k → 约 7–9k。所有路径（包括可移植路径）都不再使用费马加法链。
- 正确性：整点例程在随机 `Z` 的随机点、Wycheproof 中全部合法的 ECDH 点、`P + P`、`P + (-P)` 与无穷远点上
  与可移植公式逐 limb 比较；safegcd 在两个模数的随机值与边界值上与费马求逆比较；宽梳形表在随机标量与边界
  标量（每个最高位数字）上与完备公式的参考实现比较；宽梳形表不会遇到相同操作数的论证写在 `ec/hw.rs` 中。
- 常数时间证据（Zen 4 上 release 反汇编）：点运算例程、AVX2 查表与 `Fe::invert` 中没有任何条件分支；
  每个 `divsteps_59` 只有一个（循环计数）；`ecdh_x_impl`、`sign_impl` 与 `hw::mul_base` 中只有 CPU 特性与
  `OnceLock` 检查、循环计数、公开的数字位置与边界、输出长度以及最后的无穷远点判断。
- `unsafe`：`ec::hw` 新增 6 个块与 2 个 `unsafe fn`（点运算共用一个块、divsteps 一个块、两个 AVX2 查表及其
  两处调用；见 docs/unsafe-review.zh-CN.md）。

### 性能：`only-crypto` 中 x86_64 上开销更低的 P-256 点运算公式

无 API 变化（`tools/api/public-api.sh` 不变）。在空闲的基准机上测量（Zen 4，CPU 2，交替运行五轮取中位数，
同一次运行中对比 ring 0.17）：P-256 ECDH 为 ring 的 1.08 倍 → 1.12 倍（32,351 → 33,904 次/秒），签名 1.36 倍
→ 1.38 倍，验签 1.08 倍 → 1.10 倍，生成密钥 1.36 倍 → 1.40 倍。上一条记录中的 0.96 倍是在有负载的机器上测得的；
在空闲时，这次修改之前的代码已经是 1.08 倍。TLS 1.3 握手没有变化（secp256r1 为 rustls 的 1.07 倍，X25519 为
1.08 倍）：一次 ECDH 约占一次握手的 1%。

- P-256 孪生曲线的整点汇编改用 OpenSSL `ecp_nistz256` 的公式：加法为 12M + 4S，配 7 次模加减，代替
  add-2007-bl 的 11M + 5S 与 13 次模加减（这里乘法与平方开销相同，线性运算则不然）；混合加法为 8M + 3S，代替
  7M + 4S（7 次对 14 次）；倍点先算 `2Y`，于是 `Z₃ = 2Y·Z`、`4β = X·(2Y)²`、`8γ² = ((2Y)²)²/2`（新增模减半）
  只需 10 次线性运算，原来是 14 次。加法返回同一个点的另一种表示（`(X, Y, Z)` 而不是 `(4X, 8Y, 2Z)`）；倍点的
  limb 与原来相同。
- 点运算例程中的 Montgomery 约简在四步中都把 `p₃` 放在 `rdx` 中，并用 `shlx`/`shrx` 拆分 `m·2⁹⁶`（编译器保留的
  `rbx` 存放移位计数 32，在帧中保存与恢复）：每步从 10 条指令减为 7 条。
- 周期数（`perf stat`，Zen 4）：加法 745 → 721，混合加法 537 → 508，倍点 355 → 348，可变基点标量乘法
  148.1k → 140.6k，固定基点（梳形表）29.8k → 28.9k。倍点表现为每次乘法固定约 44 个周期：调整顺序（先算独立的
  乘积，或先算 `Y` 链）慢了 8–10%，OpenSSL 式把约简交织进乘积各行持平，把 `cmov` 选择换成 `xor`/`and` 掩码
  慢了 10%，因此都没有采用。
- 正确性：`points_match_portable` 逐 limb 比较倍点，加法则按点比较（交叉相乘，`Z = 0` 恰好出现在可移植公式
  给出 `Z = 0` 的地方），并新增两侧为全零无穷远点的情形；模减半在随机值与边界值上检查。
- 常数时间：Zen 4 上 release 反汇编中，`ecdh_x_impl`（17 处：循环计数、公开的数字位置与边界、CPU 特性检查、
  输出长度与最后的无穷远点判断）、`hw::mul_base`、`divsteps_59` 与 `safegcd::inv_with` 的条件分支与之前相同，
  点运算例程中没有。
- `unsafe`：没有新增块；点运算块保存并恢复 `rbx`（docs/unsafe-review.zh-CN.md）。

### 性能：`only-crypto` 中基于 BMI2 + ADX 与 AVX-512 IFMA 的 RSA

无 API 变化（`tools/api/public-api.sh` 不变）。在空闲的基准机上测量（Zen 4，CPU 2，新旧二进制交替运行三轮，
同一次运行中对比 ring 0.17，单位次/秒）：RSA-2048 PKCS#1 v1.5 签名 1,192 → 3,910（ring 的 0.49 倍 → 1.61 倍），
RSA-3072 371 → 1,455（0.47 倍 → 1.85 倍），RSA-4096 156 → 755（0.45 倍 → 2.19 倍）；验签 39,250 → 79,970
（0.60 倍 → 1.22 倍）、18,300 → 33,440（1.10 倍）、10,110 → 19,090（1.09 倍）；含公钥解析的验签（即验证一个证书
签名；ring 每次调用都会解析）5,850 → 67,090（0.09 倍 → 1.02 倍），3072 与 4096 位为 0.95 倍与 0.95 倍。
only-tls 使用 RSA-2048 证书的完整握手（`tls-bench` 新增一行）：775 → 2,586 次/秒，rustls + ring 的 0.43 倍
→ 1.44 倍。

- 在支持 AVX-512 IFMA 的 x86_64 上（新增 `cpu` 特性 `ifma`：CPUID leaf 7 加 AVX-512 状态），2048、3072 与
  4096 位密钥的 CRT 模幂以 2⁵² 为基数运算（`bignum::ifma`）：对 20、32 或 40 个数字做几乎 Montgomery 乘法，
  每个乘积一个 `asm!` 块，操作数放在寄存器中（20 与 32 个数字用 `ymm`，40 个用 `zmm`）；20 个数字时用两个
  累加器，使每个寄存器每步只承担两次相互依赖的乘加；最低位数字与下一个 `yᵢ` 在通用寄存器中计算，使这条依赖链
  不经过向量单元；进位用一个 generate / propagate 掩码字规整。整个模幂过程中结果都小于 `2p`，最后做一次带掩码的
  减法。一次 1024 位乘法需要 416 个周期。
- 没有 IFMA、但有 BMI2 + ADX 时：16 至 64 个 limb 的 Montgomery 乘法与平方用 `asm!` 实现（`bignum::hw`；
  `mulx` 加两条进位链的操作数扫描，行用汇编器的 `.rept` 展开，下一步约简因子直接取自寄存器，32 个 limb 以内有
  专用平方，最后的减法用 `cmovnz`）：1024 位乘法 1,240 → 805 个周期，平方 1,490 → 681；只走这条路径时 RSA-2048
  签名为 ring 的 0.99 倍，验签 1.20 倍。
- 模幂：固定 5 位窗口（原为 4 位），扁平的预计算表中偶数项用平方得到，每次查表用 AVX2 `vpcmpeqq` 掩码一遍扫过
  全部 32 个表项（没有 AVX2 时用常数时间的 `ct` 掩码）。
- `R² mod m`：秘密素数用 `64 + k` 次倍加与六次 Montgomery 平方，代替 `128k` 次倍加（常数时间）；公开模数用一次
  长除法；密钥解析不再是证书校验的主要开销。私钥运算保留盲化（现在用专用平方更新），省去四次 2048 位的形式转换，
  并用三次乘法把盲化后的输入约简到各素数域。
- 没有尝试 Karatsuba：在这些位数下，汇编的行循环已没有多少可省。
- 正确性：`asm_matches_generic`（在每个规模上把 BMI2 + ADX 代码与通用 CIOS 比较：随机值，以及 0、1、m - 1、
  m - 2、R - 1、R - m，最高 limb 满与不满的模数，200 步运算链），`ifma_pow_matches`（用边界底数与指数把 IFMA
  模幂与平方-乘法比较），`r2_constructions`；`rsa_vs_ring` 现在用 2048、3072（新增）与 4096 位（新增）密钥签名，
  要求 PKCS#1 v1.5 签名与 ring 逐字节一致，并在强制可移植实现时再比较一次；Wycheproof 的 RSA 向量不变，两条
  路径都通过。
- 常数时间：Zen 4 上的 release 反汇编中，`Mont::mul_into` / `sqr_into`、`ifma::amm`、`ifma::pow`、`Mont::pow`、
  查表、`Mont::new`、`crt_combine` 与 `private_op` 的条件分支只有循环计数、按公开 limb 数与数字个数的分派、
  CPU 特性、切片与内存分配检查、公开的窗口位置、盲化缓存与最后的故障检查（数量见 `src/ct.rs`）。
- `unsafe`：`only-crypto` 新增 7 个块与 1 个 `unsafe fn`（`bignum::hw`：两个 Montgomery 汇编块与 AVX2 查表；
  `bignum::ifma`：IFMA 汇编块）；见 docs/unsafe-review.zh-CN.md。

### 新增：`only-crypto` 的统计计时测试（`tools/ct-dudect`）

dudect 式测试（对固定与随机秘密做 Welch t 检验，随机交错，`rdtsc` / `cntvct_el0` 计时，分位数裁剪与二阶
检验，`|t| > 4.5` 视为泄漏），在硬件与可移植代码上测量依赖秘密的路径：P-256 ECDH、生成密钥与签名，X25519
及其生成密钥，Ed25519 签名，RSA-2048 签名，AES-GCM 与 ChaCha20-Poly1305 的标签校验，HMAC 校验，`ct_eq` 与
`ct.rs` 原语；以 A/A 测试和两个故意泄漏的函数作为自检。这是新的 workspace 内部工具（不发布，无新依赖）；
CI 中作为信息性任务 `ct-dudect` 运行（不属于 `ci-ok`，t 值保存为 artifact）。在 Zen 4 上未见泄漏，只有两处
细小且时有时无的差异有待进一步测量（退化的全零 X25519 标量；P-256 可移植签名处于阈值边缘）；方法与结果见
[docs/constant-time.zh-CN.md](docs/constant-time.zh-CN.md)。

### 性能：`only-deflate` 的存储块只复制一次

无 API 变化；压缩输出逐字节不变。在基准主机上测量（Zen 4，CPU 2，新旧 `bench` 二进制交替五轮，zlib-rs 在同一次
运行中）：解压级别 6 的随机数据（存储块）15,456 → 34,278 MB/s（zlib-rs 的 0.43 倍 → 0.94 倍），级别 9 为
15,357 → 34,003 MB/s。文本与 JSON（字面量与匹配）不变。

- 存储块从输入直接复制到调用方的输出，不再经过窗口；一段连续的存储数据只把最后一个窗口大小（至多 32 KiB）的部分
  放进历史，每次调用一次，在压缩块或尾部需要之前完成。
- `Inflater::decompress_vec` 用 `extend_from_slice` 追加存储数据（无需先填零再复制）；块头在没有输出空间时解码。
  `decompress` 预先保留两倍输入大小（不超过上限）的空间。
- 测试：三种格式下存储块在每个输入字节处切开、按每种输出大小读取（经 `decompress` 与 `decompress_vec`），以及
  长于窗口的存储块（至多 65,535 字节）之后按最大距离匹配，窗口为 512 字节、4 KiB 与 32 KiB。
- 尝试后放弃：在以字面量为主的路径上每次补充位缓冲后解码至多五个字面量（原为三个），没有可测的差别。

### 性能：QUIC 数据通路（默认 GRO、按批 ACK、池化接收缓冲区）

API 不变（`tools/api/public-api.sh` 无变化：新增的钩子是 `#[doc(hidden)]`）。一个默认值改变：
`Config::udp_gro` 现在为 `true`。在基准主机上测量（Zen 4，回环，`quic-bench` 客户端与服务端在 CPU 2–5，
新旧交替七轮取中位数，部分轮次主机上有外部负载）：单流批量传输 6,378 → 16,066 Mbit/s（2.52×），
HTTP/3 427,901 → 443,299 请求/秒（1.04×），完整握手 9,294 → 9,542/秒（持平）。同一程序的 quinn-proto
版本在同一次运行中为 4,613 Mbit/s 与 56,934 请求/秒，本版本为 15,999 Mbit/s 与 430,098 请求/秒
（3.5× 与 7.6×）。

- `only-core`：`Handler::on_batch_end`（`#[doc(hidden)]`，默认什么也不做，不在稳定性承诺之内）告诉 UDP
  处理器：调用过它 `on_data` 的那个接收批次结束了。only-epoll 的 UDP 循环（io_uring 后端与 macOS 上的 UDP
  也由它服务）在批次的回复发出之前，对每个连接每批调用一次（一次 `recvmmsg`；macOS 上最多 32 次
  `recv_from`/`recv`）；填满整批的拨号连接现在每批之后就发出，而不是最多八批之后。其他后端（only-dpdk）
  不调用它。
- `Config::udp_gro` 默认为 `true`（Linux，内核支持 `UDP_GRO` 时；只探测一次，`ONLY_UDP_GRO=0` 仍可关闭，
  `read_buffer` 仍需至少 64 KiB）。服务端、绑定与拨号 socket 上合并的接收照旧按 `UDP_GRO` 分段大小拆开，
  `on_data` 仍然每次一个数据报（only-kcp、only-turn、only-webrtc 与 DNS 的测试不变地通过）。仅此一项，
  QUIC 批量传输 6.4 → 9.8 Gbit/s：发送方的一批 GSO 数据完整到达接收 socket，而不是被拆段。64 字节 UDP
  echo 开关 GRO 各交替 15 轮：差别不超出该场景的噪声。
- UDP 循环每次接收调用读一次时钟，并把每个计时回调的结束时间当作下一个回调的开始（与 TCP 循环相同）：
  每个数据报读三次时钟变为一次。
- only-quic 每个接收批次只确认一次：每个数据报之后处理器照常运行，已就绪的数据立即发出，但只含 ACK 的包
  等到 `on_batch_end`（每批一个，而不是每两个包一个）；QUIC 定时器也每批只设置一次。把处理器事件与数据
  也推迟到批次结束的变体在批量传输上测得 1.45×，但 HTTP/3 下降 28%（64 个在途请求变成每个往返一个
  步调一致的批次），因此没有采用。在 socket 第一次收到 `on_batch_end` 之前（以及在没有该钩子的后端上），
  每个数据报照旧单独驱动。
- 收到的数据报只复制一次，进入每线程的缓冲池（`Arc<Vec<u8>>`）并就地解密；流数据与数据报是其 `Bytes`
  切片，切片全部释放（可在任意线程）后缓冲区被复用。这取代了每个包两次分配（复制及其外层 `Arc`）。仍有
  一次复制：处理器以引用方式拿到 `recvmmsg` 的槽位，而就地解密需要本方独占的缓冲区。
- 已发送的包记录在按包号索引的环形缓冲中（`proto/conn/sent.rs`），不再用 `BTreeMap`；已确认或已丢失
  的包的帧列表被新包复用。
- 剖析中发现但未处理的：对端地址与连接 ID 表上的 SipHash（约占接收方 2%），以及 only-h3/only-http 中的
  分配与头部哈希（`encode_fields`、`Headers`），它们是 HTTP/3 剖析的主要部分。

### 变更（破坏性，1.0.0 之前）：封装 1.0 之前的依赖

rustls 0.23、quinn-proto 0.11、str0m 0.24 与 prost 0.13 不再出现在受保护的 API 中，因此 1.0.0 之后
升级它们（或用自研代码替换）不是破坏性变更。直接访问移到新的 `unstable` cargo feature 之后（`only`、
`only-tls`、`only-quic`、`only-webrtc`），与 `only-grpc` 的 `prost` feature 一样不在 semver 承诺之内
（docs/api-stability.zh-CN.md，“公开依赖”）。

| 之前 | 之后 |
|---|---|
| `only::tls::rustls`（再导出） | 仅 `unstable` feature |
| `rustls::ServerConfig::builder()...with_single_cert(chain, key)` + `alpn_protocols` | `only::tls::ServerConfig::builder(chain, key).alpn([..]).build()?`（另有 `sni_cert`、`client_auth_required` / `_optional`、`session_cache`、`session_tickets`、`tls13_only`） |
| `rustls::ClientConfig::builder().with_root_certificates(roots)...` | `only::tls::ClientConfig::builder().roots(roots).alpn([..]).build()?`（另有 `client_cert`、`sni`、`resumption`、`tls13_only`、`insecure_skip_verify`） |
| `CertificateDer`、`PrivateKeyDer`、`RootCertStore` | `only::tls::{Certificate, PrivateKey, RootCerts}`（`from_pem`、`from_der`、`from_pkcs8_der`） |
| `Tls::server(Arc<rustls::ServerConfig>, a)`、`Tls::client(Arc<rustls::ClientConfig>, ..)` | `Tls::server(ServerConfig, a)`、`Tls::client(ClientConfig, ..)` |
| `Client::with_tls(Arc<rustls::ClientConfig>)`、`H2Client::dial(.., Some((Arc<..>, name)), ..)`、`DialOptions::tls: Option<Arc<..>>` | 同上，改用 `only::tls::ClientConfig` |
| `only_quic::{proto, rustls}` 再导出、`VarInt` | 仅 `unstable` feature（`proto`）；删除 `VarInt` |
| `only_quic::{StreamId, Dir, ConnectionError, TransportConfig}`（quinn 的类型） | only 自己的类型（另有 `Side`、`Congestion`、`UdpStats`）；`ConnectionError` 的变体改为结构体形式（`ApplicationClosed { code, reason }`、`TransportError { code, reason }`） |
| `Connection::stats() -> quinn_proto::ConnectionStats` | `ConnectionStats`（`udp_tx`、`udp_rx`、`rtt`、`cwnd`、`lost_packets` 等） |
| `server_config(Vec<CertificateDer>, PrivateKeyDer, alpn) -> quinn_proto::ServerConfig` | `server_config(Vec<Certificate>, PrivateKey, alpn) -> only_quic::ServerConfig`（`.transport(&TransportConfig)`、`.migration(bool)`） |
| `server_config_from(rustls::ServerConfig)`、`client_config(RootCertStore, ..)`、`client_config_from(rustls::ClientConfig)` | `server_config_from(&only::tls::ServerConfig)`、`client_config(RootCerts, ..)`、`client_config_from(&only::tls::ClientConfig)` |
| `Error::Connect(quinn_proto::ConnectError)` | `Error::Connect(String)` |
| `only_h3::server_config(Vec<CertificateDer>, PrivateKeyDer)`、`serve(quinn_proto::ServerConfig, ..)`、`H3Client::dial(.., quinn_proto::ClientConfig)` | `Certificate` / `PrivateKey`、`only_quic::ServerConfig`、`only_quic::ClientConfig` |
| `only_grpc::codec::{encode, decode}` 约束为 `prost::Message` | 约束为 `only_grpc::codec::Message`（`encode_to`、`decode_from`）；`prost` feature 为 prost 消息实现它 |
| `only_webrtc::str0m` 再导出、`Peer::with_rtc`、`crypto_provider`、`generate_certificate` | 仅 `unstable` feature（`str0m`、`with_rtc`、`crypto_provider_str0m`）；`generate_certificate` 改为内部函数 |
| str0m 的 `ChannelId`、`ChannelConfig`、`Reliability`、`Mid`、`Pt`、`MediaKind`、`Direction`、`Frequency`、`MediaTime`、`MediaData`、`MediaAdded`、`KeyframeRequest(Kind)`、`RtpPacket`、`Candidate`、`IceConnectionState`、`RtcConfig`、`Event` | 同名的 only 自有类型（`ChannelConfig` 为 `#[non_exhaustive]`：先 `ChannelConfig::new(label)` 再设置字段；`MediaData::data` / `RtpPacket::payload` 为 `Arc<[u8]>`） |
| `create_offer(h, \|api: &mut SdpApi\| ..)`、`renegotiate(..)`；`api.add_channel(label.into())`、`api.add_media(kind, dir, None, None, None)` | `SdpChanges`：`add_channel(label)`、`add_channel_with_config(&cfg)`、`add_media(kind, dir, None, None)`、`set_direction`、`stop_media`、`ice_restart` |
| `Peer::open_channel(ChannelConfig)`、`payload_type(mid, str0m::format::Codec)` | `open_channel(&ChannelConfig)`、`payload_type(mid, only_webrtc::Codec)` |
| `PeerHandler::on_event(&str0m::Event)` | `on_event(&Event)`：`Event::ChannelBufferedAmountLow(id)` 或 `Event::Other(OtherEvent)` |
| `Error::Rtc(str0m::RtcError)`、`impl From<str0m::RtcError> for Error` | `Error::Rtc(only_webrtc::RtcError)`；新增 `Error::InvalidCandidate` |
| `Endpoint::add_candidate(str0m::Candidate)` | `Candidate::host(addr)` / `server_reflexive(addr, base)` / `relayed(addr, base)` / `parse(sdp)` |

### 变更（破坏性，1.0.0 之前）：自研日志门面 `only-log` 取代 `log`

DEV-PLAN 第 B 波。`only` 不再依赖 `log` crate，而是通过新的公开 crate `only-log`（无依赖，以
`only::log` 重新导出）记日志：级别、target、沿用 `log` 宏语法的结构化键值对、存放在原子变量中的全局
最大级别（被禁用的语句只需一次 relaxed 读：0.25-0.29 ns，`log` 为 0.36 ns）、带 `set_logger` /
`set_boxed_logger` 的 `Logger` trait，以及内置 logger（`only::log::init(level)` 向 stderr 输出格式化
行，`StderrLogger`）。target、消息和键名保持不变；未安装 logger 时，错误与慢回调警告仍打印到 stderr。
新增的 `log` cargo feature（`only`、`only-core`、`only-log`；不在 semver 承诺之内）桥接到 `log`
crate：未安装 only-log logger 时记录交给 `log` 的 logger（`Config::log_level` 也会像以前一样设置
`log::max_level`），`only::log::bridge::route_log_to_only()` 则把 `log` 的记录（str0m、rustls ……）
送入 only-log 的 logger。

迁移：

| 之前 | 之后 |
|---|---|
| `env_logger::init()`（或任意 `log` logger） | 不变，在 `only` 上开启 `features = ["log"]`；或改用 `only::log::init(only::log::LevelFilter::Info)` |
| `cfg.log_level = Some(log::LevelFilter::Info)` | `Some(only::log::LevelFilter::Info)`（开启 `log` feature 时也可写 `Some(log::LevelFilter::Info.into())`） |
| `Telemetry::set_log_level(log::LevelFilter)` | `set_log_level(only::log::LevelFilter)` |
| `impl log::Log for MyLogger` | `impl only::log::Logger for MyLogger`（`enabled` 与 `flush` 有默认实现）；用 `only::log::set_logger` 安装 |
| `record.key_values().visit(&mut visitor)` | `record.key_values().iter()` / `.get("conn_id")`；值实现了 `Display` |
| `log::max_level()` | `only::log::max_level()` |

### 变更：自研密码学（`only-crypto`，DEV-PLAN 第 A 波）

- 新的内部 crate `only-crypto`（只依赖 std，除 AES-NI / ARMv8 AES 模块外 `#![deny(unsafe_code)]`）：SHA-1、
  SHA-224/256、SHA-384/512、MD5、HMAC、HKDF、PBKDF2、CRC-32 / CRC-32C、AES-128/192/256（检测到 CPU
  指令时使用指令，否则使用常数时间 fixsliced 软件实现）及 CTR、带常数时间 GHASH 的 AES-GCM、ChaCha20-Poly1305、base64（严格解码）、操作系统随机数与
  ChaCha20 生成器。用 NIST CAVP、RFC 与 Wycheproof 向量测试，并（在测试与模糊测试目标中）与被替代的
  crate 交叉比对。
- `only-kcp`、`only-turn`、`only-ws`、`only-http`、`only-media`、`only-bittorrent` 和
  `only-webrtc` 改用它，不再依赖 sha1、sha2、md-5、hmac、pbkdf2、aes、aes-gcm、ctr、crc32fast、
  base64 与 getrandom（它们只作为 dev / fuzz 的参照实现保留，在第 D 波之前仍经由 str0m/dimpl 间接存在）。
  公开 API 与线上格式不变（KCP 加密，包括旧实现封装的“黄金”数据报；TURN MESSAGE-INTEGRITY/FINGERPRINT；
  WebSocket accept key；BitTorrent info hash 与 MSE；SRT 密钥包装与 AES-CTR；RTMP digest 握手；SRTP）。
- `only-sys`（内部，`#[doc(hidden)]`）：基于 `getrandom(2)` / `getentropy(2)` 的 `fill_random`，
  回退到 `/dev/urandom`。
### 新增：公钥密码学与 X.509（`only-crypto`、新的 `only-x509`，DEV-PLAN 第 B 波）

为自研 TLS 1.2/1.3、DTLS、QUIC 与 WebRTC 协议栈（第 C、D 波）打基础；协议 crate 目前还没有使用它们，
行为没有变化。

- `only-crypto`（内部层级；API 只增不减）：X25519（RFC 7748）、Ed25519（RFC 8032，严格验证：`S` 必须规范、
  比较 `R` 的编码）、P-256 与 P-384 上的 ECDH 和 ECDSA（RFC 6979 确定性 nonce，DER 与定长签名，带校验的
  SEC1 点）、RSA PKCS#1 v1.5 与 PSS 签名/验证（SHA-256/384/512，SHA-1 仅验证），模数 2048–8192 位（CRT、
  盲化、结果校验），严格 DER 读写器、PEM，以及密钥编码（PKCS#8 v1/v2、SEC1、PKCS#1、
  SubjectPublicKeyInfo），统一在 `pkey::{PrivateKey, PublicKey, SignatureAlgorithm}` 之后。`Error` 新增
  `InvalidKey`、`Encoding`、`Unsupported`、`Random`、`ZeroSharedSecret`。常数时间的域运算（P-256/P-384 与
  标量用 Montgomery，Curve25519 用 2⁵¹ 进制）、完备加法公式、读取全部表项的查表。
- 新的内部 crate `only-x509`（`#![forbid(unsafe_code)]`）：证书解析（严格 DER；subjectAltName、
  basicConstraints、keyUsage、extKeyUsage、nameConstraints、密钥标识符），基于 `RootStore` 的证书链构建与
  校验（有效期、CA/pathLen、密钥用途、EKU、DNS/IP/directoryName 名称约束、未知关键扩展、签名校验次数上限），
  RFC 6125 服务器名匹配（仅最左标签通配符、IP SAN），以及自签名和 CA 签发证书的生成
  （`CertificateParams`、`generate_simple_self_signed`）。
- 测试：Wycheproof（X25519、Ed25519、ECDSA P-256/P-384 的 DER 与 P1363、ECDH P-256/P-384、RSA PKCS#1 v1.5
  与 PSS 验证、RSA 签名生成）、RFC 7748 / 8032 / 6979 向量、与 ring 和 RustCrypto p256/p384 签名逐字节一致
  且互相验证、真实证书链（Google Trust Services、Let's Encrypt 的 ECDSA 与 RSA 链）、OpenSSL 生成的证书链与
  密钥（RSA-PSS、P-384、Ed25519）、与 rcgen 和 rustls-webpki 互通、构造的反例证书链；模糊测试目标
  `x509_parse` 与 `crypto_sig_verify`（与 ring 差分），并有语料回放测试。

### 新增：自研 DTLS 1.2（新的 `only-dtls`，DEV-PLAN 第 C 波）

自研 WebRTC 协议栈的 DTLS 层（第 D 波将用它替代 str0m 的 `dimpl`）；目前还没有代码使用它，因此行为不变。

- 新的内部 crate `only-dtls`（`#![forbid(unsafe_code)]`，只依赖 `only-crypto` 与 `only-x509`）：
  sans-io 的 DTLS 1.2（RFC 6347）`Connection`，可作任一角色，由 `handle_datagram`、`poll_transmit`、
  `poll_event`、`poll_timeout` / `handle_timeout` 与 `send_application_data` 驱动。记录层支持 epoch、
  48 位序列号与 64 条记录的防重放窗口；握手消息按配置的 MTU 分片并支持乱序重组；按指数退避重传
  flight（RFC 6347 §4.2.4），对端重发上一 flight 时也重传；无状态的 HMAC-SHA-256 HelloVerifyRequest
  cookie（`HelloVerifier` 供在证明返回可达性之前不分配任何状态的监听方使用）。
- 密码套件 `TLS_ECDHE_{ECDSA,RSA}_WITH_{AES_128_GCM_SHA256, AES_256_GCM_SHA384,
  CHACHA20_POLY1305_SHA256}`，群 X25519 / P-256 / P-384，ECDSA、Ed25519、RSA-PSS 与 RSA PKCS#1 签名；
  扩展主密钥（RFC 7627，默认必需）；拒绝重协商（RFC 5746）。
- WebRTC：`Config::webrtc`，自签名证书的双向认证，可由 `PeerVerifier::Fingerprints`（SDP
  `a=fingerprint`）、回调校验或交给调用方；`Identity::generate_self_signed`、`Fingerprint`（SDP 格式）、
  `use_srtp`（RFC 5764）支持 `SRTP_AEAD_AES_128_GCM`、`SRTP_AEAD_AES_256_GCM`、
  `SRTP_AES128_CM_HMAC_SHA1_80/32`，SRTP 主密钥随 `Event::Connected` 给出，以及 RFC 5705 导出器
  （`export_keying_material`）。
- 测试：在 MTU 256、25% 丢包、重复与乱序的模拟链路上握手，每个套件配合 ECDSA P-256/P-384、Ed25519 与
  RSA 证书，负面用例（错误指纹、重放、篡改记录、错误 cookie、超时、缺少客户端证书、无共同套件）；
  与 OpenSSL `s_client`/`s_server -dtls1_2`（Docker 中的 3.5 与 4.1；`-use_srtp` 与 `-keymatexport`
  的密钥一致）和 pion/dtls v3 双向互通（`tools/interop/dtls/run.sh`），并在内存中与 `dimpl` 互通
  （`tests/dimpl.rs`）；fuzz 目标 `dtls_record` 与 `dtls_handshake` 及语料回放测试。未实现：DTLS 1.3
  （RFC 9147）、连接 ID、会话恢复、PSK。
### 变更：`only-tls` 自研 TLS 1.3 与 1.2（DEV-PLAN 第 C 波；不再依赖 rustls、ring）

`only-tls` 现在依据 RFC 自己实现 TLS，基于 `only-crypto` 与 `only-x509`（`#![forbid(unsafe_code)]`，
无第三方依赖）。受保护的 API 不变（`api/only-tls.txt` 完全相同）：`ServerConfig` / `ClientConfig`
构建器、`Certificate`、`PrivateKey`、`RootCerts`、`Error`、`Tls`、`TlsInfo`、`tls_info`；only-http
（HTTP/1.1，经 ALPN 的 HTTP/2）、only-ws（`wss://`）、only-socks、only-grpc 与 only-mux 无需改动即
运行其上。

- TLS 1.3（RFC 8446）：双方完整握手、HelloRetryRequest（回显 cookie）、密钥调度、KeyUpdate（应答，
  并在达到 AES-GCM 记录上限前主动发送）、NewSessionTicket 与 PSK 会话恢复（`psk_dhe_ke`；
  `session_tickets(true)` 为无状态票据，会话缓存为一次性缓存票据）、客户端证书、中间设备兼容模式，
  拒绝 0-RTT（按 RFC 8446 4.2.10 跳过）。
- TLS 1.2（RFC 5246 + RFC 7627 扩展主密钥 + RFC 5746 重协商指示，以 `no_renegotiation` 警告拒绝
  重协商）：仅 ECDHE 搭配 ECDSA、Ed25519 或 RSA 证书与 AEAD 套件，按会话 ID 与 RFC 5077 票据恢复，
  客户端证书；设置并检查 RFC 8446 的降级哨兵。
- 套件：TLS_AES_128_GCM_SHA256、TLS_AES_256_GCM_SHA384、TLS_CHACHA20_POLY1305_SHA256 以及六个
  ECDHE-ECDSA/RSA 的 AES-GCM / ChaCha20-Poly1305 TLS 1.2 套件。组：X25519、secp256r1、secp384r1。
  签名：ECDSA P-256/P-384、Ed25519、RSA-PSS（rsae）与 RSA PKCS#1 v1.5（TLS 1.2 与证书）。扩展：SNI、
  ALPN、supported_versions、key_share、signature_algorithms、psk_key_exchange_modes、pre_shared_key、
  early_data、cookie、extended_master_secret、renegotiation_info、session_ticket、ec_point_formats；
  未知扩展被忽略。
- 记录层：16 KiB 分片、TLS 1.3 内层内容类型与填充、严格的状态机、握手消息跨记录重组（跨密钥切换则拒绝）、
  close_notify、告警、警告告警数量有上限；证书由 `only-x509` 验证（链、有效期、EKU、DNS 名与 IP 地址）；
  `insecure_skip_verify` 不变。
- 面向 QUIC 的内核（`only_tls::quic`，`#[doc(hidden)]`，内部）：同一套 TLS 1.3 状态机，不经记录层，
  按加密级别驱动（握手字节进出、各级别的流量密钥、quic_transport_parameters、强制 ALPN、无兼容模式、
  RFC 9001 密钥派生辅助函数及其附录 A 向量），供第 D 波的自研 QUIC 使用。在那之前 only-quic 仍用
  quinn-proto，其 rustls 配置现由 only-quic 根据 only-tls 的配置自行构建（rustls 只留作 only-quic 的依赖）。
- 测试：RFC 8448 跟踪（简单 1-RTT、恢复绑定值、HelloRetryRequest：密钥调度、transcript、Finished、记录
  逐字节一致），覆盖所有套件、组、密钥类型与版本的内存握手，会话恢复、客户端认证、低至单字节的分片、
  KeyUpdate、降级检测与反例；互通矩阵（`tools/interop/tls/run.sh`，107 个用例：OpenSSL
  `s_server`/`s_client`、Go `crypto/tls` 双向、curl 的 HTTP/1.1 与 HTTP/2），`tools/interop/grpc/run.sh`
  新增 TLS 一环，`only` 的 TLS 测试保留 rustls 客户端；以 tlsfuzzer 测试服务端（`tools/interop/tls/tlsfuzzer.sh`：
  33 个适用的 TLS 1.3 / 1.2 脚本，985 个探测，5 个已知且有记录的失败）；fuzz 目标 `tls_server`、`tls_client`、
  `tls_record` 及语料回放。
- 性能（Apple M4 Pro，服务端 2 线程，rustls 客户端）：完整握手约为 rustls+ring 的 0.7 倍（`only-crypto`
  的 P-256 ECDSA 与 X25519 慢于 ring 的汇编），小记录持平，大块吞吐约 0.45 倍（`only-crypto` 的 GHASH
  为可移植实现；PMULL / PCLMULQDQ 是第 A 波的后续工作）。

迁移：only-tls 的 `unstable` feature（以及 `only/unstable` 中与 TLS 相关的部分）不再暴露任何内容：
`only::tls::rustls`、`ServerConfig::from_rustls` / `as_rustls` 与 `ClientConfig::from_rustls` /
`as_rustls` 已移除（它们本就不在 semver 承诺之内）。`ServerConfigBuilder::build` 在私钥与证书不匹配时
也会报错。rcgen 与 rustls 已从 only-tls、only-http、only-ws、only-mux、only-h3、only-quic、only-grpc
的 dev-dependencies 中移除（测试证书改由 `only-x509` 生成）；`only` 的 TLS 测试保留 rustls 客户端作为
互通对端。

### 变更：`only-quic` 自研 QUIC v1（DEV-PLAN 第 D 波；不再依赖 quinn-proto、rustls、bytes）

`only-quic` 现在依据 RFC 9000、9001、9002 以及 RFC 9221 数据报自行实现 QUIC，是基于 `only-tls`
（其不经记录层的 TLS 1.3，`only_tls::quic`）与 `only-crypto` 的 sans-io 核心
（`#![forbid(unsafe_code)]`，无第三方依赖）。quinn-proto、其内部的 rustls（及 ring）以及 `bytes` crate
已从 only-quic 和 only-h3 中移除；工作区里已没有库依赖 rustls。除负载类型外 API 不变（迁移见下）：
`QuicServer`、`dial`、`Connection`、`QuicHandler`、`ServerConfig` / `ClientConfig` /
`TransportConfig`、`StreamId`、`ConnectionError`、`ConnectionStats`；only-h3 的 API 不变
（`api/only-h3.txt` 完全相同）。

- 数据包：长/短包头、三个包号空间、包号编码、包头保护（AES、ChaCha20）、AES-128/256-GCM 与
  ChaCha20-Poly1305 包保护、合并数据包、Initial 与路径验证的填充、版本协商、带完整性标签的 Retry、无状态
  重置（对未知连接 ID 发送，按令牌识别）、1-RTT 密钥更新（每几百万个包发起一次，对端发起时跟随）。
- 帧：RFC 9000 的全部帧以及 DATAGRAM，并遵守按包类型的限制；流级与连接级流量控制、流数量上限
  （MAX_STREAMS 批量下发）、BLOCKED 帧、最终大小检查、以 RESET_STREAM 回应 STOP_SENDING。
- 丢包恢复（RFC 9002）：RTT 估计、按包序与时间阈值的丢包检测、探测超时与握手防死锁探测、持续拥塞、
  NewReno 与 CUBIC（RFC 9438）、pacing、3 倍放大限制、ACK 延迟规则、空闲超时、保活、探测到 1452 字节的
  路径 MTU 发现。
- Endpoint：按连接 ID 路由（8 字节 ID，用 NEW_CONNECTION_ID 下发、退役后补充）、握手压力大时使用 Retry、
  NEW_TOKEN 地址验证（令牌按服务器名保存在 `ClientConfig` 中）、经路径验证的迁移
  （`ServerConfig::migration(false)` 拒绝迁移）、传输参数与连接 ID 校验、基于票据的会话恢复
  （`server_config` 开启票据）。
- I/O：满尺寸的数据报成批地用 GSO 发出（`Conn::send_segments`，最多 10 个）；在连接自身回调中发起的写入
  先攒起来，回调返回后与 ACK 一起发出，因此 HTTP/3 响应的头、体与 FIN 通常在同一个包里。
- 测试：RFC 9001 附录 A 向量、各组件的单元测试，以及模拟网络（丢包、乱序、重复、MTU、断网、虚拟时钟）上
  的握手、大块传输、多流、迁移、密钥更新、Retry、会话恢复、重置与超时测试；与 quic-go 的原生 QUIC 双向互通
  （新增 `tools/interop/quic/run.sh`：流与数据报，然后是 Retry、密钥更新与 150 MB 的流）以及与 quic-go、
  fib 的 HTTP/3 双向互通（`tools/interop/h3/run.sh`）；在 Docker 中以 ngtcp2 1.11（通过 libcurl-gnutls）
  和 OpenSSL 3.5 的 QUIC（curl、libcurl、`openssl s_client -quic`）作为我方服务端的客户端（新增
  `tools/interop/quic/docker.sh`）；fuzz 目标 `quic_packet`、`quic_frame`、
  `quic_conn`，并回放语料。
- 性能（与 quinn-proto 版本对比，同一个回环基准 `crates/only-h3/examples/quic-bench.rs`）：在 AMD Ryzen 7 7800X3D（Linux，回环，交替运行 3 轮）上，完整握手 6705-6785 次/秒，对比 6536-6674 次/秒（约 1.0 倍）；单流大块吞吐 3.1-3.6 Gbit/s，对比 4.6-4.7 Gbit/s（约 0.72 倍；包保护使用 `only-crypto` 的硬件 AES-GCM）；单连接 64 个并发的 HTTP/3 请求 17.1 万次/秒，对比 5.8 万次/秒（约 2.9 倍，因为响应、FIN 与 ACK 共用数据包）。

迁移：流与数据报负载改为 `only_quic::Bytes`（原为 `bytes::Bytes`），这是唯一的签名变化
（`QuicHandler::on_stream_data`、`QuicHandler::on_datagram`，以及接受 `impl Into<only_quic::Bytes>` 的
`Connection::send` 与 `Connection::send_datagram`）。它的形状相同（引用计数；`new`、`from_static`、
`copy_from_slice`、`slice`、`split_to`、`split_off`、`truncate`、`advance`、`Deref<Target = [u8]>`、
`From<Vec<u8>>`、`From<&'static [u8]>`、`From<&'static str>`、`From<String>`、`Vec<u8>: From<Bytes>`），
通常只需改导入：`use bytes::Bytes;` 改为 `use only_quic::Bytes;`。only-quic 的 `unstable` feature 保留且为空：
`only_quic::proto`、`ServerConfig::from_quinn` / `as_quinn_mut` 与 `ClientConfig::from_quinn` /
`as_quinn_mut` 已移除（它们本就不在 semver 承诺之内）。`Congestion::Bbr`（实验性）实际运行 CUBIC。
`Connection::queued_bytes` 统计尚未发出的字节数。`dial` 发起的连接结束后其 UDP socket 会被关闭（以前一直保持到引擎停止）；`open_bi` / `open_uni` 从不运行处理器回调，因此可以在持有处理器也会获取的锁时调用。未实现：0-RTT、发送 ECN 标记、客户端主动迁移、
preferred_address、QUIC v2。

### 变更：`only-webrtc` 使用自研 WebRTC 协议栈（DEV-PLAN 第 D 波；不再依赖 str0m、dimpl、p256）

`only-webrtc` 在 API 不变的前提下（`RtcServer`、`Endpoint`、`Peer`、`PeerHandler` 及其顺序保证、
`ChannelConfig`、`Codec`、`SdpChanges`、`Event`、`RtcError` 等）改为运行在自研、sans-io、无第三方
依赖的 WebRTC 协议栈上。新增四个内部 crate，均为 `#![forbid(unsafe_code)]`，构建于 `only-crypto`
之上：

- `only-ice`：ICE（RFC 8445）完整 agent 与 ICE-lite：候选优先级与 foundation、带节奏控制与重传的
  检查列表、peer-reflexive 候选、常规提名、角色冲突（487）、在获得远端凭据之前到达的检查、consent
  freshness（RFC 7675）、trickle（RFC 8838）与重启；STUN 使用 `only-turn` 的编解码。RFC 5769 向量；
  与 pion/ice 互通。
- `only-srtp`：SRTP/SRTCP（RFC 3711、RFC 7714），支持 AES-CM-HMAC-SHA1-80/32 与
  AEAD-AES-128/256-GCM、ROC 估计、防重放窗口；RFC 3711 与 RFC 7714 向量，并与 pion/srtp 逐字节比对。
- `only-rtp`：RTP 头扩展（单字节与双字节形式）、RTCP（SR、RR、SDES、BYE、通用 NACK、PLI、FIR、REMB、
  传输层拥塞控制反馈）、带 NACK + RTX（RFC 4588）、报告与 RTT 的收发流、TWCC 与基于时延和丢包的
  带宽估计；Opus、G.711、G.722、VP8、VP9、H.264（RFC 6184）、H.265（RFC 7798）与 AV1 的载荷格式，
  以及无抖动缓冲延迟的组帧器。与 pion/rtp、pion/rtcp、pion/interceptor 逐字节比对。
- `only-sctp`：基于 DTLS 的 SCTP（RFC 8261；RFC 9260 的核心部分），拥塞控制、快速重传、PR-SCTP
  FORWARD-TSN（RFC 3758）、流重置（RFC 6525）、DCEP 数据通道（RFC 8831/8832）；经 UDP 与
  pion/sctp 1.8 和 1.12 互通。

`only-webrtc` 本身新增了 SDP offer/answer（BUNDLE、rtcp-mux、编解码器 / RTX / rtcp-fb / extmap 协商、
ssrc 与 FID 组、setup 角色与指纹、ICE-lite、候选、sctp-port / max-message-size、重新协商与 ICE 重启）
以及把各层粘合起来的 sans-io peer。测试覆盖模拟丢包链路（ICE + DTLS + SCTP + 媒体），并与 pion（数据
通道、Opus/VP8 回显、PLI、TURN 中继，两个 offer 方向）、fib 的 Go WebRTC（双向）以及无头 Chrome
（`tools/interop/webrtc/browser.sh`：数据通道，Chrome 的摄像头与麦克风媒体回显后由其解码，两个 offer
方向）互通。新增 fuzz 目标 `ice_stun`、`srtp_unprotect`、`rtp_rtcp`、`rtp_codec`、`sctp_packet`；
`webrtc_sdp` 现在驱动新的 SDP 代码。

迁移说明：

- `only-webrtc` 的 `unstable` feature 现在是预留的空 feature：`only_webrtc::str0m`、
  `crypto_provider_str0m`、`Peer::with_rtc`、`RtcConfig::with_str0m` 与 `OtherEvent::as_str0m`
  已移除（它们本就不在 semver 承诺内）。
- 受保护的 API 不变，只是 `Event`、`OtherEvent`、`RtcConfig`、`RtcError` 与 `SdpChanges` 现在实现了
  `RefUnwindSafe`（`RtcError` 还实现了 `UnwindSafe`）：只增加了 auto trait，没有减少。
- 行为：默认不再提供 H.265（用 `RtcConfig::enable_h265(true)` 开启）；DTLS 只支持 1.2（浏览器与 pion
  协商的都是 1.2）；应答方取 DTLS 客户端角色（`a=setup:active`）；`OtherEvent` 的 `Debug` 输出变了
  （它从来不是稳定的）；`Endpoint` 仍没有 TURN 客户端（与以前一样，relay 候选需在别处获得）。
- 依赖：str0m、dimpl、p256 / ecdsa / elliptic-curve、它们引入的 RustCrypto crate 以及 rand 0.9 已退出
  库的依赖图；only-dtls 与 dimpl 的内存互通测试已删除。p256/p384 0.13 仍是 only-crypto 交叉检查的
  dev-dependency，因此 `deny.toml` 中对 RUSTSEC-2026-0387（crypto-bigint）的忽略现在只涉及它们。

### 变更：自研 HTTP 编解码（不再依赖 httparse、loona-hpack、regex）

DEV-PLAN“长期：去除第三方依赖”第 A 波。公开 API 不变。

- HTTP/1 头部解析（only-http 的请求、chunked trailer 与客户端响应，only-ws 客户端握手响应）改用自研解析器
  `only_ws::http1`（`#[doc(hidden)]`）：零拷贝；增量（分多次读到的头部只扫描一遍，不再每次读都从头重新解析；
  会话也不再每次读都复制已缓存的字节）；按 RFC 9110/9112 严格校验：方法与字段名必须是 token，请求目标必须是
  可见 ASCII（httparse 放行的非 ASCII 字节现在返回 400），请求行各元素之间恰好一个 SP，拒绝孤立 CR、冒号前
  或首个字段前的空白以及过时的折行（响应中同样拒绝），行尾接受 CRLF 或单独 LF。头部值不再做 `str::trim`
  （按 RFC 9110 只去掉两侧的 SP/HTAB）。速度与 httparse（SIMD）相当，用的是安全代码中的按字扫描
  （`tools/codec-bench`）。
- HPACK 改为自研（`only_http::hpack`，`#[doc(hidden)]`）：编码器带动态表，Huffman 编码不更长时使用，
  `authorization` / `proxy-authorization` / 较短的 `cookie` 用 never-indexed 字面量，对端修改
  `SETTINGS_HEADER_TABLE_SIZE` 后按 RFC 7541 §4.2 发送动态表大小更新（loona-hpack 从不发送）；解码器带动态表，
  大小更新只允许出现在头部块开头且不超过我方设置，整数不超过 32 位，解码过程中即应用头部列表大小限制（整个块
  仍会处理完，使动态表保持同步）；Huffman 解码每次处理 4 位。RFC 7541 附录 C 的向量双向通过；h2spec 147/147。
- 路由约束（`{id:[0-9]+}`）改用自研线性时间引擎（`only_http::re`）：字面量、`.`、带范围/取反/转义的字符类、
  ASCII 的 `\d \w \s`（及其取反）、分组（含命名分组，不做捕获）、`|`、`* + ? {m} {m,} {m,n}` 及其惰性形式、
  `^`/`$`；不支持的语法（标志、`\b`、`\p{..}`、反向引用、POSIX 字符类、字符类集合运算、超过 1000 的计数）
  在注册时 panic 并指出问题。正则参数始终可用；only-http 的 `regex` cargo feature 保留为空操作以保持兼容。
- 模糊测试：`http1_request` / `http1_client` 将头部解析器与 httparse 对比，`hpack` 与 loona-hpack 对比（编解码
  双向互通），新增的 `regex_match` 与 `regex` crate 对比；这些 crate 只作为 `fuzz/` 与 `tools/codec-bench`
  微基准（都在库的 workspace 之外）的依赖保留。
### 变更（内部）：自研系统调用与 io_uring 绑定（不再依赖 `libc`、`io-uring`）

DEV-PLAN“不依赖三方库”第 B 波。公开 API 不变；行为、errno 与 `EINTR` 处理不变。

- `only-sys` 在 `only_sys::ffi`（`#[doc(hidden)]`，内部）中声明自有的操作系统绑定：C 类型、常量、`#[repr(C)]` 结构体（`sockaddr_in`/`in6`/`storage`/`ll`、`msghdr`、`mmsghdr`、带 `CMSG_*` 辅助函数的 `cmsghdr`、`iovec`、`epoll_event`（x86_64 上为 packed）、`kevent`、`timespec`、`pollfd`、`cpu_set_t`、`sigaction`、`utsname`），以及 C 库（Linux，glibc 或 musl）与 libSystem（macOS）函数的 `extern "C"` 声明。没有 C 封装的系统调用（`bpf`、`io_uring_*`）经 `syscall(2)` 调用，系统调用号按架构区分。支持 Linux x86_64 与 aarch64（riscv64 / loongarch64 共用通用布局）以及 macOS aarch64 / x86_64；其他 Linux 架构会以明确的错误信息编译失败，而不是悄悄使用错误的布局。
- 每个布局与常量都在仅测试用的模块中与 `libc` crate 对比（`libc` 现在只是 dev-dependency），已在 macOS aarch64、Linux aarch64 和 Linux x86_64 上验证。
- `only-uring` 拥有自研 io_uring 绑定（`ring`）：`io_uring_setup` / `io_uring_enter` / `io_uring_register`，按内核内存序访问的 mmap SQ/CQ ring 与 SQE 数组，反应器用到的提交项（multishot accept、带缓冲区选择的 multishot recv、poll add、async cancel 与 cancel-any、read），CQE 标志，opcode 探测与 `IORING_FEAT_*` 检查（探测现在也要求 `IORING_FEAT_EXT_ARG`），SQPOLL 以及 cooperative / single-issuer / deferred task-run 设置。buffer ring、`KernelBuf`、在途取消与 graveyard 逻辑不变。
- `only-ebpf` 与 `only-dpdk`（TAP、AF_PACKET）改用 `only_sys::ffi`。

### 变更（实验性层级）：only-dpdk 使用自研 TCP/IP 协议栈

`only-dpdk` 不再依赖 smoltcp（DEV-PLAN“去除第三方依赖”第 A 波）：用户态协议栈改为 only 自研，位于
`crates/only-dpdk/src/net`（安全 Rust，`#![forbid(unsafe_code)]`，无依赖），`Device` 种类、
`DpdkConfig` 与 `Backend::Dpdk` 的集成方式不变。

- 以太网 II；ARP 缓存 60 s，并为等待解析的报文排队（发往新邻居的第一个 SYN 不再被丢弃，smoltcp 版本
  因此要多等 1 s 的 SYN 重传）；IPv4 发送分片与带上限的重组（超过 MTU 的 UDP 数据报现在可用）；ICMP
  回显应答、端口/协议不可达，收到的不可达会交付给已拨出的 UDP 连接（以 `ConnectionRefused` 关闭，与
  内核后端一致）。
- 遵循 RFC 9293 的 TCP：RFC 6298 的 RTT / RTO，SACK（RFC 2018）与 RFC 6675 风格的恢复，NewReno
  快速恢复（RFC 6582），CUBIC（RFC 9438，默认）或 NewReno，窗口缩放与时间戳及 PAWS（RFC 7323），
  延迟 ACK，keepalive，可复用的 TIME-WAIT，RFC 5961 挑战 ACK，带 SYN cookie 的监听 backlog。
- I/O 循环改为事件驱动，并使用每连接一项的定时器堆（smoltcp 版本在每轮有流量的迭代中检查所有连接）；
  ACK 按接收批次合并；内存链路的一端发送后会唤醒对端线程。
- 多队列 DPDK 端口上可以拨号（原先返回 `Unsupported`）：本地端口对应其队列，RSS 放到其他队列的回包
  会被转交。
- `DpdkConfig` 新字段：`syn_cookies`（默认 `true`）、`congestion`（新类型 `only::dpdk::Congestion`，
  默认 `Cubic`）、`tcp_keepalive`（默认 `None`）。`udp_buffer` 现在限制每个 UDP 端口排队的数据报。
- TAP 与 AF_PACKET 设备直接使用 `libc`（`src/sys.rs`）；AF_PACKET socket 使用 8 MiB 接收缓冲区，并
  跳过本机发出的帧。
- 测试：逐层单元测试、虚拟时间中的模拟丢包/乱序链路，内核对端测试新增 `tc netem` 丢包、20 ms 下的
  4 MiB 窗口、500 条并发连接、向内核拨号与 ping；模糊测试目标 `dpdk_ethernet`、`dpdk_arp`、
  `dpdk_ipv4`、`dpdk_tcp`、`dpdk_udp`、`dpdk_icmp`、`dpdk_stack`。基准示例 `stack-bench`；与 smoltcp
  版本的 A/B 对比见 docs/BENCHMARKS.zh-CN.md。
- `deny.toml`：去掉了 smoltcp 带来的 0BSD 许可证与 `bitflags@1` 重复项。

### 变更（性能）：QUIC 与 TLS 热路径（DEV-PLAN 性能优化）

API 无变化。Ryzen 7 7800X3D，回环，交替运行三轮（见 docs/BENCHMARKS.zh-CN.md）：

- `only-quic`：单流大块吞吐 3.4-3.7 → 5.7-5.8 Gbit/s（quinn-proto 版本的 1.25 倍，之前为 0.72 倍），单连接 64 个并发的
  HTTP/3 请求 17.1 万 → 41.5-42.6 万次/秒，握手 +2%。pacer 原先把 RTT 下限设为 1 ms，令牌桶一空就通过定时器线程为每个包
  唤醒一次发送方；现在使用测得的 RTT，并等整批令牌补满再发（与 quinn-proto 相同），被 pacing 的数据以 GSO 批次从 I/O 线程
  发出（每 GiB：futex 调用 42.3 万 → 5600 次，上下文切换 18.2 万 → 9500 次）。另外每个包的簿记更省（流映射不再用 SipHash，
  按序插入区间只需一次查找，批次缓冲区与包号空间选择不再逐个数据报分配内存）。
- `only-tls`：收到的记录只复制一次，直接进入调用方的明文缓冲区并在那里解密（以前经过接收缓冲区再复制出来）；大块写入一次性
  为所有记录预留空间。16-64 KiB 记录的加密 + 解密提升 5-7%。握手经过剖析：98% 以上是曲线运算与哈希，因此未改动。新增
  `crates/only-tls/examples/tls-bench.rs`，与 rustls 0.23 + ring 对比（仅为开发依赖）。

### 变更（性能）：only-deflate 达到 zlib-rs 的速度（DEV-PLAN 性能优化）

`only-deflate`（仍为 `#![forbid(unsafe_code)]`，无依赖，不用 SIMD）的压缩速度现在为使用 zlib-rs
后端的 flate2 的 0.94-1.48 倍（之前为 0.25-0.9 倍），输出最多大 0.5%（45 组级别 × 语料中 36 组完全
相同）；解压为 0.82-1.23 倍（之前为 0.7-0.85 倍）。在 x86-64 上测量，表格见 docs/BENCHMARKS.zh-CN.md。
对每种窗口大小（8 按 9 布局）输出的流与之前一样有效；API 不变。

- 压缩采用 zlib-ng / zlib-rs 的级别表与匹配策略：四字节哈希（级别 9 为三字节）；级别 1 为 `quick`
  （每个位置只探测一次，直接写出固定编码块，若存储块更小则改用存储块），级别 2 为 `fast`，级别 3-6 为
  `medium`（贪心，级别 5 起向前多看一个匹配），级别 7-9 为惰性的 `slow`，级别 9 使用 zlib-ng 的跳链
  搜索。候选匹配先做廉价的排除检查，再每次比较 8 字节。**级别 1 的输出现在比之前最多大 40%**（与
  zlib-ng、zlib-rs 的级别 1 相同），速度为之前的 1.7-2.9 倍；级别 2-9 快 1.03-4 倍，输出比之前小 12%
  到大 3.4% 不等。
- `Deflater::reset`（不保留上下文的 permessage-deflate）对短流只清空它用过的哈希槽，而不是整张表；
  存储块直接从窗口写出；构造 Huffman 编码时统计码长不再受存储转发停顿影响。
- 解压：快速路径无分支地补充 64 位比特，每次补充后解码最多三个字面量或一个长度/距离对；匹配以 8 或
  16 字节为单位复制（重叠匹配也是）；完整编码的解码表不再预先清零。
- permessage-deflate 回显（`pmd_echo`，级别 6，保留上下文）与 zlib-rs 相比：64 B 消息 1.84 倍，
  512 B 1.04 倍，4 KiB 1.00 倍，64 KiB 0.98 倍（之前为 1.36 / 0.62 / 0.75 / 0.54 倍），线上字节与
  zlib-rs 相同。
- `bench` 示例覆盖级别 1..=9（`BENCH_LEVELS`）、生成的语料加上传入的文件，并提供剖析模式
  （`BENCH_PROFILE`）；新的流式测试覆盖每个级别、窗口大小与刷新方式。

### 新增

- `only-protobuf` 与 `only-protobuf-build`（DEV-PLAN“不依赖第三方”第 A 批）：自研的 protobuf
  运行时与代码生成器，取代 prost，没有任何依赖。
  - `only-protobuf`：线格式、`Message`（编码、解码、合并、长度前缀分帧）、开放枚举
    （`Enumeration`）、保留未知字段（`UnknownFields`）、`Name`、有界解码（最多 100 层嵌套、检查
    长度、检查 UTF-8；线类型不符的字段作为未知字段保留，与 C++、Go 一致），以及 `well_known`
    （`Empty`、`Timestamp`、`Duration`、`Any`、包装类型、`FieldMask`、`Struct` / `Value` /
    `ListValue`，含与 `std` 类型的转换和 `Any::pack` / `unpack`）。编码结果与 protoc 的 C++
    运行时逐字节一致。
  - `only-protobuf-build`：`.proto` 解析器（proto3 与 proto2：消息、嵌套类型、枚举、`optional`、
    `required`、`repeated`、`map`、`oneof`、默认值、package、import、内置 well-known 类型）与供
    `build.rs` 使用的 Rust 代码生成器（`compile(&["x.proto"], out_dir)`、`Config`），不需要
    `protoc`。service 生成 `only-grpc` 桩代码：`<service>_server` 中的 trait 与 `register`，以及
    类型化的 `<service>_client`；此时消息也实现 `only_grpc::codec::Message`。
  - 用 protoc 生成的黄金编码、与 prost 的差分（测试与 fuzz 目标 `protobuf_diff`），以及与 grpc-go
    自带的 route_guide / helloworld 生成代码双向互通（`tools/interop/grpc/run.sh`，新增
    `tools/protobuf-test`）做了验证。
- `only-grpc`：`Sink::send_message` 与 `ClientSink::send_message`（编码一个 `codec::Message` 后
  发送），以及重导出 `only_grpc::Headers`。

- `only-prefork`（M6，可选）：用多个 worker 进程服务同一个程序。supervisor 以 N 个 worker 的身份重新执行
  当前二进制（不在多线程之后 fork），每个 worker 运行自己的 `Engine`；监听套接字通过 `SO_REUSEPORT`
  共享（Linux 默认），或从 supervisor 继承（`ListenMode::Inherit`，macOS 默认；重启与重载期间不拒绝任何
  连接）；崩溃的 worker 按指数退避重启；SIGTERM/SIGINT 让 worker 排空后退出，SIGHUP（或
  `Supervisor::reload`）启动新一代 worker，并在替代者就绪后停止对应的旧 worker；可选 CPU 绑核（Linux）；
  `Worker` 提供序号、worker 数与代数。示例 `prefork-http`，手册章节“多进程服务（prefork）”。
- `only::Listener::tcp_from_std`：服务一个已绑定并在监听的套接字（从 supervisor 继承、systemd socket
  activation）；内部的 `EpollGroup::bind_listener` / `UringGroup::bind_listener`。
- `only-sys`（内部）：`process` 模块（在 `pre_exec` 中让子进程继承 fd、设置 CPU 亲和性与父进程退出信号，
  `take_inherited_fd`、`reserve_reuseport`、self-pipe 方式的 `signal_pipe`、`kill`）。
- `only-deflate`（内部，DEV-PLAN“不依赖第三方”第 A 波）：纯安全 Rust、无依赖的 DEFLATE、zlib 与 gzip，
  替代 `only-ws`（permessage-deflate）、`only-http`（压缩中间件）与 `only-grpc`（gzip 消息）中的
  `flate2`/`zlib-rs`。流式 `Inflater`（任意拆分输入、有界输出、窗口 2^8..2^15、与 zlib 相同的编码检查）
  与 `Deflater`（哈希链、惰性匹配、zlib 级别 0..=9、限长动态 Huffman、固定或存储块、同步/完全刷新、
  窗口 2^8..2^15），以及 Adler-32 与 CRC-32。与 zlib-rs 和 `gzip(1)` 双向互通；模糊测试目标
  `deflate_inflate`（与 zlib-rs 差分）和 `deflate_roundtrip`；Miri 运行其测试，Miri 任务重新运行
  only-grpc 的 gzip 测试（docs/unsafe-review.zh-CN.md 中 zlib-rs 的别名问题不再适用）。其他 crate 的公开
  API 不变。
- `only-ws`：permessage-deflate 支持 8 位窗口。服务端接受 `server_max_window_bits=8`（以前会拒绝该提议），
  被告知 `client_max_window_bits=8` 的客户端会压缩（以前发送未压缩消息）；此时压缩器把距离限制在
  250 字节以内。`deflate::Deflater`、`deflate::Inflater` 与 `protocol::Decoder` 现在实现 `UnwindSafe`
  （不再持有 zlib-rs 状态）。

### 弃用

- `only-grpc` 的 `prost` feature（不在 semver 承诺之内）：仍可使用，请改用 `only-protobuf` /
  `only-protobuf-build`。它可能在某个 minor 版本中移除。

### 修复

- `only-ws`：每个 WebSocket 连接都带着约 2 KB 内联的 permessage-deflate 状态（`Option` 中的
  only-deflate inflater 与 deflater），即使没有协商压缩；现在状态改为装箱。升级 + 一次 echo 之后的
  空闲连接：3,486 → 1,426 字节。
- io_uring：优雅关闭期间，multishot accept 在取消生效前已完成接受的连接会被重置；现在它们会被服务
  （收到第一份数据后调用 `on_shutdown`），并且排空要等 accept 真正结束才完成，监听套接字因此确实被关闭。
- `only-dpdk`（实验性，M6）：内核旁路后端。用户态 TCP/IP 协议栈（smoltcp，IPv4）运行在 only 的
  I/O 线程上，底层可以是 DPDK 端口（按 `EalConfig` 初始化 EAL，每个 rx/tx 队列对一个线程，mbuf
  批量收发，多队列时用 RSS 并在队列间扇出 ARP）、Linux TAP 接口、AF_PACKET socket 或进程内的
  `MemoryWire`。UDP listener 每次 `on_data` 交付一个数据报，TCP listener 交付字节流，支持
  `dial` / `dial_udp`、背压、空闲超时、遥测与优雅关闭，因此协议 crate（only-kcp 等）无需修改即可
  运行。同一设备上的多个 listener 共享该设备的协议栈与线程。
- `only`：cargo feature `dpdk`（`Backend::Dpdk(DpdkConfig)`，再导出 `only::dpdk`）与 `dpdk-pmd`
  （同时支持 DPDK 端口；通过 pkg-config 查找并链接 libdpdk）。实验性：不在 semver 承诺范围内
  （docs/api-stability.zh-CN.md）。
- `only-core`（面向后端，`#[doc(hidden)]`）：`ConnInner::new_virtual` 与
  `ConnInner::drain_output`，供由用户态协议栈搬运字节的连接使用。
- `tools/dpdk/`（Dockerfile + `test.sh`）与重型 CI 任务 `dpdk`：基于发行版的 DPDK 构建，并通过
  DPDK 的 `net_tap` PMD（单队列与双队列）smoltcp 的 TAP 设备以及 veth 对上的 AF_PACKET，与内核协议栈互测 UDP/TCP echo。
- `Engine::bind_udp` 与 `UdpBinding`（only、only-core）：在引擎运行中绑定的非连接 UDP socket，
  像 UDP 监听器一样服务（每个对端地址一个连接），并可用 `UdpBinding::send_to` 向任意地址发送。
  ICE agent 与 TURN 中继需要它。
- `only-turn`（新 crate）：STUN 编解码（RFC 8489，含 TURN 与 ICE 属性、`MESSAGE-INTEGRITY`、
  `FINGERPRINT`）、`StunServer`，以及 UDP 上的 TURN 中继 `TurnServer`（RFC 8656）：长期凭据的分配
  （`static_auth`，以及用于 TURN REST API 的 `ephemeral_auth`）、权限、通道、Send/Data 指示、刷新、
  `EVEN-PORT` 与 `RESERVATION-TOKEN`、无状态 nonce、配额，以及默认拒绝私有与回环对端的对端策略；
  `TurnCore` 是同一服务器的 sans-io 状态机。互通：pion/turn 客户端与 coturn 的
  `turnutils_uclient`。
- `only-webrtc`（新 crate）：基于 sans-io 的 `str0m` 0.24、跑在 only UDP 上的 WebRTC。
  `RtcServer` 服务一个 UDP 监听器（默认 ICE-lite，按 ICE 用户名与源地址分流各 peer）；`Endpoint`
  在 `bind_udp` socket 上运行完整 ICE agent，可从 STUN 服务器获取 server-reflexive 候选。`Peer`
  （任意线程）可在数据通道上发送、写媒体、请求关键帧、重新协商；`PeerHandler` 回调对每个 peer
  逐个执行。DTLS 1.2/1.3 与指纹校验、SRTP（AES-CM、AES-GCM）、SCTP 数据通道（可靠或不可靠、
  有序或无序）、带 NACK、PLI/FIR、TWCC 的 RTP/RTCP。纯 Rust 加密实现（RustCrypto 与 `dimpl`，
  无需 C 工具链）。与 pion 互通（两种 offer 方向的数据通道与媒体，以及经 only TURN 中继），并与 fib
  的 Go 版 WebRTC 互通（数据通道）；
  `tools/interop/webrtc/run.sh`。
- 模糊测试目标 `stun_message`、`turn_server` 与 `webrtc_sdp`。
- `only-media`（M7 流媒体），新 crate：一个流 hub，周围是 RTMP、RTSP、SRT、HTTP-FLV、WS-FLV、HLS
  以及 WHIP/WHEP 信令。
  - `hub`：按路径区分的流，一个推流者多个订阅者，用于秒开的 GOP 缓存，`Dropper`（慢播放者丢帧至下一个
    关键帧），推流 / 播放鉴权钩子，轨道未知前先预留路径，等待（重新）推流者，`Timeline` 时间戳规整，
    按流统计。
  - RTMP 服务端：简单握手与 Flash digest 握手、chunk 流、推流 / 播放、Enhanced RTMP（H.265 `hvc1`、
    Opus）；AMF0 / AMF3；FLV 封装 / 解封装（传统与增强 tag）。
  - HTTP-FLV 与 WS-FLV 播放（`HttpFlv`），MPEG-TS 分段的 HLS，支持 LL-HLS 分片、预加载提示与阻塞式刷新
    （`Hls`），同时分发二者的 `MediaHttp`；MPEG-TS 封装器。
  - RTSP 1.0 服务端（ANNOUNCE/RECORD、DESCRIBE/SETUP/PLAY，支持 TCP 交织与 UDP，Digest/Basic 鉴权），
    H.264/H.265/AAC/Opus/G.711 的 RTP 打包与解包（为带 B 帧的视频推算解码时间），SDP，以及带
    `WebRtcEngine` 集成 trait 的 WHIP/WHEP HTTP 信令。
  - SRT live 模式（HSv5 主叫/监听、ARQ、TSBPD、基于密码的 AES-CTR 加密、stream ID 访问控制），提供基于
    hub 的 `SrtServer` 与 `srt::dial` / `push` / `pull`；增量式 MPEG-TS 解复用器（`mpegts::demux`）。
  - 已与作为推流端和播放端的 ffmpeg / ffprobe 互通测试（SRT 在 Docker 中使用 libsrt）；模糊测试目标
    `rtmp_server`、`flv_demux`、`amf_decode`、`rtsp_server`、`sdp_parse`、`rtp_depacketize`、
    `mpegts_demux`、`srt_listener`、`srt_conn`。
- `only_ws::WsSender::queued_bytes`，供向慢速对端推流的生产者控制节奏。
- `only-bittorrent`（M7）：bencode；v1 .torrent 文件（路径安全检查、`Builder`）与磁力链接；HTTP
  与 UDP tracker 的编解码、`TrackerClient`（only-http、`dial_udp`）和 `TrackerServer`（共用一个
  存储的 only-http service 与 UDP acceptor）；带 Fast 扩展、扩展协议、ut_metadata 和 ut_pex 的
  peer wire 协议；MSE/PE（DH-768、RC4）；带 LEDBAT 的 uTP；主线 DHT；`port::UdpPort`，让 uTP 与
  DHT 共用一个 only UDP listener；以及 `client::Client`（磁力链接、带残局模式的最稀有优先选片、
  请求流水线、带乐观 unchoke 的 choke 算法、在逻辑池上进行的存储与 SHA-1 校验、PEX、DHT、
  tracker、事件）。与 libtorrent 2.0 和 aria2 1.37 互通（`tools/interop/bittorrent/run.sh`）；
  模糊测试目标 `bt_bencode`、`bt_peer_wire`、`bt_krpc`、`bt_utp`、`bt_tracker`、`bt_mse`。
- `Engine::dial_udp_from`：在 UDP listener 自己的 socket 上建立对端连接，使发往新地址的数据报从
  listener 的端口发出（DHT 节点、uTP）。

### 修复

- 当 engine 同时有 TCP listener 与 UDP listener（或 UDP 客户端线程）但没有 `client_threads` 时，
  `Engine::dial` 不再选中 UDP group（并因此失败）。

## [1.0.0-rc.1] - 2026-11-14

1.0 的第一个发布候选版：API 冻结以供评审。每个 crate 的公开 API 记录在 `api/<crate>.txt` 中，并在
CI 中检查。

### 新增

**核心引擎（M0–M1）**
- 每核一线程的事件循环：每个 I/O 线程拥有自己的 reactor、连接、缓冲区和定时器轮；回调直接在所属
  线程上运行，因此连接级 handler 状态无需加锁（ADR-001..004）。
- `Handler` / `Acceptor` / `fn_acceptor`，以及 `Conn`：可克隆的 `Send + Sync` 句柄，提供 `send`、
  `send_owned`、`send_shared`（`SharedBuf`）、`send_segments`、`cork`/`flush`、
  `close`/`close_after_send`、`hold_reads`、`on_drain`；连接关闭后使用句柄返回 `Error::Closed`。
- 后端：`only-epoll` 中的 epoll（Linux）与 kqueue（macOS）；`SO_REUSEPORT` 分发 accept；异步
  `Engine::dial`。
- 背压（写高水位、`max_queued_bytes`）、空闲与写超时、连接数上限、带超时的优雅停机。
- 连接发送路径的 `loom` 模型；5,000 个同时连接与 100,000 个空闲连接的压力测试。

**逻辑线程池、io_uring、UDP、TLS（M2）**
- `only-pool` 自适应有界线程池；`Conn::spawn_blocking`，完成回调回到连接所属 I/O 线程；有序响应
  槽（`Conn::reserve_response`、`ResponseSlot`、`ResponseStream`）。
- 慢回调检测（`Config::slow_callback_threshold`、`slow_hook`）。
- `only-uring`：io_uring 后端（multishot accept/recv、provided-buffer ring、内核探测并回退到
  epoll）；按 listener 选择后端（`Listener::backend`）。
- UDP：`Listener::udp`（每个对端一个 `Conn`）、`Engine::dial_udp`、`recvmmsg`/`sendmmsg`、UDP
  GSO/GRO、`udp_max_peers`。
- `only-tls`：rustls 作为 `Conn` 之下的 sans-io 传输层（`Tls::server`、`Tls::client`、`tls_info`）。

**HTTP 与 WebSocket（M3）**
- `only-http`：支持 pipelining、chunked 消息体与 trailer、流式请求与响应体的 HTTP/1.1 服务器，
  `Router`（静态 > `:param` > `*wildcard`、正则参数、嵌套、layer），中间件（recover、request id、
  CORS、logger、response time、compress、etag、csrf、limiter），静态文件（`files::Files`：range、
  预压缩文件、缓存、`sendfile`），HTTP/1 客户端（`client::Client`、`ResponseFuture`）。
- `only-ws`：RFC 6455 及 permessage-deflate、`PreparedMessage` 广播、子协议、origin 检查；服务端
  升级（`Context::upgrade_websocket`）与客户端（`only_ws::client`）；Autobahn 测试全部通过。

**HTTP/2 与更多协议（M4）**
- 基于同一 `Service` 的 HTTP/2 服务器（h2c prior knowledge 与 upgrade、ALPN `h2`、流量控制、HPACK、
  push）以及 `h2client::H2Client`；h2spec 全部通过。
- `only-mux`（一个端口上的多种协议）、`only-arpc`（lesismal/arpc 线上格式）、`only-grpc`（基于
  only-http 的 unary 与流式 gRPC、gzip、deadline、拦截器、可选 prost 辅助）、`only-socks`
  （SOCKS5/4/4a 与 HTTP CONNECT）。

**QUIC、HTTP/3、KCP、eBPF（M5）**
- `only-quic`（在 only UDP 上驱动 quinn-proto）与 `only-h3`（带 QPACK 的 HTTP/3，客户端与服务端）。
- `only-kcp`：与 skywind3000/kcp 和 kcp-go 兼容的 KCP（加密、Reed–Solomon FEC）。
- `only-ebpf`：通过 `Accel::Ebpf` 按 CPU 或一致性哈希的 `SO_REUSEPORT` 分流（经典 BPF 无需特权，
  有特权时用 eBPF），以及内核内的 sockmap `Relay`。

**生产就绪（M6）**
- 遥测：每线程计数器、`Engine::metrics`（Prometheus 与 JSON）、连接表、慢回调环形记录、设置热更新
  （`Engine::reload`）、`only_http::observe` 端点与 HTTP 指标。
- 带种子的混沌测试（engine、fd 耗尽、TLS、HTTP/WebSocket）。

**1.0 稳定化**
- 21 个 fuzz 目标及语料和覆盖率报告；`cargo-deny`/`cargo-audit` 门禁；unsafe 审查
  （docs/unsafe-review.zh-CN.md）、Miri 与 sanitizer job；严格的 lint 集；中英文 mdBook 指南及迁移
  指南；基准测试报告。
- API 冻结：`docs/api-stability.zh-CN.md`（semver、MSRV 与平台策略）、`docs/deprecation.zh-CN.md`、
  本变更日志、由 CI job `public-api` 检查的公开 API 快照（`api/*.txt`、`tools/api/public-api.sh`），
  以及在 1.0.0 发布后生效的 `semver-checks` job。
- 评审新增的 API：`AnyAcceptor` 与 `Listener::serve_any`（类型擦除的 acceptor，`only-mux` 使用）；
  `Request::new`、`ClientRequest::new`/`body`、`FileBody::new`；`only` 再导出 `Part`、
  `ResponseStream`、`Transport` 和 `SharedBuf`（`only-core` 也再导出 `SharedBuf`）；
  `only_h3::H3Error`；`InflateError`、`ProtocolError`（ws）、`FrameError`（arpc）和 `QpackError`
  实现 `Display`/`Error`；`only_core::Error::source` 返回底层 I/O 错误。
- 每个公开类型都实现 `Debug`；构建器方法带 `#[must_use]`。

### 变更（破坏性，附迁移方式）

配置与报告结构体以及将会增长的枚举现在是 `#[non_exhaustive]`：在 only 之外不能再使用结构体
字面量。从 `Default`（或预设）开始，再给字段赋值：

```rust
// 之前
let cfg = Config { idle_timeout: Some(d), ..Config::default() };
// 之后
let mut cfg = Config::default();
cfg.idle_timeout = Some(d);
```

受影响的结构体：`only`：`Config`、`UringConfig`、`EbpfConfig`、`PoolConfig`、`PoolStats`、
`SlowCallback`、`UdpStats`、`ConnInfo`、`LoopMeta`、`LoopCounters`、`LoopMetrics`、`Metrics`、
`ReloadReport`、`SlowRecord`；`only-tls`：`TlsInfo`；`only-http`：`HttpConfig`、`H2Config`、
`H2Options`、`WsOptions`、`Request`、`Response`、`FileBody`、`ClientRequest`、`ClientResponse`、
`Cors`、`Compress`、`LogRecord`、`HttpSnapshot`；`only-ws`：`WsConfig`、`DialOptions`、`PmdOffer`、
`PmdParams`、`ProtocolError`；`only-grpc`：`CallOptions`、`Status`、`Metadata`；`only-kcp`：
`KcpConfig`、`Stats`；`only-h3`：`H3Config`；`only-ebpf`：`AttachOptions`、`SteerInfo`、`Probe`；
`only-arpc`：`proto::Message`。枚举（`match` 需加通配分支）：`only::Error`、`Part`、`Backend`、
`Accel`、`AccelStatus`、`only_http::Method`、`Version`、`BodyMode`、`ClientError`、
`only_ws::client::WsClientError`、`deflate::InflateError`、`only_mux::Rule`、
`only_arpc::CallError`、`proto::Cmd`、`only_quic::Error`、`only_h3::qpack::QpackError`、
`only_kcp::KcpError`、`CloseReason`、`only_ebpf::Steering`、`HashKey`、`Tier`。

重命名与签名变更：

| Crate | 之前 | 之后 |
|---|---|---|
| only | `Listener::serve_dyn(Arc<dyn DynAcceptor>)`（隐藏） | `Listener::serve_any(impl Into<AnyAcceptor>)` |
| only-mux | `Mux::into_dyn() -> Arc<dyn DynAcceptor>` | `Mux::into_any() -> AnyAcceptor`（另有 `From<Mux> for AnyAcceptor`；可直接把 `Mux` 传给 `serve_any`） |
| only-mux | `Mux::route_dyn(rule, Arc<dyn DynAcceptor>)` | `Mux::route_any(rule, impl Into<AnyAcceptor>)` |
| only-mux | `Mux::max_sniff(n)` | `Mux::max_sniff_bytes(n)` |
| only-http | `H2Client::connect(..)` | `H2Client::dial(..)` |
| only-http | `H2Client::connect_blocking(..)` | `H2Client::dial_blocking(..)` |
| only-ws | `client::connect(..)`（阻塞） | `client::dial_blocking(..)` |
| only-ws | `INTERNAL_ERROR` | `protocol::close::INTERNAL` |
| only-arpc | `dial(..)`（阻塞） | `dial_blocking(..)` |
| only-arpc | `Routes::max_body(n)` | `Routes::max_body_bytes(n)` |
| only-grpc | `GrpcClient::gzip(bool)` | `GrpcClient::compress(bool)`（与 `GrpcServer::compress` 同名） |
| only-grpc | `GrpcServer::max_message(n)` | `GrpcServer::max_message_bytes(n)` |
| only-h3 | `H3Client::connect(..)` | `H3Client::dial(..)` |
| only-h3 | `server(quic, service)` | `serve(quic, service)` |
| only-h3 | `server_with(quic, service, cfg)` | `serve_with(quic, cfg, service)`（配置在 service 之前，与 `only_http::serve_with` 一致） |
| only-h3 | `H3Config::max_body`、`max_field_section` | `max_body_bytes`、`max_field_section_bytes` |
| only-h3 | `request`、`request_blocking`、`get` 返回 `Result<Response, String>` | `Result<Response, H3Error>`（`Closed`、`Reset(code)`、`Protocol`、`Timeout`） |
| only-kcp | `Config` | `KcpConfig` |
| only-kcp | `KcpServer::new`、`dial`、`dial_conv`、`Crypt::new` 返回 `Result<_, String>` | `std::io::Result<_>`（设置有误时为 `InvalidInput`） |
| only-kcp | `Kcp::stats: [u64; 4]`（公开字段） | 改为私有；请用 `Session::stats()` |
| only-ebpf | `Relay::new_unchecked(pairs)` | `Relay::new_any_kernel(pairs)` |
| only-ebpf | `Relay::splice_conns(&Arc<ConnInner>, &Arc<ConnInner>)` | `Relay::splice_conns(&Conn<A>, &Conn<B>)` |

移出受保护 API（现为 `#[doc(hidden)]`；面向后端或测试的辅助，可能在任何发布中变化）：
`only_core::{LoopLink, Task, Pool, LoopStats, telemetry::Counter, telemetry::json_str,
telemetry::prometheus_header}` 以及仅供后端使用的 `Telemetry` 方法、`only::{DynAcceptor,
DynHandler}` 再导出、`only_http::transport`、`only_ws::WsSession`、
`only_ebpf::{cbpf, SLOTS, slot_table, expected_index}`。

版本：所有 crate 均为 `1.0.0-rc.1`，相互之间以精确（`=`）版本依赖；`only-sys`、`only-buf`、
`only-timer`、`only-pool`、`only-epoll` 和 `only-uring` 是内部 crate，自身不作 semver 承诺
（见 docs/api-stability.zh-CN.md）。

[Unreleased]: https://github.com/lesismal/only/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/lesismal/only/releases/tag/v1.0.0-rc.1
