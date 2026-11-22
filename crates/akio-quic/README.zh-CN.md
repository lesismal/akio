# akio-quic

[English](README.md)

为 [`akio`](https://github.com/lesismal/akio) 提供 QUIC v1（RFC 9000、RFC 9001、RFC 9002）、v2（RFC 9369）与不可靠数据报
（RFC 9221），在本 crate 中基于 [`akio-tls`](../akio-tls)（无记录层的 TLS 1.3）和
[`akio-crypto`](../akio-crypto) 实现：sans-io 协议核心，安全 Rust（`#![forbid(unsafe_code)]`），
无第三方依赖。它在 API 不变的前提下替换了 quinn-proto、其内部的 rustls 以及 `bytes` crate
（DEV-PLAN 第 D 波）。

`QuicServer` 是 UDP 监听器的 acceptor：一个 endpoint 按连接 ID 把每个数据报路由到对应连接，
因此客户端换了地址连接仍然保持。`dial` 在带 UDP 客户端线程的引擎上发起客户端连接。处理器实现
`QuicHandler`（流数据、重置、停止、数据报、关闭）；写入从不阻塞。用 `server_config` /
`client_config`（或接受 `akio::tls` 配置的 `*_from` 变体）和 `TransportConfig`（流数量上限、窗口、
空闲超时、保活、MTU 探测、数据报缓冲、NewReno、CUBIC 或 BBR、ECN）进行配置。

```rust,no_run
use akio::{Engine, Listener};
use akio_quic::{Bytes, Connection, QuicHandler, QuicServer, StreamId};

struct Echo;
impl QuicHandler for Echo {
    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        let _ = c.send(id, data);
        if fin {
            let _ = c.finish(id);
        }
    }
}
let certs = akio::tls::Certificate::from_pem(&std::fs::read("cert.pem").unwrap()).unwrap();
let key = akio::tls::PrivateKey::from_pem(&std::fs::read("key.pem").unwrap()).unwrap();
let cfg = akio_quic::server_config(certs, key, &[b"echo"]).unwrap();
let engine = Engine::builder()
    .listen(Listener::udp("0.0.0.0:4433".parse().unwrap()).serve(QuicServer::new(cfg, |_c: &Connection| Echo)))
    .build()
    .unwrap();
engine.run().unwrap();
```

## 协议

- **数据包**：长/短包头，Initial / Handshake / 1-RTT 三个包号空间，包号编码与解码，包头保护（AES 与
  ChaCha20），AEAD 包保护（AES-128/256-GCM、ChaCha20-Poly1305），合并数据包，Initial 与路径验证数据报的
  填充，QUIC 版本 1 与 2（RFC 9369：其 salt、HKDF 标签、Retry 密钥与长包头类型位），版本协商（客户端
  在双方都支持的版本上重新开始一次，并以 RFC 9368 的 version_information 参数防降级；
  `ClientConfig::version`、`ServerConfig::versions`），带完整性标签的 Retry，无状态重置（对未知连接 ID 发送，限速且小于触发包；按令牌识别），
  1-RTT 密钥更新（RFC 9001 第 6 节：每几百万个包发起一次，对端发起时跟随，旧密钥为迟到的包保留一段时间）。
- **帧**：RFC 9000 的全部帧（PADDING、PING、带区间和 ECN 计数的 ACK、RESET_STREAM、STOP_SENDING、
  CRYPTO、NEW_TOKEN、STREAM、MAX_DATA、MAX_STREAM_DATA、MAX_STREAMS、DATA_BLOCKED、
  STREAM_DATA_BLOCKED、STREAMS_BLOCKED、NEW_CONNECTION_ID、RETIRE_CONNECTION_ID、PATH_CHALLENGE、
  PATH_RESPONSE、CONNECTION_CLOSE、HANDSHAKE_DONE）以及 DATAGRAM（RFC 9221），并遵守 RFC 9000 第 12.4
  节按包类型的限制。
- **流**：双向与单向，隐式打开，流级与连接级流量控制及窗口更新，流数量上限（MAX_STREAMS 批量下发），
  最终大小检查，收到 STOP_SENDING 时以 RESET_STREAM 回应。
- **恢复**（RFC 9002）：RTT 估计，按包序与时间阈值的丢包检测，带退避的探测超时与握手防死锁探测，持续
  拥塞，NewReno、CUBIC（RFC 9438）与 BBR（见下），发送节奏控制（pacing），地址验证前 3 倍放大限制，ACK 延迟与立即
  ACK 规则，空闲超时，保活，路径 MTU 探测（DPLPMTUD，探测到 1452 字节）。
- **握手**：通过 `akio_tls::quic::QuicTls` 运行 TLS 1.3（必须 ALPN），传输参数及 initial_source /
  original_destination / retry_source 连接 ID 校验，基于票据的会话恢复，用 Retry 令牌和 NEW_TOKEN 令牌做
  地址验证（令牌按服务器名保存在 `ClientConfig` 中）。
- **连接 ID**：8 字节 ID，用 NEW_CONNECTION_ID 按对端上限下发，退役后补充，由 endpoint 路由；按
  retire_prior_to 跟踪对端的 ID 与重置令牌。
- **ECN**（RFC 9000 第 13.4 节、RFC 9002 第 7.1 节；`TransportConfig::ecn`，默认开启）：在 UDP 层能
  设置码点的地方（Linux 上每条 `sendmmsg` 消息、macOS 上每次 `sendmsg` 带一个 `IP_TOS` /
  `IPV6_TCLASS` 控制消息，akio-dpdk 用户态协议栈下直接写入 IP 头；内核套接字上可用
  `AKIO_UDP_ECN=0` 关闭）以 ECT(0) 发送；从 `IP_RECVTOS` / `IPV6_RECVTCLASS` 控制消息（akio-dpdk 下
  从 IP 头）读取收到的码点并
  在 ACK_ECN 帧中报告；用十个包的测试期（遇到探测超时提前结束，丢弃带标记包的路径只多花一个 PTO）和
  对端计数验证路径；CE 标记视为拥塞事件；清除、改写或丢弃标记的路径回退为不带标记发送。
  `ConnectionStats::ecn_capable` / `ecn_ce_events`。
- **BBR**（`Congestion::Bbr`，实验性）：基于投递速率采样的 BBRv1 模型与状态机（2/ln 2 增益的
  Startup、Drain、ProbeBW 增益循环、ProbeRTT），加上 BBRv2/v3 的丢包与 ECN 上限：一轮中丢失或被 CE
  标记的字节超过 2% 时结束 Startup，并把在途数据限制在一个 BDP 与 0.7 倍窗口中的较大者，之后每个
  干净的轮次回升八分之一。pacer 按其 pacing 速率发送。未实现 v3 的带宽与在途下限、探测时间表与
  DCTCP 式 ECN 比例。
- **迁移**：客户端换地址（NAT 重绑定、端口变化）后，经路径验证（PATH_CHALLENGE / PATH_RESPONSE）跟随；
  IP 变化时重置拥塞状态，对端给过新的连接 ID 时换用新 ID；`ServerConfig::migration(false)` 拒绝迁移。
  客户端可用 `Connection::migrate(&engine)` 主动迁移：服务端提供了首选地址
  （`ServerConfig::preferred_address`，由同一个 `QuicServer` 的克隆在第二个监听器上提供服务）时迁到
  该地址，否则换一个新的本地 UDP socket；新路径先用一个未用过的连接 ID 探测，得到回应后切换（拥塞、
  ECN 与 RTT 状态重新开始，旧 socket 关闭），三个 PTO 内无回应则放弃。对来自其他地址的探测的回应使用
  单独的连接 ID（RFC 9000 第 9.5 节）。
- **I/O**：满尺寸的数据报成批地用一次 GSO 发送（`Conn::send_segments`，最多 10 段）；在连接自身回调中
  发起的写入会先攒起来，回调返回后与 ACK 一起发出。收到的数据报逐个处理（处理器事件与待发数据
  立即处理），但 ACK 每个接收批次只生成一次，在 I/O 循环内部的批次结束钩子里；UDP GRO（Linux 上
  默认开启）让大流量接收方一次拿到整批 GSO 数据。收到的包只复制一次，进入每线程池化的缓冲区并在
  其中解密，流数据和数据报都是它的切片；切片全部释放后缓冲区被复用。已发送的包记录在按包号索引的
  环形缓冲中。一个共享的定时器线程驱动各种超时。

**0-RTT**（RFC 9001 第 4.6 节），双方默认关闭：`ServerConfig::zero_rtt(true)` 与
`ClientConfig::zero_rtt(true)`。客户端用允许 0-RTT 的票据恢复会话时，从服务端上次给出的传输参数起步
（RFC 9000 7.4.1：只记限额，不记连接 ID、令牌或地址），`dial` 之后立即可以打开流，流数据放在 0-RTT
包中发送（应用数据包号空间，合并在 Initial 之后；版本 1 与 2 均支持）。服务端只在限额与签发票据时相同
的情况下接受 0-RTT，并使用 `akio-tls` 的防重放（10 秒新鲜度窗口加上每个服务端一份有上限的近期
ClientHello 记录，见其 README），以 0.5-RTT 应答。被拒或丢失的 0-RTT 数据会重发（以 1-RTT 发送；Retry
之后以 0-RTT 发往新的连接 ID）。客户端通过 `Connection::early_data()` 得知结果；服务端用
`Connection::is_early(stream)` 判断，akio-h3 会给这类请求加上 `Early-Data: 1`（RFC 8470）。
**0-RTT 数据可被重放**（发往共享票据的其他服务端，或在窗口内由能诱使客户端重试的攻击者发起），且没有
前向保密：只处理可安全重复的请求，其余回 `425 Too Early`。

兼容版本协商（RFC 9368 第 4 节，ADR-013 与 ADR-014）：服务端偏好版本 2 时
（`ServerConfig::prefer_version`）在一次握手内把版本 1 客户端切换到版本 2，并做 version_information
防降级检查；与 ngtcp2 的互通见 `tools/interop/quic/ngtcp2-cvn.sh`（quic-go 未实现 RFC 9368）。ECN 标记在
Linux、macOS 与 akio-dpdk 上设置和读取（ADR-035）；其他平台上连接不打标记。

quic-go（v0.62）对版本 2 的密钥更新用 v1 的标签 `quic ku` 派生，而 RFC 9369 第 3.3.2 节（及其测试向量
A.5）规定为 `quicv2 ku`；它在 100 个包后发起第一次密钥更新，因此与 quic-go 的版本 2 连接会在那里停住。
本 crate 遵循 RFC。

## 内部结构

- `proto`（crate 私有）：sans-io 核心：`packet`（包头、保护、包号）、`crypto`（包密钥、包头保护、
  Initial 密钥、Retry 标签、密钥更新、令牌）、`frame`、`params`（传输参数）、`stream`（发送与接收
  缓冲）、`ranges`、`recovery`（RTT、NewReno、CUBIC、pacer）、`bbr`（BBR 及其速率采样）、`conn`（连接：
  接收路径、发送路径、流、`ecn`、`migrate`）、`endpoint`（按连接 ID 路由、Retry、版本协商、无状态重置），
  以及 `sim`：用于测试的带虚拟时钟、会丢包/乱序/重复的模拟链路，可加上限速的尾部丢弃瓶颈，并可打 CE
  标记、清除或黑洞 ECN。
- `bytes`：负载类型 `Bytes`（克隆与切片代价低；收到的数据是解密后数据包的切片），以及每线程的
  接收缓冲池。
- `fuzzing`（`#[doc(hidden)]`，feature `fuzzing`）：`quic_packet`、`quic_frame`、`quic_conn` 模糊测试
  目标的入口。

## 测试

- RFC 9001 附录 A 向量：Initial 密钥派生、客户端与服务端 Initial 包、Retry 完整性标签、ChaCha20 短包头
  数据包、密钥更新；版本 2 的 RFC 9369 附录 A 向量（Initial 密钥、Retry 标签、ChaCha20 数据包与密钥
  更新）。
- 各组件的单元测试与模拟网络测试：30% 丢包下的握手；10% 丢包、乱序、重复、MTU 1350 的链路上传输 2 MB
  外加 40 条流；小窗口与流数量上限；NAT 重绑定与端口变化；拒绝迁移；任一端发起的密钥更新以及每 100 个包
  自动更新；ChaCha20 与 AES-256 套件；Retry；NEW_TOKEN 与会话恢复；版本协商；无状态重置；空闲超时与保活；
  握手前后的关闭；数据报；重置与停止；4 秒断网；NewReno；ECN 验证及在打标记的 AQM 后对 CE 退避，
  被清除、黑洞或关闭时的回退；BBR 以很小的队列填满 20 Mbit/s 瓶颈、1% 随机丢包下吞吐为 CUBIC 的 4 倍、
  浅缓冲上丢包有界；客户端迁移到新端口（两次）、探测失败时留在原路径、被 disable_active_migration
  拒绝、迁移到首选地址；带 Retry 与密钥更新的版本 2、版本协商后以版本 2 重新开始、伪造的版本协商被
  识别为降级。环回网络上：迁移到首选地址与新端口、版本 2，以及 Linux 与 macOS 上的 ECN 验证。
  `quic_conn` 模糊测试目标还会选择路径如何对待 ECN（保留、清除、标记 CE、改标 ECT(1)）。
- 互通：`tools/interop/quic/run.sh`（与 quic-go 的原生 QUIC 流与数据报回显，双向，含 Retry、密钥更新与
  150 MB 传输；双向版本 2；双向客户端迁移，我方使用 BBR；Linux 上与 quic-go 的 ECN 验证）、`tools/interop/h3/run.sh`（与 quic-go、fib 的 HTTP/3 双向互通），以及
  `tools/interop/quic/docker.sh`（在 Debian 的 `rust:1` 镜像中，以通过 libcurl-gnutls 的 ngtcp2 和通过
  curl、libcurl、`openssl s_client -quic` 的 OpenSSL 3.5 QUIC 作为我方 HTTP/3 与回显服务端的客户端）。
- 模糊测试目标 `quic_packet`、`quic_frame`、`quic_conn`，并在 stable 上回放语料。
