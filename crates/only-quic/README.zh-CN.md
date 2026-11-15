# only-quic

[English](README.md)

为 [`only`](https://github.com/lesismal/only) 提供 QUIC v1（RFC 9000、RFC 9001、RFC 9002）与不可靠数据报
（RFC 9221），在本 crate 中基于 [`only-tls`](../only-tls)（无记录层的 TLS 1.3）和
[`only-crypto`](../only-crypto) 实现：sans-io 协议核心，安全 Rust（`#![forbid(unsafe_code)]`），
无第三方依赖。它在 API 不变的前提下替换了 quinn-proto、其内部的 rustls 以及 `bytes` crate
（DEV-PLAN 第 D 波）。

`QuicServer` 是 UDP 监听器的 acceptor：一个 endpoint 按连接 ID 把每个数据报路由到对应连接，
因此客户端换了地址连接仍然保持。`dial` 在带 UDP 客户端线程的引擎上发起客户端连接。处理器实现
`QuicHandler`（流数据、重置、停止、数据报、关闭）；写入从不阻塞。用 `server_config` /
`client_config`（或接受 `only::tls` 配置的 `*_from` 变体）和 `TransportConfig`（流数量上限、窗口、
空闲超时、保活、MTU 探测、数据报缓冲、NewReno 或 CUBIC）进行配置。

```rust,no_run
use only::{Engine, Listener};
use only_quic::{Bytes, Connection, QuicHandler, QuicServer, StreamId};

struct Echo;
impl QuicHandler for Echo {
    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        let _ = c.send(id, data);
        if fin {
            let _ = c.finish(id);
        }
    }
}
let certs = only::tls::Certificate::from_pem(&std::fs::read("cert.pem").unwrap()).unwrap();
let key = only::tls::PrivateKey::from_pem(&std::fs::read("key.pem").unwrap()).unwrap();
let cfg = only_quic::server_config(certs, key, &[b"echo"]).unwrap();
let engine = Engine::builder()
    .listen(Listener::udp("0.0.0.0:4433".parse().unwrap()).serve(QuicServer::new(cfg, |_c: &Connection| Echo)))
    .build()
    .unwrap();
engine.run().unwrap();
```

## 协议

- **数据包**：长/短包头，Initial / Handshake / 1-RTT 三个包号空间，包号编码与解码，包头保护（AES 与
  ChaCha20），AEAD 包保护（AES-128/256-GCM、ChaCha20-Poly1305），合并数据包，Initial 与路径验证数据报的
  填充，版本协商，带完整性标签的 Retry，无状态重置（对未知连接 ID 发送，限速且小于触发包；按令牌识别），
  1-RTT 密钥更新（RFC 9001 第 6 节：每几百万个包发起一次，对端发起时跟随，旧密钥为迟到的包保留一段时间）。
- **帧**：RFC 9000 的全部帧（PADDING、PING、带区间和 ECN 计数的 ACK、RESET_STREAM、STOP_SENDING、
  CRYPTO、NEW_TOKEN、STREAM、MAX_DATA、MAX_STREAM_DATA、MAX_STREAMS、DATA_BLOCKED、
  STREAM_DATA_BLOCKED、STREAMS_BLOCKED、NEW_CONNECTION_ID、RETIRE_CONNECTION_ID、PATH_CHALLENGE、
  PATH_RESPONSE、CONNECTION_CLOSE、HANDSHAKE_DONE）以及 DATAGRAM（RFC 9221），并遵守 RFC 9000 第 12.4
  节按包类型的限制。
- **流**：双向与单向，隐式打开，流级与连接级流量控制及窗口更新，流数量上限（MAX_STREAMS 批量下发），
  最终大小检查，收到 STOP_SENDING 时以 RESET_STREAM 回应。
- **恢复**（RFC 9002）：RTT 估计，按包序与时间阈值的丢包检测，带退避的探测超时与握手防死锁探测，持续
  拥塞，NewReno 与 CUBIC（RFC 9438），发送节奏控制（pacing），地址验证前 3 倍放大限制，ACK 延迟与立即
  ACK 规则，空闲超时，保活，路径 MTU 探测（DPLPMTUD，探测到 1452 字节）。
- **握手**：通过 `only_tls::quic::QuicTls` 运行 TLS 1.3（必须 ALPN），传输参数及 initial_source /
  original_destination / retry_source 连接 ID 校验，基于票据的会话恢复，用 Retry 令牌和 NEW_TOKEN 令牌做
  地址验证（令牌按服务器名保存在 `ClientConfig` 中）。
- **连接 ID**：8 字节 ID，用 NEW_CONNECTION_ID 按对端上限下发，退役后补充，由 endpoint 路由；按
  retire_prior_to 跟踪对端的 ID 与重置令牌。
- **迁移**：客户端换地址（NAT 重绑定、端口变化）后，经路径验证（PATH_CHALLENGE / PATH_RESPONSE）跟随；
  IP 变化时重置拥塞状态，对端给过新的连接 ID 时换用新 ID；`ServerConfig::migration(false)` 拒绝迁移。
- **I/O**：满尺寸的数据报成批地用一次 GSO 发送（`Conn::send_segments`，最多 10 段）；在连接自身回调中
  发起的写入会先攒起来，回调返回后与 ACK 一起发出。收到的数据报逐个处理（处理器事件与待发数据
  立即处理），但 ACK 每个接收批次只生成一次，在 I/O 循环内部的批次结束钩子里；UDP GRO（Linux 上
  默认开启）让大流量接收方一次拿到整批 GSO 数据。收到的包只复制一次，进入每线程池化的缓冲区并在
  其中解密，流数据和数据报都是它的切片；切片全部释放后缓冲区被复用。已发送的包记录在按包号索引的
  环形缓冲中。一个共享的定时器线程驱动各种超时。

未实现：0-RTT（发送与接受；`only-tls` 拒绝早期数据）、发送 ECN 标记（会解析收到的 ECN 计数；socket 层
不暴露 TOS 字节）、客户端主动迁移（API 没有重新绑定的入口）、preferred_address（解析但不使用）、BBR
（`Congestion::Bbr` 实际运行 CUBIC）、QUIC v2。

## 内部结构

- `proto`（crate 私有）：sans-io 核心：`packet`（包头、保护、包号）、`crypto`（包密钥、包头保护、
  Initial 密钥、Retry 标签、密钥更新、令牌）、`frame`、`params`（传输参数）、`stream`（发送与接收
  缓冲）、`ranges`、`recovery`（RTT、NewReno、CUBIC、pacer）、`conn`（连接：接收路径、发送路径、流）、
  `endpoint`（按连接 ID 路由、Retry、版本协商、无状态重置），以及 `sim`：用于测试的带虚拟时钟、会丢包/
  乱序/重复的模拟链路。
- `bytes`：负载类型 `Bytes`（克隆与切片代价低；收到的数据是解密后数据包的切片），以及每线程的
  接收缓冲池。
- `fuzzing`（`#[doc(hidden)]`，feature `fuzzing`）：`quic_packet`、`quic_frame`、`quic_conn` 模糊测试
  目标的入口。

## 测试

- RFC 9001 附录 A 向量：Initial 密钥派生、客户端与服务端 Initial 包、Retry 完整性标签、ChaCha20 短包头
  数据包、密钥更新。
- 各组件的单元测试与模拟网络测试：30% 丢包下的握手；10% 丢包、乱序、重复、MTU 1350 的链路上传输 2 MB
  外加 40 条流；小窗口与流数量上限；NAT 重绑定与端口变化；拒绝迁移；任一端发起的密钥更新以及每 100 个包
  自动更新；ChaCha20 与 AES-256 套件；Retry；NEW_TOKEN 与会话恢复；版本协商；无状态重置；空闲超时与保活；
  握手前后的关闭；数据报；重置与停止；4 秒断网；NewReno。
- 互通：`tools/interop/quic/run.sh`（与 quic-go 的原生 QUIC 流与数据报回显，双向，含 Retry、密钥更新与
  150 MB 传输）、`tools/interop/h3/run.sh`（与 quic-go、fib 的 HTTP/3 双向互通），以及
  `tools/interop/quic/docker.sh`（在 Debian 的 `rust:1` 镜像中，以通过 libcurl-gnutls 的 ngtcp2 和通过
  curl、libcurl、`openssl s_client -quic` 的 OpenSSL 3.5 QUIC 作为我方 HTTP/3 与回显服务端的客户端）。
- 模糊测试目标 `quic_packet`、`quic_frame`、`quic_conn`，并在 stable 上回放语料。
