# 变更日志

[English](CHANGELOG.md)

only 的所有重要变更都记录在这里。格式遵循
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，only 从 1.0.0 起遵循
[语义化版本](https://semver.org/lang/zh-CN/)，具体定义见
[docs/api-stability.zh-CN.md](docs/api-stability.zh-CN.md)。弃用遵循
[docs/deprecation.zh-CN.md](docs/deprecation.zh-CN.md)。workspace 中所有 crate 共用一个版本号。

## [Unreleased]

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
