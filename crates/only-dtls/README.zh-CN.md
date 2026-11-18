# only-dtls

[English](README.md)

[`only`](https://github.com/lesismal/only) 的 sans-io DTLS 1.2（RFC 6347）与 DTLS 1.3（RFC 9147），构建在
[`only-crypto`](../only-crypto) 与 [`only-x509`](../only-x509) 之上，安全 Rust
（`#![forbid(unsafe_code)]`），没有其他依赖。它是 DEV-PLAN 第 D 波计划中自研 WebRTC 协议栈的 DTLS 层
（DTLS-SRTP 密钥、SCTP 数据通道），由 `only-webrtc` 使用。这是内部 crate
（docs/api-stability.zh-CN.md）：API 跟随该协议栈的需要，可能在任何发布中变化。

## 驱动连接

`Connection` 没有套接字、线程或时钟。调用方传入每个收到的数据报和当前时间，并发送它产生的数据：

```rust,ignore
use std::sync::Arc;
use std::time::Instant;
use only_dtls::{Config, Connection, Event, Identity, PeerVerifier, Role};

let identity = Identity::generate_self_signed()?;           // 其指纹写入 SDP
let remote = only_dtls::Fingerprint::parse("sha-256 AB:CD:...")?; // 来自对端 SDP
let config = Arc::new(Config::webrtc(identity, PeerVerifier::Fingerprints(vec![remote])));
let mut conn = Connection::new(config, Role::Client, Instant::now(), b"203.0.113.9:5000")?;
loop {
    while let Some(datagram) = conn.poll_transmit() { /* socket.send(&datagram) */ }
    while let Some(event) = conn.poll_event() {
        match event {
            Event::Connected(info) => { /* info.srtp_keys、info.peer_fingerprint */ }
            Event::ApplicationData(data) => { /* SCTP 包 */ }
            Event::Closed => { /* close_notify */ }
            _ => {}
        }
    }
    // 等待数据报直到 conn.poll_timeout()，然后：
    // conn.handle_datagram(Instant::now(), &datagram)?  或  conn.handle_timeout(Instant::now())?
}
```

- `Connection::client` / `Connection::server` / `Connection::new(config, role, now, peer)`：
  WebRTC 根据 `a=setup` 选择角色（`active` 为客户端）。`peer` 是对端传输地址的任意稳定编码，会被绑定进
  HelloVerifyRequest cookie。
- `send_application_data(&[u8])` 把一条记录（≤ 16384 字节）作为一个数据报发送。
- `export_keying_material(label, context, len)` 是 RFC 5705 导出器；`HandshakeInfo::srtp_keys`
  已经包含 `EXTRACTOR-dtls_srtp` 的输出，并拆分为客户端与服务端的主密钥和盐
  （`SrtpKeys::local(role)` / `remote(role)`）。
- `close()` 发送 close_notify。致命错误会发送相应告警，并由 `handle_datagram` / `handle_timeout` 返回。
- `HelloVerifier::check(now, peer, datagram)` 让监听方无状态地应答 ClientHello
  （`Respond(hello_verify_request)`），只在 cookie 有效时（`Accept`）才创建 `Connection`。

## 协议覆盖

- 记录层：epoch、48 位序列号、每个 epoch 一个 64 条记录的防重放窗口、一个数据报中可含多条记录；
  未通过认证、重放或格式错误的记录被静默丢弃（RFC 6347 §4.1.2.7）；连接建立后忽略 epoch 0 的告警。
- 握手：两种角色的完整 ECDHE 握手；消息按 `Config::with_mtu` 分片，并可从任意顺序重组（16 条消息的
  窗口，每条消息最多 64 KiB）；flight 按指数退避重传（默认 1 秒起翻倍至 60 秒，RFC 6347 §4.2.4），
  对端重发上一 flight 时也重传；握手截止时间（默认 30 秒）；无状态的 HMAC-SHA-256 cookie，密钥每分钟轮换。
- 密码套件：`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`（WebRTC 基线）、`..._AES_256_GCM_SHA384`、
  `..._CHACHA20_POLY1305_SHA256`，以及对应的三个 RSA 套件。群 X25519、P-256、P-384（非压缩点）。签名
  ECDSA（SHA-256/384/512）、Ed25519、RSA-PSS 与 RSA PKCS#1 v1.5（SHA-256/384/512）。
- 扩展：`extended_master_secret`（RFC 7627；默认必需）、`use_srtp`（RFC 5764：
  `SRTP_AEAD_AES_128_GCM`、`SRTP_AEAD_AES_256_GCM`、`SRTP_AES128_CM_HMAC_SHA1_80`、
  `SRTP_AES128_CM_HMAC_SHA1_32`，不支持 MKI）、`renegotiation_info`（RFC 5746）、`supported_groups`、
  `ec_point_formats`、`signature_algorithms`。拒绝重协商（`no_renegotiation`）。
- 认证：默认双向（`with_require_client_certificate`）。不做 CA 路径校验：`PeerVerifier::Fingerprints`
  固定证书（SDP `a=fingerprint`），`PeerVerifier::Custom` 调用回调（例如 `only_x509::Verifier`），
  `AcceptAny` 把检查交给调用方（`HandshakeInfo::peer_fingerprint`）。对端始终要证明持有证书私钥。

DTLS 1.3、连接 ID、会话恢复与 PSK（ADR-021）：

- 版本：`Config::with_versions`（默认只有 DTLS 1.2，`Config::webrtc` 也是）。同时启用时连接以 DTLS 1.3
  起步，遇到只支持 1.2 的对端以 DTLS 1.2 继续（设置并检查 RFC 8446 降级标记）。
- DTLS 1.3：套件 `TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384`、`TLS_CHACHA20_POLY1305_SHA256`；
  带记录号加密的统一记录头（16 位序号、显式长度）；epoch 2 用于握手，3 及以上用于数据，每次 KeyUpdate
  加一（`Connection::update_keys`；2^23 条记录后自动更新）；ACK：发现空洞时、一轮未收齐时 RTO 的四分之一
  后、最后一轮和重发时立即；只重传未确认的分片；无状态的 HelloRetryRequest cookie（套件、组、ClientHello1
  哈希，用 `HelloVerifier` 的 HMAC 保护），`HelloVerifier::check` 也可发出；EncryptedExtensions 中的
  `use_srtp`；TLS 1.3 导出器。
- 连接 ID：`Config::with_connection_id(Some(len))`；DTLS 1.2 用 RFC 9146 `tls12_cid` 记录，DTLS 1.3 把
  CID 放在统一头里；`connection_id(datagram, len)` 用于分发。
- 会话恢复：`Config::with_session_resumption(true)`；DTLS 1.2 会话 ID（1024 条缓存）与 RFC 5077 票据，
  DTLS 1.3 NewSessionTicket（`psk_dhe_ke`）；票据用 `TicketKey` 以 AES-256-GCM 封装，携带对端证书链（恢复
  时再次校验）；`Event::NewSession` / `Connection::client_resume`。
- PSK：`Config::with_psks`；DTLS 1.2 的 `TLS_PSK_WITH_*` 与 `TLS_ECDHE_PSK_WITH_*` AEAD 套件，DTLS 1.3 的
  外部 PSK（SHA-256）。

未实现：DTLS 1.3 0-RTT、NewConnectionId / RequestConnectionId、握手后客户端认证、非 ECDHE 的证书密钥交换、
CBC 套件、SRTP MKI。

## 测试

- 模拟链路（`tests/loopback.rs`）：24 个种子，MTU 256 下 25% 丢包、10% 重复、最多 400 毫秒乱序（开启与
  关闭 cookie），检查数据报不超过 MTU，每个密码套件配合 P-256、P-384、Ed25519 与 RSA 服务端证书以及三种
  客户端证书，每个 SRTP 配置；负面用例：错误指纹（双向）、自定义校验拒绝、重放/篡改/截断的记录、未认证的
  告警、损坏的 cookie、无状态 `HelloVerifier`（其他地址、过期、垃圾数据）、超时与退避时间表、
  close_notify、无共同套件、缺少客户端证书、API 误用。
- 互通（`tools/interop/dtls/run.sh`）：OpenSSL `s_server -dtls1_2` / `s_client -dtls1_2`（rust:1 镜像中的
  3.5 与主机上的 4.1）双向，覆盖每个套件、`-use_srtp` 配置、`-mtu 300`、双向认证，且
  `-keymatexport EXTRACTOR-dtls_srtp` 与我们的密钥一致；pion/dtls v3.1 双向，覆盖每个 SRTP 配置以及
  ECDSA、ChaCha20 与 RSA 套件，比较密钥材料；自研 WebRTC 协议栈的互通测试（pion、Chrome）也端到端地覆盖了它。
- DTLS 1.3 及新功能（`tests/dtls13.rs`）：MTU 256 下 32 个种子，25% 丢包、重复与乱序（部分开启 cookie、
  CID、票据），在丢包链路上双向 KeyUpdate；客户端 ACK 后丢失的一个数据报只重传一个分片；最后一轮与 ACK
  丢失；连接内与 `HelloVerifier` 的 HRR cookie；每个 DTLS 1.3 套件配四种密钥；版本协商（六种组合，开关
  cookie）；DTLS 1.3 与 DTLS 1.2 会话恢复（含丢包链路）；外部 PSK（错误密钥：binder 校验失败）；每个
  DTLS 1.2 PSK 套件；两个版本下长度不对称的 CID；重放与篡改的 DTLS 1.3 记录。密钥计划用 TLS 前缀对照
  RFC 8448 校验。
- DTLS 1.3 互通（`tools/interop/dtls/dtls13.sh`，由 `run.sh` 调用，在 `tools/interop/dtls/Dockerfile`
  的镜像中）：OpenSSL 4.1 `-dtls1_3` 双向（比较 SRTP 密钥、MTU 300 下的 RSA/ChaCha20、为组和为 cookie 的
  HRR、双向 KeyUpdate、会话恢复、两个版本的 PSK、与 `-dtls`、`-dtls1_2`、`-listen` 的版本协商），wolfSSL
  5.8.4（两个版本双向 CID、HRR、KeyUpdate、会话恢复）；pion/dtls 双向 CID 与 PSK 套件。
- Fuzz：`fuzz/` 中的目标 `dtls_record`（记录拆分、分片与消息解析、重新编码）与 `dtls_handshake`
  （任意数据报输入握手中及已连接的客户端和服务端状态机）；`fuzzing::tests` 在 stable 上回放它们的语料。
