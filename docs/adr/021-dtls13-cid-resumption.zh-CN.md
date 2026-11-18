# ADR-021：only-dtls 的 DTLS 1.3、连接 ID、PSK 与会话恢复

[English](021-dtls13-cid-resumption.md) | 简体中文

状态：已采纳（2026-11-18）

## 背景

only-dtls（wave C）只实现了 DTLS 1.2：带证书的完整 ECDHE 握手，没有连接 ID、会话恢复和预共享密钥。
DEV-PLAN wave D 列为未完成的有：DTLS 1.3（RFC 9147）及其 ACK、连接 ID（DTLS 1.2 的 RFC 9146 与
DTLS 1.3 的 CID）、会话恢复（DTLS 1.2 会话 ID 与票据、DTLS 1.3 PSK 票据）以及 PSK。only-dtls 属于
Internal 层（docs/api-stability.md），API 可经 ADR 变更；工作区内唯一的使用者是 only-webrtc。

## 决定

1. **一个 `Connection` 背后两台状态机。** DTLS 1.2 状态机保持不变（内部 `Conn12`）；DTLS 1.3 是第二台
   sans-io 状态机（`Conn13`）。`Config::with_versions` 含 DTLS 1.3 时连接以 DTLS 1.3 起步：同时启用 1.2
   时客户端的 ClientHello 还带上 DTLS 1.2 服务端所需的一切（1.2 套件、扩展主密钥、`ec_point_formats`、
   重协商 SCSV）；服务端对提供 1.3 的 ClientHello 以 1.3 应答。对端只会 DTLS 1.2 时（客户端收到 DTLS 1.2
   ServerHello 或 HelloVerifyRequest，服务端收到不含 1.3 `supported_versions` 的 ClientHello），连接把
   状态（已发的 ClientHello、已重组的分片、序号、定时器）交给 DTLS 1.2 状态机，由它重新处理同一个数据报。
   这类服务端设置、这类客户端检查 RFC 8446 §4.1.3 的降级标记。
2. **默认仍是 DTLS 1.2，WebRTC 也是。** `Config::new` 与 `Config::webrtc` 只启用 DTLS 1.2。pion/dtls
   （v3）不支持 DTLS 1.3，WebRTC 栈目前协商 DTLS 1.2；向它们提供 1.3 只会让 ClientHello 变大（密钥共享）
   而无收益。需要时用 `with_versions(vec![Version::Dtls13, Version::Dtls12])` 开启。
3. **DTLS 1.3 密钥计划由 only-dtls 自己实现**，基于 only-crypto 的 HKDF，不复用 only-tls：only-tls 依赖
   only-core / only-log / only-deflate（引擎），sans-io 的 WebRTC 栈不能引入它们，而且其标签前缀是
   `"tls13 "`，DTLS 1.3 用 `"dtls13"`。结构与 only-tls 相同，并用 TLS 前缀对照 RFC 8448 校验；DTLS 1.3
   没有公开的握手轨迹向量，DTLS 标签由互通测试验证。
4. **DTLS 1.3 记录层与可靠性。** epoch 0 用 DTLSPlaintext，此后用统一头：16 位序号、显式长度、协商后的
   CID、记录号加密（AES-ECB / ChaCha20 掩码）；epoch 2 为握手，3 及以上为应用数据（每次 KeyUpdate 加一），
   各有重放窗口。发出的每条握手记录都记下它携带的分片；ACK 标记分片，重传只发未被确认的部分。接收方在
   对端重发一轮或收到对端最后一轮时立即 ACK，发现空洞时在下一个定时点 ACK（合并同时到达的数据报），一轮
   久未收齐时在 RTO 的四分之一后 ACK。上限：最多领先 16 条消息，每条消息 64 KiB，cookie 前 ClientHello
   8 KiB（同 DTLS 1.2），缓存 32 条早到记录，每个 ACK 32 个记录号，每轮记住 256 条记录，握手后的一轮重传
   8 次后放弃。
5. **HelloRetryRequest cookie 无状态。** cookie 携带所选套件、HRR 要求的组以及 ClientHello1 的哈希，
   用 `HelloVerifier` 的密钥做 MAC，服务端据 ClientHello2 重建 transcript。`HelloVerifier::check` 对
   提供 DTLS 1.3 的 ClientHello 回以这样的 HelloRetryRequest（`HelloCheck::Respond`），并接受第二个
   ClientHello；关闭 cookie 创建的连接信任监听方已检查过的 cookie。HRR 沿用 ClientHello1 的记录号；
   ServerHello 从 ClientHello2 的记录号继续（否则 OpenSSL 4.1 客户端的最后一轮永远结束不了）。
6. **连接 ID**：`Config::with_connection_id(Some(len))` 让每个连接请对端使用 `len` 字节的随机 CID
   （0：对端要求时发送 CID，自己不需要）。DTLS 1.2 用 RFC 9146 的 `tls12_cid` 记录与 RFC 9146 附加数据；
   DTLS 1.3 在 ClientHello / ServerHello 中协商 CID（与 wolfSSL 一致）并放进统一头。
   `Connection::local_connection_id` 和自由函数 `connection_id(datagram, len)` 让监听方按 CID 分发数据报。
   未做：NewConnectionId / RequestConnectionId。
7. **客户端的会话恢复是 sans-io 的**：客户端收到 `Event::NewSession(Box<Session>)`（DTLS 1.2 连接时的会话 ID
   或票据、每个 DTLS 1.3 NewSessionTicket），用 `Connection::client_resume(config, now, &session)` 恢复。
   `Config::with_session_resumption(true)` 两端都开启：服务端向请求的客户端签发 RFC 5077 票据（否则用
   上限 1024 的会话 ID 缓存），并发一个 DTLS 1.3 NewSessionTicket，用 `TicketKey` 以 AES-256-GCM 封装
   （每个配置随机生成，或用 `with_ticket_key` 共享）。票据带上对端证书链，恢复时由校验器重新检查，指纹
   绑定对恢复的会话同样有效。默认有效期 2 小时（`with_ticket_lifetime`，最长 7 天），以 Unix 秒计，
   重启后仍有效。DTLS 1.3 恢复只用 `psk_dhe_ke`（始终前向安全）；未实现 0-RTT。
8. **外部 PSK**：`Config::with_psks(Vec<Psk>)`。客户端提供第一个；服务端接受列出的任一身份，只做 PSK 时
   无需证书。DTLS 1.2 增加 AEAD 的 PSK 与 ECDHE-PSK 套件（`CipherSuite::PSK`，仅在配置了 PSK 时提供）；
   DTLS 1.3 以 SHA-256 在 `psk_dhe_ke` 中使用外部 PSK。

新增公共 API（only-dtls）：`Version`、`Psk`、`Session`、`TicketKey`、`connection_id`；
`Config::{with_versions, with_psks, with_session_resumption, with_ticket_key, with_ticket_lifetime,
with_connection_id}`；`Connection::{client_resume, version, local_connection_id, update_keys}`；
`Event::NewSession`；`HandshakeInfo::{version, resumed, psk_identity, local_connection_id,
peer_connection_id}`；`CipherSuite::{PSK, TLS13, is_tls13, is_psk}` 及九个套件变体；
`AlertDescription::{MissingExtension, UnknownPskIdentity}`。`Config::new` 的默认套件列表前面加上了
DTLS 1.3 与 PSK 套件（按版本和是否有 PSK 过滤，只用 DTLS 1.2 时行为不变）。DTLS 1.3 连接在握手后
`Connection::poll_timeout` 也可能返回时间（最后一轮待 ACK、NewSessionTicket、KeyUpdate）。

## 影响

- 互通（`tools/interop/dtls/run.sh`）：OpenSSL 4.1（在 `tools/interop/dtls/Dockerfile` 中构建；Debian 的
  OpenSSL 3.5 没有 DTLS 1.3）和 wolfSSL 5.8.4 覆盖 DTLS 1.3 双向、版本协商与降级、HRR（cookie 与组）、
  小 MTU、KeyUpdate、会话恢复、PSK、CID（wolfSSL，两个版本）；pion/dtls v3 覆盖 DTLS 1.2 CID 与 PSK 套件双向。
- 不使用新选项的配置，DTLS 1.2 路径不变；WebRTC 的握手逐字节相同。记录层在 gpu51 上与 ab65d376 同轮 A/B
  （`dtls-bench`，三轮交替，分支/基线）：64 字节记录 0.97-1.00（AES-128-GCM）与 0.99-1.01（ChaCha20），1 KiB
  记录 1.00-1.01 与 1.01-1.02；前提是 `Event::NewSession` 中的会话装箱、接收路径不再每条记录分配内存。
- 未做：0-RTT、NewConnectionId / RequestConnectionId、握手后客户端认证、WebRTC 默认使用 DTLS 1.3。
