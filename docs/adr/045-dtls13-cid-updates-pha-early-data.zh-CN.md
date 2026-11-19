# ADR-045：only-dtls 的 DTLS 1.3 连接 ID 更新、握手后客户端认证与早期数据

[English](045-dtls13-cid-updates-pha-early-data.md) | 简体中文

状态：已采纳（2026-11-19）

## 背景

ADR-021 为 only-dtls 带来了 DTLS 1.3（RFC 9147）、连接 ID（DTLS 1.2 用 RFC 9146，DTLS 1.3
放在统一头中）、PSK 与会话恢复，并列出未完成项：DTLS 1.3 0-RTT、NewConnectionId /
RequestConnectionId、握手后客户端认证、非 ECDHE 的证书密钥交换以及 CBC 套件。only-dtls 属于
内部层级（docs/api-stability.md）；工作区内唯一的使用者 only-webrtc 仍使用 DTLS 1.2
（ADR-021 §2），因此本 ADR 不改变 WebRTC 的行为。

## 决策

1. **握手后 flight 排队发送。** DTLS 1.3 状态机一次只发送一个 flight（RFC 9147 §7 的可靠性：
   ACK、部分重传）。此前 NewSessionTicket 与 KeyUpdate 各自用"等当前 flight 结束"的标志；现在
   它们与新消息共用一个握手后 flight 队列（最多 32 个），每个 flight 在开始发送时才构造，
   这样消息序号保持有序，并使用当时的密钥（握手后 Finished 依赖客户端应用流量密钥，而
   KeyUpdate 会改变它）。已排队或正在发送 KeyUpdate 时再请求 KeyUpdate 会合并。
2. **连接 ID 更新（RFC 9147 §9）**，仅 DTLS 1.3（RFC 9146 没有对应消息）：
   `Connection::new_connection_ids(count, immediate)` 发送 NewConnectionId，携带协商长度的
   新随机 CID（`cid_immediate` 或 `cid_spare`）；`request_connection_ids(n)` 发送
   RequestConnectionId（同时只能有一个未答复的请求）；`rotate_connection_id()` 把我们发送的
   CID 切换为对端给出的下一个备用 CID；`spare_connection_ids()` 返回备用 CID 数量。收到的
   RequestConnectionId 立即答复，最多补足到 8 个有效 CID（按 §9 可以少给或给空列表）；排队中
   未答复的请求超过 4 个则发送 `too_many_cids_requested`（新增
   `AlertDescription::TooManyCidsRequested`）。没有非空 CID 时两种消息都以
   `unexpected_message` 拒绝（§9）。DTLS 1.3 没有 RetireConnectionId，因此本端 CID 隐式退役：
   对端按发放顺序使用 CID（§9 的 "SHOULD"），一条在较新 CID 下通过认证的记录会让更早的 CID
   退役（跨越切换而乱序的数据报会被丢弃，与丢包相同）。`cid_immediate` 会清空我们持有的旧
   备用 CID（对端可能已让它们退役）。连接接受的 CID 集合由
   `Connection::local_connection_ids()` 给出，每次变化都产生 `Event::LocalConnectionIds(set)`，
   按 `connection_id(datagram, len)` 路由的监听方可据此维护精确的映射。所有本端 CID 保持配置的
   长度，这是路由所需。
3. **握手后客户端认证（RFC 8446 §4.6.2）**，DTLS 1.3：
   `Config::with_post_handshake_auth(true)` 让客户端发送 `post_handshake_auth`，并以
   Certificate、CertificateVerify 与 Finished 答复 CertificateRequest，覆盖的转录为握手转录加
   该请求（没有身份、或没有适合所请求签名方案的密钥时，以空 Certificate 拒绝）。服务端调用
   `Connection::request_client_certificate()`（同时只有一个请求，16 字节随机上下文），Finished
   校验通过后得到 `Event::ClientCertificate(chain)`；证书链经过 `PeerVerifier`（拒绝即致命错误，
   `bad_certificate`），并更新 `HandshakeInfo::peer_certificates` / `peer_fingerprint`。答复本身
   确认了请求 flight，两者也都会被 ACK（RFC 9147 §7）。
4. **早期数据（0-RTT）**，基于会话恢复票据，用 `Config::with_early_data(max)` 显式开启
   （默认 0）：
   - 服务端：NewSessionTicket 携带 `early_data`（max_early_data_size，保存在加密的票据状态中，
     格式 2；格式 1 的旧票据仍可打开，只是没有早期数据）。仅在以下条件下接受早期数据：第一个
     PSK 身份、票据允许早期数据、使用票据的密码套件（客户端提供早期数据时服务端优先选择该
     套件）、没有 HelloRetryRequest、票据年龄新鲜（客户端与服务端计算的年龄相差不超过 10 秒，
     另加 1 秒以容纳票据按整秒记录的签发时间），并且该 ClientHello 是第一次使用：binder 记录在
     `AntiReplayStore` 中，保留三个窗口（RFC 8446 §8.2 "ClientHello recording"，与 ADR-013 中
     only-tls 的存储设计相同，单独实现是因为 only-dtls 不得依赖 only-tls；默认每个配置一个
     100,000 条的 `MemoryAntiReplay`，`Config::with_anti_replay` 可共享存储；存储出错则拒绝早期
     数据）。接受的记录（epoch 1，`client_early_traffic_secret`）在 `Event::Connected` 之前以
     `Event::EarlyData` 交付，超过 max_early_data_size 即 `unexpected_message`，连接建立时丢弃
     epoch 1；被拒绝的早期数据直接跳过、不缓存。`HandshakeInfo::early_data` 告诉双方是否被接受。
   - Cookie：`with_hello_verify(true)`（默认）时，每个不带 cookie 的 ClientHello 都会收到
     HelloRetryRequest，而它会拒绝早期数据。早期数据被接受的 ClientHello 跳过这一往返：其
     binder 证明客户端持有我们的票据，防重放记录只放行该 ClientHello 一次，且简化的服务端
     flight（不含证书）比 ClientHello 还小，无法放大流量。这项检查只针对提供早期数据的
     ClientHello 在 HelloRetryRequest 之前进行；此时 binder 错误会退回到 HelloRetryRequest
     （致命错误随第二个 ClientHello 出现，与以前一致）。位于连接之前的 `HelloVerifier::check`
     看不到票据，仍总是要求 cookie：经它处理的客户端的早期数据永远不会被接受。
   - 客户端：`with_early_data` 非零时，若会话允许（`Session::max_early_data`），
     `Connection::client_resume` 会提供早期数据；`Connection::send_early_data` 可在收到服务端
     Finished 之前发送记录（DTLS 1.3 没有 EndOfEarlyData，RFC 9147 §5.6）。遇到
     HelloRetryRequest 或服务端未回应 `early_data` 时即结束（此后返回 `Error::NotAvailable`）；
     如有需要，应用以 1-RTT 数据重发。
   - 外部 PSK 不支持早期数据（没有预先配置的参数）。
5. **错误**：当连接没有协商所需能力或状态不允许时（DTLS 1.2、没有 CID、没有
   `post_handshake_auth`、已有未完成的请求、早期数据未提供或被拒绝），新操作返回新增的
   `Error::NotAvailable(reason)`；`Error::NotConnected` / `Error::Closed` 同以前。
6. **有意不做**：非 ECDHE 的证书密钥交换（静态 RSA、DHE）与 CBC 套件。RFC 8996 / RFC 9325
   反对前者缺少前向保密，以及后者先 MAC 后加密的记录保护（Lucky13 类填充预言）；RFC 8827 /
   RFC 9325 要求 WebRTC 使用 ECDHE 与 AEAD，并只推荐 AEAD 套件；我们互通的所有实现（OpenSSL、
   wolfSSL、pion、浏览器）都协商 ECDHE AEAD 套件。加入它们只会增加攻击面，而没有需要它们的
   对端。

新增公开 API（only-dtls）：`AntiReplayStore`、`MemoryAntiReplay`；
`Config::{with_early_data, with_anti_replay, with_post_handshake_auth}`；
`Connection::{new_connection_ids, request_connection_ids, rotate_connection_id,
spare_connection_ids, local_connection_ids, peer_connection_id, request_client_certificate,
send_early_data}`；`Session::max_early_data`；`Event::{EarlyData, ClientCertificate,
LocalConnectionIds}`；`HandshakeInfo::early_data`；`Error::NotAvailable`；
`AlertDescription::TooManyCidsRequested`。全部为新增（`Event`、`Error`、`AlertDescription`
与 `HandshakeInfo` 都是 non-exhaustive）。

## 影响

- 互通（`tools/interop/dtls/dtls13.sh`；`tools/interop/dtls/Dockerfile` 构建的镜像现在以
  `--enable-earlydata --enable-postauth` 编译 wolfSSL）：wolfSSL 5.8.4 客户端 `-r -0` 的早期
  数据被我们的服务端接受（cookie 开与关）；我们客户端的早期数据被 wolfSSL 服务端
  （`-r -0 -J n`）接受并读出，在其默认的 HelloRetryRequest cookie 下被拒绝，连接仍然恢复；
  握手后认证双向互通（wolfSSL 服务端 `-Q` 验证我们的 Certificate、CertificateVerify 与
  Finished；wolfSSL 客户端 `-Q` 以其证书答复我们的请求）。OpenSSL 4.1 与 wolfSSL 5.8 都未实现
  NewConnectionId / RequestConnectionId：它们在我们自己的两端之间测试，内存中经有损链路，
  互通脚本中经 UDP。DTLS 1.2 互通（OpenSSL 3.x、pion）不变。GnuTLS 没有 RFC 9146 CID，无法用于
  测试 DTLS 1.2 CID；这仍由 pion 与 wolfSSL 覆盖。
- 基准（gpu51，同一次运行，基线 ec0d9616 对比本变更，三轮交替）：DTLS 1.2 记录 64 B
  1.00-1.03 / 1 KiB 0.99-1.01（AES-128-GCM 与 ChaCha20 相近），DTLS 1.3 记录 0.98-1.02，完整
  握手 1.00（DTLS 1.2 与 1.3），DTLS 1.3 会话恢复 1.00-1.01（`dtls-bench`、新增的
  `dtls-hs-bench`）：无退化；新路径在不使用时没有开销。
- Fuzz：新目标 `dtls_post_handshake`（任意握手后消息按已解密的方式交给已连接的两端处理，同时
  运行真实的 CID、KeyUpdate 与认证 flight；随后把任意早期数据与数据报送给接受 0-RTT 的服务端）；
  `dtls_record` 解析并重新编码新消息；`dtls_handshake` 的配置提供握手后认证与早期数据，并调用
  新 API。
- 早期数据按设计可被重放（RFC 8446 §8）：应用只能在其中发送幂等请求，`Event::EarlyData` 与
  `Config::with_early_data` 的文档写明了这一点。
