# ADR-062：only-tls 的异步防重放存储、票据密钥轮换、status_request_v2 与 BoGo

[English](062-tls-async-anti-replay-ticket-rotation-bogo.md) | 简体中文

状态：已采纳（2026-11-20）

## 背景

开发计划里 TLS 还剩下的几项：

1. **OCSP 响应验证**（RFC 6960），包括服务端装订的响应和 TLS 1.3 客户端自己带的响应。ADR-038（`only-x509`
   中的验证，服务端装订响应用 `RevocationPolicy`）与 ADR-049（`client_ocsp_policy`）已经完成；计划中较早的
   几行仍写着“未完成”。
2. **`status_request_v2`**（RFC 6961，TLS 1.2 的 `ocsp_multi`）：ADR-049 没有做。
3. **异步的 `AntiReplayStore`。** ADR-013 的共享 0-RTT 防重放存储是同步的：I/O 线程要等待到 Redis 之类存储的
   往返。规则 1 要求 I/O 线程绝不阻塞。
4. **多把有效密钥并存的票据密钥轮换。** `session_ticket_key` 只接受一把密钥；轮换就要新建配置，所有持有票据的
   客户端都要做一次完整握手。
5. **BoGo 测试运行器**（BoringSSL 的 `ssl/test/runner`），第 D 波之前由 rustls 为 only-quic 提供。

## 决定

### OCSP（第 1 项）

没有新内容：`OcspResponse::verify`（签发者或带 id-kp-OCSPSigning 的委托响应者签名、CertID 匹配、带时钟偏差的
thisUpdate / nextUpdate、nonce）在 `ClientConfigBuilder::ocsp_policy` 下用于服务端装订的响应，在
`ServerConfigBuilder::client_ocsp_policy` 下用于 TLS 1.3 客户端的响应，软失败 / 硬失败与 CRL 检查一致
（ADR-038、ADR-049）；模糊测试目标 `x509_ocsp` 解析响应。本次更正计划中的描述。

### status_request_v2（第 2 项）

有意不实现。RFC 6961 只用于 TLS 1.2，只是额外装订中间证书的响应；TLS 1.3 在 `status_request` 中为每张证书
带一个响应（RFC 8446 第 4.4.2.1 节）；OpenSSL、Go、rustls 和 BoringSSL 都从未实现它（主流实现中只有 Java 的
JSSE 实现过），CA/浏览器论坛也已让公共 CA 的 OCSP 变为可选。客户端从不发送它；服务端收到时与其他未知扩展
一样忽略（ServerHello 中没有 `status_request_v2`，也不为它发送 CertificateStatus）。有测试覆盖这两点。

### 异步防重放存储（第 3 项）

1. **新增一个 trait**，而不是修改原有的那个（原 trait 保持不变，只有新增）：

   ```rust
   pub trait AsyncAntiReplayStore: Send + Sync {
       fn check_and_insert(&self, binder: &[u8], ttl: Duration, done: ReplayCheck);
   }
   impl ReplayCheck { pub fn complete(self, result: io::Result<bool>); }
   ```

   该调用不得阻塞：发出请求后立即返回；客户端库的回调或读线程在任意线程上调用 `complete`。允许在调用内直接
   应答（命中本地缓存），此时不挂起任何东西。应答的含义与 ADR-013 相同：`Ok(true)` 接受早期数据，`Ok(false)`
   或 `Err` 拒绝（失败即关闭）。未应答就被丢弃的 `ReplayCheck` 同样拒绝。
2. **挂起握手而不是线程。** 服务端先完成其他所有检查（binder 校验、票据解开、新鲜度），再调用存储。如果应答
   还没到，它保存 ClientHello、选中的 PSK 及其会话，什么也不发送就返回，所改动的状态在第二遍处理时都会重新
   设置（SNI、证书、ALPN）。应答到达后，同一个 ClientHello 从头再处理一遍，同时给出 PSK 与应答，因此不会重复
   查找任何东西（会话缓存中的 TLS 1.3 票据只交出一次），也不需要回滚任何握手状态。其间到达的字节（早期数据
   记录，其密钥尚未决定）留在接收缓冲区中，上限为 64 KiB 与 `max_early_data` 中较大者的两倍再加 128 KiB；
   超出则以 `unexpected_message` 断开连接。
3. **唤醒连接。** sans-io 内核接受一个唤醒器。TCP 上它来自 only-core 新增的钩子：`Transport::set_waker(TransportWaker)`
   （默认忽略），由引擎在安装传输层时调用一次；`TransportWaker::wake()`（任意线程，只持有弱引用）向连接的
   I/O 线程投递一个任务，该线程以空输入轮询传输层，并像处理从套接字读到的字节一样交出解码结果和产生的输出。
   QUIC 上，`only_quic` 给握手一个唤醒器，从应答所在线程驱动连接（连接本来就可以在任意线程上使用），连接在
   `poll_transmit` 中继续握手，然后处理等待密钥期间暂存的 0-RTT 包。阻塞式测试流直接等待应答。
4. **超时。** `ServerConfigBuilder::anti_replay_timeout`（默认 1 秒，至少 1 ms）：超时未应答的检查拒绝早期
   数据，握手以 1-RTT 恢复继续。截止时间由一个进程级线程（`only-tls-replay-timer`，在第一个未能在调用内应答
   的检查时启动）以弱引用保存；迟到的应答被忽略。握手超时仍然限制整个握手。
5. **默认路径不变。** `MemoryAntiReplay` 与 `anti_replay_store` 仍在调用内应答；挂起机制让每条握手消息和每个
   握手阶段的记录多一次 `Option` 判断，QUIC 每次 `poll_transmit` 多一次（A/B 见下文）。

使用 Redis 时，`check_and_insert` 用非阻塞客户端发出 `SET only:0rtt:<hex binder> 1 NX PX <ttl ms>`，并根据
回复完成检查（`OK` → `Ok(true)`，nil → `Ok(false)`，错误 → `Err`）。书中 TLS 一章有示意代码。

### 票据密钥轮换（第 4 项）

1. **`TicketKeys`**：共享句柄（克隆共享同一组密钥），交给 `ServerConfigBuilder::session_ticket_keys`：第一把
   密钥封装新票据，此前最多 `MAX_TICKET_KEYS - 1` = 3 把密钥仍能解开它们封装的票据。票据开头带 16 字节的
   密钥名，解开时按名字找密钥。
2. **三种轮换方式**：
   - `TicketKeys::new(key)`，然后由应用决定何时 `rotate(key)` / `set(seal, open_only)`（密钥来自密钥存储，
     推送到每台服务器：共享票据的服务器在轮换过程中继续共享，与 `session_ticket_key` 一样）；
   - `TicketKeys::derived(secret, period)`：周期 `n = unix_time / period` 的密钥为
     HKDF-SHA256(secret, "epoch" ‖ n)；它负责封装，`n - 1` 与 `n + 1` 的密钥也能解开（上一周期的票据，以及
     时钟快了不到一个周期的服务器）。共享票据的服务器同步轮换，除了密钥和各自的时钟外无需任何协调；
   - `TicketKeys::random(period)`：每个周期一把随机密钥，上一把在下一个周期内仍能解开；仅限本进程。
3. **不用线程。** 周期变化后，第一次封装或解开票据的握手把定时密钥推进到当前周期（读锁下一次比较；只在变化时
   取写锁）。默认的票据器（配置生命期内一把密钥）与 `session_ticket_key` 完全不经过锁。
4. **有效期。** 使用定时密钥时，票据声明的有效期不超过一个周期（`min(6 小时, period)`），即保证能解开的时间；
   TLS 1.2 票据与缓存的会话使用相同的有效期。
5. **未做：** TLS 1.2 恢复时续发票据（RFC 5077 第 3.3 节）。TLS 1.2 客户端用旧密钥封装的票据恢复时会一直使用
   该票据，直到那把密钥移出密钥组，然后做一次完整握手；TLS 1.3 客户端在每次握手后都会收到新票据。

### BoGo（第 5 项）

shim `crates/only-tls/examples/bogo-shim.rs` 像 BoringSSL 的 `bssl_shim` 驱动 BoringSSL 那样驱动 only-tls
（经阻塞式测试流）：连接运行器、写入 shim id、以客户端或服务端握手、用 `-expect-*` 参数核对协商结果并回显测试
消息；参数可带 `-on-initial-` / `-on-resume-` / `-on-retry-` 前缀，客户端在 `-resume-count` 个连接之间保留会话
缓存。不认识的参数，或要求 only-tls 不支持、无法报告的内容（对端的签名算法、密钥材料导出、验证回调）时以
89 退出，运行器把该测试记为未实现。`tools/interop/tls/bogo.sh` 构建 shim，按固定的 BoringSSL 提交
（`ddd73296`，2026-11-19；Go 1.27）获取运行器，以 `-allow-unimplemented -loose-errors`（shim 报告的是 only-tls
自己的错误信息，而不是 BoringSSL 的错误码）和 `tools/interop/tls/bogo_config.json` 运行；该文件的
`DisabledTests` 逐条写明原因，列出 only-tls 未实现的领域（DTLS 与 QUIC，BoGo 经其他 shim 测试它们；TLS 1.0/1.1、
CBC、RSA 密钥交换、PSK 套件、重协商、ECH、委托凭据、Channel ID、ALPS、后量子群组及其他 BoringSSL 独有功能），
以及每个仍预期失败的测试：告警与 BoringSSL 不同（14 个）、RFC 允许而 BoringSSL 做法不同的行为（约 40 个：
HelloRetryRequest 之后兼容 CCS 的位置、被拒的早期数据自动重发、不恢复没有 EMS 的 TLS 1.2 会话等），以及发现
但尚未修复的 only-tls 缺陷。

x86 主机上的结果：8,110 个测试中 **882 个通过、0 个失败**，1,122 个未实现，6,106 个被禁用（其中约 2,700 个是
DTLS 与 QUIC）。这次运行发现了 11 个协议缺陷，均在本次修复（另有一处跳过早期数据的上限比 RFC 宽松，列为差异）：
不支持 TLS 1.3 的服务端拒绝 TLS_FALLBACK_SCSV（RFC 7507 第 3 节）；带 supported_groups 而没有 key_share 的
ClientHello 得到 HelloRetryRequest 而不是 `missing_extension`（RFC 8446 第 9.2 节）；TLS 1.2 服务端不确认
server_name，TLS 1.2 客户端接受非空的确认（RFC 6066 第 3 节）；未请求的 TLS 1.3 server_name 确认以
`illegal_parameter` 而非 `unsupported_extension` 回应；接受超过 2^14 + 1 字节的 TLS 1.3 带填充明文（RFC 8446
第 5.4 节）；对端叶证书的 keyUsage 不含 digitalSignature 时仍被接受用于签名（RFC 8446 第 4.4.2.2 节、RFC 5246
第 7.4.2 节），现在无论是否验证证书都以 `bad_certificate` 拒绝；接受未请求的 CertificateEntry 扩展（除已请求
的 status_request 外均为 `unsupported_extension`，RFC 8446 第 4.4.2 节）；只提供 TLS 1.2 的 ClientHello 因其
格式错误的 TLS 1.3 pre_shared_key 被拒（解析错误现在只在协商 TLS 1.3 时报出）；向不支持 psk_dhe_ke 的客户端
发送票据（RFC 8446 第 4.2.9 节）；对多个 update_requested 的 KeyUpdate 逐一回应（现在在我方下一次发送应用数据
之前只回应一次，RFC 8446 第 4.6.3 节，与 BoringSSL 相同）。修复之后，
`tools/interop/tls/run.sh` 在 x86 主机上 175 个用例全部通过（OpenSSL 3.0.13、Go、curl）。

## 影响

- 公开 API（均为新增）：only-core 的 `Transport::set_waker`（带默认实现的方法）、`TransportWaker`；only-tls 的
  `AsyncAntiReplayStore`、`ReplayCheck`、`ServerConfigBuilder::async_anti_replay_store`、
  `ServerConfigBuilder::anti_replay_timeout`、`TicketKeys`、`MAX_TICKET_KEYS`、
  `ServerConfigBuilder::session_ticket_keys`。隐藏项（不在承诺范围内）：`QuicTls::set_waker`、
  `QuicTls::suspended`、`QuicTls::resume`、`Connection::suspended`、`Connection::wait_resumable`。
- 挂起的握手在应答或超时之前持有它的 ClientHello 和其后到达的数据（有上限）；永不应答的存储让每次 0-RTT
  握手多花一个超时时间，而不会断开连接。
- 防重放的强度仍取决于存储的原子性（ADR-013）。
- 比以前更严格（BoGo 修复）：叶证书的 keyUsage 不含 digitalSignature，或发送未请求的 CertificateEntry 扩展的
  对端，现在握手失败，在不验证证书的模式下也是如此；这样的对端违反 RFC，其他实现同样会拒绝。
- `TicketKeys::derived` 让共享密钥成为长期密钥：持有它就能解开所有周期的所有票据。轮换它意味着换新密钥（持有
  票据的客户端各做一次完整握手）。
- 默认路径上实测的代价：见下面的 A/B。

## 代价

安静主机上的同次 A/B（docs/BENCHMARKS.zh-CN.md），默认配置：TLS 完整握手 X25519 0.99 倍、secp256r1 0.99 倍、
RSA-2048 1.00 倍（同次运行中 rustls 一列的变化幅度相同）；QUIC 完整握手 1.00 倍（七轮），恢复会话拨号到应答
0.99 倍（0-RTT）与 1.00 倍（1-RTT）。
