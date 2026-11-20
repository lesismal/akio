# ADR-054：DTLS 上的 TURN、IPv6 上的 mDNS 与 SDES-SRTP

[English](054-turn-dtls-mdns-ipv6-sdes.md) | 简体中文

状态：已采纳（2026-11-20）

## 背景

`crates/only-webrtc/README.md` 列出的三个缺口在非浏览器部署中反复出现：

- **DTLS 上的 TURN**（RFC 7350，`turns:host?transport=udp`）。`only-turn` 提供 UDP、TCP 与 TLS 上的
  TURN，`Endpoint::gather_relay_via` 也只能经这三种方式分配。只放行 UDP 出站又要求控制通道加密的
  网络，以及公开了 DTLS 监听的 coturn 部署，都用不上。
- **IPv6 组播上的 mDNS。** `Endpoint::resolve_mdns` 与 `conceal_host_candidates`（ADR-044）只用一个
  `224.0.0.251:5353` 上的 IPv4 套接字。名字可以解析出 IPv6 地址，但只能经由 IPv4 应答器；纯 IPv6
  链路、只在 `ff02::fb` 上应答的浏览器都够不着，链路本地 IPv6 候选也没有出站接口。
- **SDES-SRTP**（RFC 4568 `a=crypto`）。SIP 网关（Asterisk、FreeSWITCH 及其后的 PBX）用 SDP 中的
  安全描述而不是 DTLS-SRTP 给 SRTP 提供密钥。`only-srtp` 已实现它们用到的全部套件（ADR-040），
  `Profile::sdes_name` / `from_sdes_name` 也已存在，只是没有协商。

约束：`only-srtp`、`only-rtp` 与 `only-ice` 正由其他会话修改，这里不动；浏览器看到的内容必须与今天
完全一样；`only-turn` 与 `only-webrtc`（公开层）的公开 API 不得暴露内部层类型（`only-dtls`、
`only-srtp`）。

## 决定

### 1. DTLS 上的 TURN

**服务端。** `TurnServer::dtls(&tls::ServerConfig) -> io::Result<TurnDtls>` 是客户端说 DTLS 的 UDP
监听器的 acceptor。它接受与 `turns:` TCP 监听器相同的 `tls::ServerConfig`（默认证书链与私钥；仅当
配置要求时才要客户端证书），一张证书两处共用。每个客户端五元组：

- ClientHello 由每个 acceptor 一个的 `only_dtls::HelloVerifier` 无状态应答（DTLS 1.2 用
  HelloVerifyRequest，1.3 用 HelloRetryRequest cookie）；只有带有效 cookie 的 ClientHello 才创建
  DTLS `Connection::server`（关闭 cookie）。提供 DTLS 1.3，可回退到 1.2（TLS 配置只用 TLS 1.3 时
  只用 1.3）。
- 每条应用数据记录是一条 STUN 或 ChannelData 消息，保持 UDP 语义：不分帧，不填充（RFC 7350 第 4
  节）。响应与中继数据在分片锁下加密（锁顺序为分片 → 会话，与其他 `TurnEnv` 调用一致）。
- **分配的生命期等同于其 DTLS 关联**：close_notify、致命告警、监听器的 `udp_idle_timeout`，或同一
  五元组上的新握手（已建立的关联上收到随机数不同且 cookie 有效的 ClientHello：客户端重启了）都会
  释放它。否则丢了关联的客户端在旧分配过期前会一直被 437 Allocation Mismatch 拒绝。
- 重传与握手定时器跑在服务端已有的清扫线程上（每 500 ms；DTLS 从 1 s 起）。
- DTLS 客户端占分片表的三分之一（UDP、流、DTLS），同一地址在两种传输上是两个客户端，与 UDP 和
  TCP 之前的做法一致。`TurnServer::dtls_relay_of` 报告 DTLS 客户端的中继地址。

**客户端。** `RelayServer::dtls(addr, server_name, tls::ClientConfig, user, pass)`，以及
`turns:host[:port]?transport=udp` URL（默认端口 5349；与 TLS 一样由 `tls_config` 补全）。分配跑在
**endpoint 自己的 UDP 套接字**上的 `only_dtls::Connection::client` 里，与普通 UDP 分配一样：来自
服务器地址的数据报在对端路由之前从套接字取出、解密，交给 sans-io TURN 客户端；握手完成前它的消息
排队等待（有上限，已排队事务的重传不重复排队）。DTLS 定时器并入中继在共享 WebRTC 定时器线程上的
定时器。服务器证书用 `only_x509::Verifier` 按 TLS 客户端配置的根证书对 `server_name` 校验（有客户端
证书就发送；`insecure_skip_verify` 不校验）。握手失败时 `gather_relay_via` 立即失败；之后丢失的
关联会丢失分配，并以新的握手重新分配（ADR-032 的退避）。候选是 UDP 中继候选（与普通 UDP 分配
相同），服务器给出的映射地址成为服务器反射候选。每个服务器地址只有一个数据报中继（UDP 或 DTLS）：
两者会读到同样的数据报。

`tls::ServerConfig` / `tls::ClientConfig` 的内容通过它们已有的隐藏 `__parts()`（QUIC 的桥接）读取，
因此内部层类型不会进入公开 API。

### 2. IPv6 上的 mDNS

- `resolve_mdns` 在 IPv4 套接字之外再绑定一个套接字：`[::]:5353`，加入 `ff02::fb`（5353 绑定不了
  时同样回退到临时端口加 QU 查询；没有 IPv6 的主机只跑 IPv4，行为不变）。双栈套接字丢弃
  IPv4 映射的源地址（它们归 IPv4 套接字）。
- **按接口加入。** `ff02::fb` 是链路范围的：套接字只在加入过它的链路上收得到，macOS 不指定接口时
  拒绝发往它（"no route to host"）。接口取有 IPv6 链路本地地址的那些：Linux 上读
  `/proc/net/if_inet6`，其他系统对前 64 个索引向内核询问到 `ff02::fb%<i>` 的路由（UDP connect，
  不发送任何东西）。引擎服务的套接字通过新增的 `only` API
  `Engine::bind_udp_multicast_on(group, interfaces, acceptor)` 在每个接口上加入该组
  （`bind_udp_multicast` 现以空接口列表调用它）；`UdpBinding` 不暴露其套接字，所以在 only-webrtc
  内无法做到。
- **作用域 ID。** 查询发往每个已加入接口上的 `ff02::fb`（以及 endpoint 自身链路本地主机候选的
  作用域 ID）；应答发回查询所来接口上的组（或在查询方要求时单播给它）。SDP 不携带作用域 ID，所以
  endpoint 的 hub 记住远端链路本地地址的接口：从它们发来的数据报（地址交给 ICE 前先去掉作用域 ID）
  以及解析出它们的 mDNS 应答（应答到达的接口）学得，发送时再加回去；什么都没学到时，若 endpoint
  自己的套接字绑在链路本地地址上，就用它的作用域（同一链路）。全局 IPv6 与 IPv4 地址不走这条路径。
- AAAA 记录此前已能解析和应答（ADR-044）；IPv6 主机候选与 IPv4 的一样隐藏。两种地址族的应答都可以
  携带 A 与 AAAA 记录。

### 3. SDES-SRTP

`RtcConfig::enable_sdes_srtp(true)`，**默认关闭**：

- 开启后发出的 **offer**（会话的第一个 offer 决定）是 SDES offer：媒体段为 `RTP/SAVPF`，没有
  `a=fingerprint` / `a=setup`，每个套件一行 `a=crypto`，由强到弱（AEAD_AES_256_GCM、
  AEAD_AES_128_GCM、AES_256_CM_HMAC_SHA1_80、AES_CM_128_HMAC_SHA1_80、AES_CM_128_HMAC_SHA1_32），
  各带独立的随机密钥，BUNDLE 中每段相同。重新 offer 保持密钥不变。
- 第一个在用的段是带 `a=crypto` 行的 `RTP/SAVP` 或 `RTP/SAVPF` 时，**远端 offer** 即为 SDES。开启
  SDES 时以本方能用的第一行应答，并为该套件生成本方的新密钥（标签和套件不变的重新 offer 中保留），
  协议沿用 offer 的。带 MKI、多个密钥、会话参数（`KDR=`、`UNENCRYPTED_SRTP` 等）、未知套件或密钥
  长度不对的行都不采用（RFC 4568 §6.1）；接受 lifetime 但不强制。SDES 关闭时，这样的 offer 以明确
  的错误拒绝。
- **密钥。** 各方用自己的密钥加密、用对方的密钥解密：offer/answer 完成时由 SDP 创建两个 `only-srtp`
  上下文，重新协商时只替换密钥变了的那个（翻转计数器与重放窗口保留）。ICE 有了候选对即算连通；
  不跑 DTLS 握手。
- **BUNDLE**：每个方向一个 SRTP 上下文服务整个传输，因此各段密钥不同的远端描述会被拒绝。
- SDES 会话**没有数据通道**（它们需要 DTLS）：添加时失败，offer 中的 application 段被拒绝。
- **DTLS-SRTP 仍是默认，浏览器永远看不到 `a=crypto`**：除非开启 SDES，offer 都是 DTLS-SRTP；即使
  开启了 SDES，DTLS-SRTP offer（`UDP/TLS/RTP/SAVPF`，带不带 `a=crypto` 都一样）也以 DTLS-SRTP 应答。
  在两者之间切换的重新协商会被拒绝。

## 影响

- `only-turn` 依赖 `only-dtls` 与 `only-x509`（经 `only` / `only-tls` 已在依赖图中）；`only-webrtc`
  把 `only-x509` 从开发依赖移为正常依赖。
- 新公开 API：`TurnServer::dtls`、`TurnServer::dtls_relay_of`、`TurnDtls`（以及隐藏的
  `TurnDtlsClient` 处理器）、`RelayServer::dtls`、`RelayServer::transport() == "dtls"`、
  `RtcConfig::enable_sdes_srtp`、`Engine::bind_udp_multicast_on`。`turns:...?transport=udp` 不再
  是错误。
- SDES 会话的密钥只与信令通道一样机密；文档已写明，且默认关闭。
- IPv6 mDNS 让每个解析中的 endpoint 多一个套接字，在非 Linux 主机上 `resolve_mdns` 时最多做 64 次
  UDP connect 探测。

测试：only-turn `tests/dtls.rs`（DTLS 1.3 与 1.2 客户端、双向中继数据、close_notify 与删除释放分配、
错误证书被拒、重启的客户端替换其关联、忽略非 DTLS 数据报）；only-webrtc `tests/relay_dtls.rs`（两个
`Endpoint` 经 DTLS 分配中继，数据通道回显；凭据、证书、名字错误；`turns:?transport=udp` URL）、
`tests/sdes.rs`（五个套件各自的媒体回显、保持密钥的重新协商与反方向的 offer、拒绝场景、以
DTLS-SRTP 应答 DTLS-SRTP offer）、`tests/mdns.rs`（经 `ff02::fb` 应答 AAAA 查询、只有 IPv6 应答器
知道的名字被解析并连通、隐藏 `::1` 的 endpoint、绑定链路本地地址的 endpoint）；`a=crypto` 解析与
offer/answer 选择的单元测试。模糊测试：新目标 `turn_dtls`（TURN 核心之前的 DTLS 会话，带与不带
cookie 交换）；`webrtc_sdp` 试用 SDES 配置，并检查密钥不会在未开启时出现，也不会与 fingerprint
同时出现；`webrtc_turn_url` 覆盖 `turns:?transport=udp`。

互通（`tools/interop/webrtc/turn-dtls.sh`，gpu51 上的 Docker，coturn 4.6）：coturn 的
`turnutils_uclient -S` 经 DTLS 对 only-turn 的 DTLS 监听器；only-dtls 连接中的 only_turn 客户端对
coturn 的 DTLS 监听器（提供 DTLS 1.3，协商为 1.2）；两个 `Endpoint` 经 DTLS
（`turns:127.0.0.1:5349?transport=udp`）由 coturn 中继并回显数据通道；对 only-turn 同样如此。

未做：带 MKI 或会话参数的 SDES、无 ICE 的 SDES（普通 `c=` / 端口媒体）、与 SDES 并存的数据通道；
带连接 ID 的 DTLS 上的 TURN；除 mDNS 或入站流量之外其他途径学到的链路本地地址上的 ICE。留给
`only-ice` 的后续工作：在 `MULTICAST_V4` 旁导出 `MULTICAST_V6`，并让解析出的候选携带作用域 ID。
