# ADR-095：不终止 TLS 按 SNI 路由，以及 PROXY 协议（akio-mux）

[English](095-mux-sni-routing-proxy-protocol.md) | 简体中文

状态：已采纳（2026-11-23）

## 背景

akit（基于 akio 的网关，对标 fit）提出了两个监听侧功能（`akit/docs/akio-api-requests.md`，A4 和 A5）：

- **A5，TLS 透传。** 四层路由按 TLS ClientHello 中的服务器名选择上游，转发加密字节，不终止 TLS。
  `akio-mux` 原有的 `Rule::Tls` 只看前两个字节，匹配任何 ClientHello；没有任何地方读取服务器名，
  而默认嗅探上限（64 字节）远小于真实的 ClientHello（300 字节到 2 KiB，带后量子密钥共享时更大；
  客户端还可能把它分成多次读取、多个 TLS 记录）。
- **A4，PROXY 协议。** 在负载均衡器（HAProxy、AWS NLB、nginx `proxy_protocol`）之后，客户端地址来自
  协议首字节之前的 PROXY 头（v1 文本或 v2 二进制）；上游也可能要求 akit 在自己的字节前写一个。

两者都在任何协议处理器存在之前读取连接的一段有界前缀，再把连接交出去。这正是 `akio-mux` 已经在做的：
在字节上限和截止时间（每进程一个看门狗线程，ADR-009 规则 9）之下缓存前几个字节，把它们重放给选中的
acceptor，此后连接归它所有（`spawn_blocking` 完成回调、优雅关闭）。并行的改动（ADR-094）为引擎增加
运行时监听器和 accept 过滤器；这两个功能保持为 acceptor 层，不碰引擎和后端。

## 决定

### 1. 两者都放在 akio-mux

不新建 crate：PROXY 层需要的正是 `Mux` 的那套机制（缓冲、字节上限、嗅探截止时间、重放、
供 `on_shutdown` 用的 `chosen` acceptor），而 akio-mux 除 akio-core 外没有依赖。每一层都是
`DynAcceptor`，可以嵌套组合：`ProxyProtocol::new_any(Mux::new().route(Rule::TlsSni(..), passthrough))`。

### 2. akio-mux 里的 ClientHello 解析器（`akio_mux::tls`）

akio-tls 有一个 `pub(crate)` 的 ClientHello 解码器，但公开它会让 akio-mux 为了两百行解析依赖整个
TLS 栈，而且它解码的内容远多于路由所需。akio-mux 自带一个小的独立解析器，
`tls::parse_client_hello(&[u8]) -> Result<ClientHello<'_>, HelloError>`：

- 从连续的握手记录（内容类型 22，记录版本 `0x03 xx`，记录长度 1..=2^14，即明文上限）重组握手消息：
  hello 可以跨记录，记录可以按任意方式切分它。hello 完整之前出现非握手记录、零长度或超长记录、
  ClientHello 以外的握手类型，或者消息长度超出其自身字段，都是 `Invalid`。
- 遍历 ClientHello（版本、随机数、session id ≤ 32、密码套件（偶数长度 ≥ 2）、压缩方法 ≥ 1、扩展），
  从输入中借用保留：服务器名（`server_name` 扩展，`host_name` 类型；名字只能是 ASCII 字母、数字、
  `-`、`.`、`_`，1..=255 字节，不能有空标签）、ALPN 协议列表和 legacy 版本。重复扩展是 `Invalid`
  （RFC 8446 4.2）。
- 解析满足前缀一致性：hello 的前缀要么 `Incomplete`、要么已经 `Invalid`，永远不会 `Ok`；更长的输入
  不会把 `Invalid` 变成别的。这正是 `Rule::decide` 所需要的。hello 所在最后一条记录中其后的字节被忽略。
- `SniMatcher` 和 `ClientHello` 在 crate 根重新导出。

### 3. 新规则

`Rule` 是 `#[non_exhaustive]`，以下都是新增：

- `Rule::TlsSni(SniMatcher)`：服务器名匹配的完整 ClientHello。`SniMatcher::new(["example.com",
  "*.example.org"])`：精确名和 `*.` 通配（与证书一样只匹配一个标签：`*.example.org` 匹配
  `a.example.org`，不匹配 `example.org` 和 `a.b.example.org`），不区分大小写、忽略末尾的点，
  构造时一次性建成哈希集合（规则 11）。没有服务器名的 hello 不匹配。
- `Rule::TlsHello(Arc<dyn Fn(&ClientHello) -> bool>)`：基于解析后的 hello 做任意决定（服务器名、
  ALPN、缺少 SNI）。

两者在 hello 完整前都回答 `NeedMore`，畸形的回答 `No`。每条路由各自解析；代价是 hello 完整前每次
读取遍历一遍记录头，完整时每条路由完整解析一次。

### 4. 路由严格按顺序尝试

`Mux` 原先返回第一个回答 `Yes` 的路由，即使更早的路由仍在回答 `NeedMore`。对 `[TlsSni(..), Tls]`
来说，这会让每个 hello 在两个字节后就交给 `Tls`。现在，只要更早的路由尚未决定，后面的 `Yes` 就等待；
当更早的路由都回答 `No` 时它胜出；到达嗅探上限时，第一个 `Yes`（否则 fallback）接手连接。这正是文档
原本承诺的（"路由按顺序尝试"）；在后面的路由匹配时，前面的路由从不回答 `NeedMore` 的配置不受影响。
这一改动只给每个连接一次的决定增加一个分支。

### 5. 路由了 SNI 规则时嗅探上限变大

`max_sniff_bytes` 原默认 64。带有 `TlsSni` 或 `TlsHello` 路由的 mux 现在默认改为 `TLS_SNIFF_BYTES`
（16 KiB + 5，一条满长记录），除非显式设置过 `max_sniff_bytes`。到达上限仍不完整的 hello 与其他
未决连接一样交给 fallback（或关闭）。嗅探超时不变（5 秒），约束慢速滴漏的客户端。没有这些规则的
mux 上限不变。

### 6. PROXY 协议：`akio_mux::proxy`

- **解析器。** `ProxyHeader::parse(&[u8]) -> Result<(ProxyHeader, usize), ProxyError>`，两个版本，
  与 hello 解析器一样满足前缀一致性：
  - v1：`PROXY TCP4|TCP6|UNKNOWN ... \r\n`，最多 107 字节；地址必须与族一致，端口为十进制
    0..=65535、不带前导零，单个空格分隔；`UNKNOWN` 忽略该行其余部分。
  - v2：12 字节签名，版本 2，命令 `LOCAL` 或 `PROXY`，族 `UNSPEC` / `INET` / `INET6` / `UNIX`，
    协议 `UNSPEC` / `STREAM` / `DGRAM`；长度必须覆盖地址块；剩余部分必须恰好解析为 TLV。
    `CRC32C` TLV（0x03）会被校验。`LOCAL` 头的地址被忽略（使用真实地址），`UNSPEC` 族同样。
  - `ProxyHeader { version, command, transport, addresses, tlvs }`，`Addresses::{None, Inet {
    source, destination }, Unix { source, destination }}`；辅助方法 `source()`、`destination()`、
    `tlv(kind)`、`authority()`（TLV 0x02）。
- **监听层。** `ProxyProtocol::new(next)` / `new_any(next)`：读取头部的 `DynAcceptor`，然后打开
  `next` 并重放头部之后的字节。选项：`header_timeout`（默认 5 秒，与嗅探截止时间共用看门狗）、
  `max_header_bytes`（默认 4096；v1 总是限制为 107，v2 为 16 + 65535）、`versions(v1, v2)`（默认都接受）、
  `allow_missing(bool)`（关：没有头的连接被关闭；开：原样交给 `next`，不附加头部）、
  `trusted(Fn(SocketAddr) -> bool)`（只对这些对端读取头部；其他对端直接交给 `next`，如同没有这一层：
  不相信它们发来的头）。畸形、超长或超时的头部会关闭连接；声明长度超过上限的 v2 头在读到长度时即被拒绝。
- **地址放在哪里。** 解析出的头部附加在连接上，用 `proxy::header(&conn) -> Option<&ProxyHeader>`
  读取，或用 `proxy::client_addr(&conn)`（代理来源地址，否则 `peer_addr`）。`Conn::peer_addr`
  仍报告套接字的对端：在所有协议之下改变它的含义会出人意料，需要客户端地址的代码主动去取。
- **拨号侧。** `ProxyHeader::proxy(source, destination)` / `ProxyHeader::local()`、`with_tlv`、
  `encode_v1() -> Option<Vec<u8>>`（UNIX 或带 TLV 时为 None，v1 无法承载）、`encode_v2() -> Vec<u8>`，
  以及 `proxy::send_header(&conn, &header, Version)`：拨号处理器在 `on_open` 中发送的第一样东西
  （连接完成前排队的字节会在连接完成后发出）。

### 7. akio-core：每个连接一个只写一次的附件

`ConnInner` 增加 `attachment: OnceLock<Arc<dyn Any + Send + Sync>>`（每连接 24 字节），以及
`ConnInner::attach(value) -> Result<(), Arc<..>>`（先写者胜）和 `Conn::attachment::<T>() -> Option<&T>`。
通用，因此 akio-core 不知道 PROXY 头；只写一次，因此读取不加锁（规则 12）。它由拥有连接首字节的
那一层在协议处理器运行之前设置。只有一个槽，因为目前唯一的写者是 PROXY 层；将来另一层也需要时，
存一个同时包含两者的结构体。这是唯一的 akio-core 改动。

## 影响

- akit 得到按名字透传（`Rule::TlsSni` / `Rule::TlsHello` 路由到转发 acceptor）和负载均衡器后的
  客户端地址，而 akio-mux 不依赖 akio-tls。
- 测试覆盖：跨读取、跨记录切分的 hello，没有 SNI，畸形和超长的 hello，嗅探超时，通配匹配；
  PROXY v1/v2 合法、截断、伪造长度、LOCAL、慢速滴漏头部、不受信任的对端；同一连接上先 PROXY
  再 SNI 规则。模糊测试目标 `mux_tls_hello` 和 `proxy_header` 检查不 panic、前缀一致性，以及编码
  解析出的头部能再解析回同样的值。
- akio-http 仍以 `peer_addr` 作为远端地址。在那里（以及访问日志中）使用 `proxy::client_addr`
  留给应用或后续改动。

## 未做

- TLS 1.3 加密 ClientHello（ECH）：路由看到的是外层服务器名（面向客户端的服务器），这也正是
  带 ECH 的透传所需要的。
- QUIC（UDP）SNI 路由和 UDP 上的 PROXY v2：没有 UDP mux。
- PP2 SSL 子 TLV 作为原始 TLV 字节保留，不做解码。
