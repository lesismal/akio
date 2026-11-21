# SOCKS 与 HTTP CONNECT 代理

`only-socks` 提供 SOCKS5 / SOCKS4 / SOCKS4a 服务端（`Socks`）、HTTP `CONNECT` 代理
（`connect_proxy`）以及 SOCKS 客户端（`SocksClient`，[见下文](#socks-客户端)）。服务端和代理都在回调之间转发，并且**两个方向都有背压**：一侧跟不上时，暂停读取
另一侧，直到它排空（`hold_reads` + `on_drain`，见[背压](../concepts/backpressure.md)）。

```rust,ignore
{{#include ../../../../crates/only-socks/examples/guide-socks.rs:server}}
```

- 代理需要通过它所在的 engine 拨号上游连接，但构建 acceptor 时 engine 还不存在。`EngineRef`
  解决了这个问题：先创建它，把克隆交给代理，engine 构建好后再 `set`。它以弱引用持有 engine。
- `Socks::new(engine_ref)` 接受无认证的 SOCKS5 `CONNECT`、SOCKS4 和 SOCKS4a（`BIND` 与
  `UDP ASSOCIATE` 需显式开启，见下文）。`.auth(|user, pass| ..)`
  要求 SOCKS5 用户名/密码认证（RFC 1929），并关闭 SOCKS4（它没有认证）。
- 目标：IPv4、IPv6 和域名。域名在逻辑线程池上解析，从不在 I/O 线程上；依次尝试解析出的每个
  地址。
- `connect_proxy(engine_ref)` 是一个 only-http `Service`，为 `CONNECT host:port` 建立隧道
  （其他方法返回 405）。可以单独提供，也可以作为 router 的 fallback；它用
  `Context::upgrade_raw` 接管连接。
- engine 有 `client_threads` 时，上游连接运行在这些线程上。

运行 `cargo run -p only-socks --example guide-socks`：它手工完成一次带用户名/密码的 SOCKS5
握手，并经代理转发到本地的 echo 服务。

## 限制与目标策略

`ProxyConfig`（`Socks::config`、`connect_proxy_with`）为每个会话设限。什么都不设置的配置
同样是有界的：

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `handshake_timeout` | 10 s | 从接受客户端到其上游连接建立（问候、认证、请求、域名解析、连接）。超时则关闭客户端，因此永远不完成（或逐字节慢发）请求的客户端无法占住会话。 |
| `idle_timeout` | 5 min | 隧道在两个方向上都没有任何字节流动达到该时长即关闭（两端）。 |
| `destinations` | `Destinations::PublicOnly` | 允许拨号的地址，在域名解析之后检查。 |

- `Destinations::PublicOnly` 拒绝 loopback、私有地址（RFC 1918、IPv6 ULA）、运营商级 NAT、
  link-local（包括云元数据服务 `169.254.169.254`）、组播、广播和保留地址，以及它们的
  IPv4 映射、6to4 和 NAT64 形式。否则一个他人可达的代理会成为进入其背后网络的通道（服务端
  请求伪造、通往 `localhost` 的开放转发）。SOCKS5 回复 `2`（规则不允许），SOCKS4 回复
  `0x5b`，`CONNECT` 回复 403。解析到被拒地址的域名同样被拒。
  **这是默认行为的变更**：早期版本会拨号任何目标；设置 `Destinations::Any` 可保持旧行为。
- `Destinations::Any` 恢复旧行为，用于本来就是为了访问私有网络的代理（堡垒机）；请限制谁能
  使用它（`auth`、只监听可信网卡）。`Destinations::Custom(f)` 使用你自己的规则。
- 客户端在上游连接建立前发送的数据最多保留 256 KiB（转发的暂停阈值）；超过则关闭客户端。
- `CONNECT` 目标在一个小的有界解析线程池上解析（4 个线程，最多排队 1024 个请求，满时返回
  503），从不在 I/O 线程上。
- 该策略覆盖所有命令：`CONNECT`、`BIND` 期望的对端（被拒地址回复 2，来自被拒地址的连接永远不会
  被接受），以及 `UDP ASSOCIATE` 每个数据报的目的地（按解析后的地址检查，被拒的丢弃）。它在 `allow`
  钩子之前、并且额外生效。
- `BIND` 第一次回复之后不再受握手超时约束（等待由 `bind_timeout` 限制，之后的转发由空闲超时限制）；
  `UDP ASSOCIATE` 建立后，会话超时停止，由 `udp_idle_timeout` 管理该关联。
- 停止读取的对端同样受 engine 的 `Config::write_timeout` 约束。

## BIND 与 UDP ASSOCIATE

这两个命令默认关闭（它们会应客户端请求在代理主机上打开端口），需要在服务器上开启（`bind` 同时覆盖
SOCKS5 与 SOCKS4 的 `BIND`）：

```rust,ignore
let socks = Socks::new(er.clone())
    .bind(true)                                   // SOCKS5 与 SOCKS4 BIND
    .bind_timeout(Duration::from_secs(30))        // 默认 60 秒
    .udp_associate(true)                          // SOCKS5 UDP ASSOCIATE
    .udp_idle_timeout(Duration::from_secs(60));   // 默认 120 秒
let engine = Engine::builder()
    .listen(Listener::tcp(addr).serve(socks))
    .udp_client_threads(1)                        // UDP ASSOCIATE 的转发 socket
    .build()?;
```

- **BIND**（主动模式 FTP 等“对端回连”的协议）：服务器在客户端连到它的那个地址上监听一个新端口，
  回复该地址，接受一个连接（除非请求中的地址未指定，否则只接受来自请求 IP 的连接），再回复一次对端
  地址，然后像 `CONNECT` 一样转发。`bind_timeout` 内无人连接：回复 1 并关闭。接受到的流通过
  `Engine::adopt_tcp` 加入 engine；它把任何在 engine 之外 accept 的 TCP 流当作拨号连接来服务。
  SOCKS4（及 4a）的 `BIND` 方式相同，只是使用 SOCKS4 应答（成功 `0x5a` 带端口和 IPv4 地址，失败
  `0x5b`）；只接受来自 `DSTIP` 的连接（为 `0.0.0.0` 或 4a 主机名时接受任意来源），等待期间其他连接被
  丢弃。经 IPv6 到达的代理拒绝 SOCKS4 `BIND`（无法表达监听地址）。
- **UDP ASSOCIATE**：每个关联在客户端连到代理的地址上拥有自己的 UDP socket（`Engine::bind_udp`），
  因此 engine 需要 UDP I/O 线程（`udp_client_threads` 或一个 UDP listener；没有时回复 1）。只有来自
  控制连接 IP 的数据报才算客户端的，并且端口一旦由请求或第一个数据报确定就只认这一个。分片数据报
  （`FRAG` 不为 0，RFC 1928）会被重组后作为一个数据报转发：每个关联同时只有一个序列，只按顺序接收
  （1、2、3……；分片没有序列号，所以出现缺口、重复、换了目标或中途来了一个完整数据报都会丢弃该序列），
  最多 65,507 字节，自第一个分片起 5 秒后丢弃。只转发来自客户端发送过的地址的应答，因此关联
  不是一个开放的入站端口。主机名在逻辑线程池上解析并按关联缓存。控制连接关闭时关联结束；或者在
  `udp_idle_timeout` 内双向都没有数据报时结束（服务器随后关闭控制连接）。若设置了
  `Config::idle_timeout`，它也作用于控制连接，而 UDP 流动期间控制连接是静默的：两者同时使用时请调大它。

## 访问控制

`Socks::allow` 在认证之后、任何拨号、绑定或解析之前判定每个请求：

```rust,ignore
use only_socks::{Command, Dest};
let socks = Socks::new(er.clone())
    .auth(|u, p| check_password(u, p))
    .udp_associate(true)
    .allow(|r| match (r.command(), r.dest()) {
        // UDP ASSOCIATE 的目的地是客户端自己的地址：放行。
        (Command::UdpAssociate, _) => true,
        (_, Dest::Addr(a)) => !a.ip().is_loopback() && !is_private(a.ip()),
        (_, Dest::Name(host, _)) => r.user() == Some("admin") || !host.ends_with(".internal"),
    });
```

`Request` 提供 `version()`（5 或 4）、`client()`、`user()`（RFC 1929 用户名或 SOCKS4 user id）、
`command()`（`Connect`、`Bind`、`UdpAssociate`、`UdpDatagram`）和 `dest()`（地址，或尚未解析的主机名：
要按地址检查就在钩子里解析）。钩子对 SOCKS5 与 SOCKS4/4a 的 `CONNECT`、`BIND`、`UDP ASSOCIATE` 调用，
并对关联数据报的每个不同目的地调用一次（`UdpDatagram`，结果缓存）。拒绝时回复 2（“规则集不允许连接”），
SOCKS4 回复 0x5b，或丢弃数据报。

`tools/interop/socks/run.sh` 用 curl（`--socks5`、`--socks5-hostname`、`--socks4`、`--socks4a`，有无
密码）、PySocks 的 UDP ASSOCIATE 以及手写的 BIND、SOCKS4 BIND、分片与 UDP 边界用例客户端检查上述全部
行为，并用同样的客户端测试作为参考的 Dante；它还让 `SocksClient`（见下文）分别对 Dante 和 only-socks
运行。

## SOCKS 客户端

`SocksClient` 支持 SOCKS5（`CONNECT`、`BIND`、`UDP ASSOCIATE`；无认证或用户名/密码）、SOCKS4 和
SOCKS4a（`CONNECT`、`BIND`），可以运行在 engine 上（回调在 I/O 线程上执行，不阻塞），也可以基于
`std::net` 阻塞使用：

```rust,ignore
use only_socks::{Dest, SocksClient, Version};
let client = SocksClient::from_url("socks5h://alice:secret@proxy.internal:1080")?;
// 或者 SocksClient::new(Version::Socks5, addr).auth("alice", "secret")

// 阻塞：经代理连到目标的 TcpStream。
let stream = client.dial_blocking(&Dest::Name("example.com".into(), 443))?;

// 在 engine 上：`acceptor` 服务这条隧道（`Tls` acceptor 会在隧道内运行 TLS）。
client.dial(&engine, Dest::Name("example.com".into(), 80), acceptor, |e| eprintln!("{e}"));

// BIND：告诉对端连到哪里，然后服务它的连接。
client.bind(&engine, peer_ip.into(), |bound| announce(bound), acceptor, |e| eprintln!("{e}"));

// UDP ASSOCIATE（SOCKS5）：经中继收发数据报。
client.udp_associate(
    &engine,
    |assoc, from, payload| { /* 来自 `from` 的数据报 */ },
    |r| { let assoc = r.expect("associated"); assoc.send_to(b"query", &dns_server.into()).ok(); },
);
```

- 在 engine 上，到代理的 TCP 连接建立后就会调用 `acceptor.on_open`（与 TLS 拨号相同）：handler 发送
  的数据会等待隧道建立，`on_data` 只看到目标的字节。**隧道打开前的所有失败都交给 `on_error`**：
  解析或连接代理（依次尝试它的每个地址）、拒绝（携带 `only_socks::ProxyRefused` 的 `io::Error`：
  `status()` 是最接近的 HTTP 状态码，`socks_reply()` 是 SOCKS 应答码）、不是 SOCKS 的应答、握手
  超时。随后连接关闭。
- `bind` 的 `on_bound` 在 I/O 线程上、握手进行中收到代理的第一个应答（未指定地址会被替换为代理的
  地址）：把它交给对端，不要在其中使用这条 BIND 连接。阻塞方式：`bind_blocking` 在代理开始监听时
  返回（`bound_addr()`），`accept()` 等待对端。
- `udp_associate` 在 engine 上绑定一个 UDP socket（需要 `udp_client_threads`），告知代理，并把
  `UdpAssociation` 交给 `done`（`send_to`、`relay_addr`、`close`）。不是来自中继的数据报被丢弃；分片
  数据报先重组。阻塞方式：`udp_associate_blocking()` 返回 `BlockingUdp`（`send_to`、`recv_from`），
  drop 即结束。
- 限制：`handshake_timeout`（默认 10 秒）限制连接代理及其应答；`bind_timeout`（默认 60 秒）限制
  BIND 等待对端的时间。阻塞方式逐字节读取应答，所以返回的流正好从隧道的第一个字节开始。
- 主机名：`Dest::Name` 以主机名形式交给 SOCKS5 和 SOCKS4a 代理；SOCKS4 下由客户端解析（只用 IPv4）。

HTTP 与 WebSocket 客户端的 `socks5://` / `socks4a://` 代理使用同一个握手实现
（[HTTP 客户端](http-clients.md#代理)）。见
[ADR-019](https://github.com/lesismal/only/blob/main/docs/adr/019-socks-client-fragments-socks4-bind.zh-CN.md)。

## 内核内转发

在 Linux 上做纯 TCP 转发时，`only::ebpf::Relay` 可以用 sockmap（`SOCKHASH` + `sk_skb`
verdict）在内核中拼接两个 TCP 连接，载荷字节完全不进入用户态。它需要特权，并且默认要求
Linux 6.15+（发现 6.12 在目标发送缓冲区满时会丢数据）。

代理可按需使用它：`ProxyConfig::sockmap = Some(Relay::new(0)?)`（或 `Socks::sockmap(relay)`）
会在写出成功应答时把每条 SOCKS 与 HTTP `CONNECT` 隧道拼接到内核中。应答先于任何被转发的字节
发出；已经在等待的字节（先发问候语的服务器）随后按序到达。

```rust,ignore
let socks = Socks::new(engine_ref.clone()).sockmap(only::ebpf::Relay::new(0)?);
```

以下隧道改在用户态转发：

- relay 无法创建（无特权、内核较老），或拼接失败；
- 客户端连接使用 TLS；
- 客户端在请求之后发来的数据已被代理缓存。

拼接后的字节绕过引擎的写水位。超时与关闭仍然生效：

- 空闲超时读取 socket 的 TCP 计数器（`only::ebpf::byte_counts`）。
- 一端关闭时，要等所有已转发的数据都进入另一端的发送队列后才关闭另一端，因为关闭 socket 会
  丢掉内核中的转发积压。

使用 io_uring 时，若两端都开着而一个在拼接前已完成的读交来了负载，隧道会被关闭，避免乱序。
吞吐量见[基准测试](https://github.com/lesismal/only/blob/main/docs/BENCHMARKS.zh-CN.md#ebpf-加速toolsbenchebpfsh)。

## GSS-API 认证（RFC 1961）

`only_socks::gssapi`（ADR-071）在两端实现 RFC 1961，方法 1：上下文建立的令牌、保护级别协商，以及级别
高于 none 时对 SOCKS 请求、应答和隧道中每个字节的封装。GSS-API 机制本身由应用提供：在系统的 GSS-API 库
（通过自选绑定使用 MIT 或 Heimdal Kerberos）、SSPI 或其他实现之上实现 `GssContext`。

```rust,ignore
use only_socks::gssapi::{GssContext, Protection};

// 服务端：每个连接一个 acceptor 上下文（在逻辑池中创建），以及授予的级别范围。
let socks = Socks::new(engine_ref.clone())
    .gssapi(|| Ok(Box::new(MyKerberos::acceptor()?) as Box<dyn GssContext>),
            Protection::Integrity..=Protection::Confidentiality);

// 客户端：为代理主机名创建 initiator 上下文；请求的级别即可接受的最低级别。
let client = SocksClient::with_host(Version::Socks5, "proxy.example.com", 1080)
    .gssapi(|host| Ok(Box::new(MyKerberos::initiator(&format!("rcmd@{host}"))?) as Box<dyn GssContext>),
            Protection::Confidentiality);
```

- 建立步骤可能阻塞（Kerberos initiator 会向 KDC 申请服务票据）：服务端在逻辑池中执行，客户端每一步在
  一个短命的辅助线程中执行；都不会在 I/O 线程上执行。`wrap` / `unwrap` 对每条消息在 I/O 线程上执行。
- 级别：`None`（只认证；即 Dante 的 `clear`）、`Integrity`、`Confidentiality`；服务端把客户端请求的级别
  限制在自己的范围内后授予，客户端拒绝低于自己请求的级别。
- 服务端的访问控制钩子通过 `Request::user()` 看到 GSS-API 对端的名字。
- `UDP ASSOCIATE` 在所有级别都可用：有保护时，客户端与转发端之间的每个数据报（包括 SOCKS 头）是一条用
  控制连接的上下文封装的 RFC 1961 封装数据消息，服务端、engine 客户端与阻塞客户端都如此；无法解封装的
  数据报被丢弃。因此机制的 `unwrap` 应接受乱序的令牌（数据报会丢失和乱序）。
- 有保护时不支持：客户端阻塞的 `CONNECT` / `BIND` 辅助函数（它们返回 `TcpStream`）、`sockmap` 快速路径，
  以及放在 `Tls::server` 里的服务端（需要它自己的 transport）。

互操作（`tools/interop/socks/gssapi.sh`，Docker 中带 KDC 的 MIT Kerberos；workspace 不链接任何 GSS-API
库，由仅用于测试的 `python3-gssapi` 垫片代替应用的机制）：only-socks 的客户端与服务端、重新编译并启用
GSS-API 的 Dante，以及一个独立的 Python RFC 1961 客户端，所有级别，15/15。

## 不支持

Linux `splice(2)` 转发路径（没有尝试：保留 engine 上带双向背压的转发，内核内转发由
`only::ebpf::Relay` 提供）。

ADR-059 起：数据报可以双向分片发送（RFC 1928 `FRAG`；`UdpAssociation::send_fragmented`、
`BlockingUdp::send_fragmented`，服务端 `Socks::udp_fragment_size(Some(n))`，默认关闭），
`SocksClient::tls(cfg, name)` 让 engine 方法经 TLS 连接代理（服务端放在 `Tls::server` 后面即可）；
HTTP 与 WebSocket 客户端支持 `https://` HTTP 代理。
