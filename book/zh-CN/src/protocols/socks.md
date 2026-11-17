# SOCKS 与 HTTP CONNECT 代理

`only-socks` 提供 SOCKS5 / SOCKS4 / SOCKS4a 服务端（`Socks`）和 HTTP `CONNECT` 代理
（`connect_proxy`）。两者都在回调之间转发，并且**两个方向都有背压**：一侧跟不上时，暂停读取
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

这两个 SOCKS5 命令默认关闭（它们会应客户端请求在代理主机上打开端口），需要在服务器上开启：

```rust,ignore
let socks = Socks::new(er.clone())
    .bind(true)                                   // SOCKS5 BIND
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
- **UDP ASSOCIATE**：每个关联在客户端连到代理的地址上拥有自己的 UDP socket（`Engine::bind_udp`），
  因此 engine 需要 UDP I/O 线程（`udp_client_threads` 或一个 UDP listener；没有时回复 1）。只有来自
  控制连接 IP 的数据报才算客户端的，并且端口一旦由请求或第一个数据报确定就只认这一个。分片号不为 0
  的数据报被丢弃（RFC 1928 允许未实现分片的实现这样做）。只转发来自客户端发送过的地址的应答，因此关联
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
密码）、PySocks 的 UDP ASSOCIATE 以及手写的 BIND 与 UDP 边界用例客户端检查上述全部行为，并用同样的客户端
测试作为参考的 Dante。

## 内核内转发

在 Linux 上做纯 TCP 转发时，`only::ebpf::Relay` 可以用 sockmap（`SOCKHASH` + `sk_skb`
verdict）在内核中拼接两个 TCP 连接，载荷字节完全不进入用户态。它需要特权，并且默认要求
Linux 6.15+（发现 6.12 在目标发送缓冲区满时会丢数据）。它尚未接入 only-socks。

## 不支持

UDP 分片重组（分片会被丢弃）、SOCKS4 `BIND`、GSSAPI 认证、SOCKS 客户端、Linux `splice(2)` 路径。
