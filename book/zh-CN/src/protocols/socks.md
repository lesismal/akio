# SOCKS 与 HTTP CONNECT 代理

`only-socks` 提供 SOCKS5 / SOCKS4 / SOCKS4a 服务端（`Socks`）和 HTTP `CONNECT` 代理
（`connect_proxy`）。两者都在回调之间转发，并且**两个方向都有背压**：一侧跟不上时，暂停读取
另一侧，直到它排空（`hold_reads` + `on_drain`，见[背压](../concepts/backpressure.md)）。

```rust,ignore
{{#include ../../../../crates/only-socks/examples/guide-socks.rs:server}}
```

- 代理需要通过它所在的 engine 拨号上游连接，但构建 acceptor 时 engine 还不存在。`EngineRef`
  解决了这个问题：先创建它，把克隆交给代理，engine 构建好后再 `set`。它以弱引用持有 engine。
- `Socks::new(engine_ref)` 接受无认证的 SOCKS5、SOCKS4 和 SOCKS4a。`.auth(|user, pass| ..)`
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
- 停止读取的对端同样受 engine 的 `Config::write_timeout` 约束。

## 内核内转发

在 Linux 上做纯 TCP 转发时，`only::ebpf::Relay` 可以用 sockmap（`SOCKHASH` + `sk_skb`
verdict）在内核中拼接两个 TCP 连接，载荷字节完全不进入用户态。它需要特权，并且默认要求
Linux 6.15+（发现 6.12 在目标发送缓冲区满时会丢数据）。它尚未接入 only-socks。

## 不支持

SOCKS `BIND` 和 `UDP ASSOCIATE`；Linux `splice(2)` 路径。
