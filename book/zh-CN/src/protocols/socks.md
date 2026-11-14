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

## 内核内转发

在 Linux 上做纯 TCP 转发时，`only::ebpf::Relay` 可以用 sockmap（`SOCKHASH` + `sk_skb`
verdict）在内核中拼接两个 TCP 连接，载荷字节完全不进入用户态。它需要特权，并且默认要求
Linux 6.15+（发现 6.12 在目标发送缓冲区满时会丢数据）。它尚未接入 only-socks。

## 不支持

SOCKS `BIND` 和 `UDP ASSOCIATE`；Linux `splice(2)` 路径。
