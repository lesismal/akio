# ADR-119：代理隧道在连接建立后检查，以及它的连接超时

[English](119-socks-connected-check-and-connect-timeout.md) | 简体中文

状态：已采纳（2026-11-24）

## 背景

akio-socks 用 `ProxyConfig::destinations` 决定代理可以连到哪里，在拨号前逐个地址检查；另有访问钩子
（`Socks::allow`）看到请求本身，主机名以名字的形式出现。两者都看不到全部：钩子不知道名字解析成了什么，
`Destinations` 不知道某个地址来自哪个名字，也不知道连接是从哪个本地地址发起的。

akit（构建在 akio 上的网关）移植 fit 的正向代理，即 `listeners[].socks` 和用于 HTTP `CONNECT` 的
`forward_proxy` 处理器，其规则两者都需要。fit 按目的主机名解析出的地址来判定它，并且因名字而异：`allow`
列表中的名字只会被 `deny` 网段，或回环、链路本地、组播、未指定地址及本机自身地址的默认拒绝所拒绝；其他名字
则需要某个 `allow` 网段包含其地址。连到本机自身地址的连接表现为来源地址等于目的地址，这只有打开的连接才能
告诉我们。fit 在连接打开后、发送任何数据之前做这项检查，这样 DNS 无法在检查与拨号之间改变答案。

fit 还给代理一个独立的连接超时（`connect_timeout`，默认 10 秒），与 SOCKS 握手的超时分开，并以相应的方式
应答：HTTP `504 Gateway Timeout`，SOCKS5“主机不可达”。akio 的 `handshake_timeout` 覆盖从问候到连接完成的
全过程，超时只关闭客户端而不应答。akit 以 A132 和 A133 提出了这两项（`akit/docs/akio-api-requests.zh-CN.md`）。

## 决定

`ProxyConfig` 增加两个字段，默认都是 `None`，保持所有代理原有行为：

- `connected: Option<Connected>`，其中
  `Connected = Arc<dyn Fn(&Dest, SocketAddr, SocketAddr) -> bool + Send + Sync>`。它在每条 `CONNECT`
  隧道（SOCKS5、SOCKS4 与 4a、HTTP `CONNECT`）的上游连接打开时、在其 I/O 线程上做出判定，此时隧道尚未使用
  该连接，客户端也尚未得知：参数是客户端所请求的目的地（主机名为 `Dest::Name`，地址为 `Dest::Addr`，包括
  HTTP `CONNECT` 的字面地址）、所连接的地址和本地地址（IPv4 映射地址都写成 IPv4）。返回 `false` 时关闭该
  连接，不再尝试其他地址，请求按不允许失败：SOCKS5 应答 2，SOCKS4 `0x5b`，HTTP `502 Bad Gateway`，与 fit
  的应答一致。`destinations` 仍先过滤地址。`BIND` 和 `UDP ASSOCIATE` 仍只用 `destinations`。
- `connect_timeout: Option<Duration>`：从 `CONNECT` 请求到其上游连接建立的最长时间，包括名字解析和尝试的
  每个地址。超过后请求失败并应答（SOCKS5 4，SOCKS4 `0x5b`，HTTP `504 Gateway Timeout`），应答发出后关闭
  客户端。由代理的看门狗线程计时，与另外两个超时相同；`handshake_timeout` 仍从客户端连接时开始计时。

隧道的结果现在只确定一次（`Pending`）：第一个打开并通过检查的上游、一次失败或连接超时，以先到者为准；超时
之后才打开的连接会被关闭。逻辑线程池无法接收名字解析任务（池已满）的 SOCKS 请求，现在会先收到应答 1 再被
关闭，此前是不应答直接关闭。

## 影响

- 代理可以同时按名字和地址判定，并识别本机自身地址，无需自己解析，也不会有可能被 DNS 给出不同答案的第二次
  查询。
- akit 的 `socks` 监听器和 `forward_proxy` 处理器按 fit 的方式应用 fit 的规则和超时。
- 测试（`crates/akio-socks/tests/proxy.rs`）：检查能看到名字和两个地址，并以 SOCKS5 2、SOCKS4 `0x5b` 和
  HTTP 502 拒绝，上游收不到任何数据；连接超时应答 SOCKS5 4 和 HTTP 504，且不会截断按时建立的隧道。epoll 与
  io_uring。
