# ADR-019：SOCKS 客户端、HTTP/WebSocket 客户端的 SOCKS 代理、UDP 分片重组与 SOCKS4 BIND

[English](019-socks-client-fragments-socks4-bind.md) | 简体中文

状态：已采纳（2026-11-17）

## 背景

`docs/DEV-PLAN.md`（M4，akio-socks）留有未完成项：SOCKS 客户端、UDP 分片重组（服务端丢弃所有
`FRAG` 非零的数据报，RFC 1928 允许这样做）、SOCKS4 `BIND`、GSSAPI 和 Linux `splice` 转发路径。
ADR-010 为 HTTP 与 WebSocket 客户端加入了 HTTP 代理（`akio_ws::proxy::Proxy`，`CONNECT` 隧道作为
TLS 之下的一层 `Transport`），并把 SOCKS 列为“暂不支持，以后可增量加入”。

依赖方向是 `akio-ws → akio-http → akio-socks`（服务端的 HTTP `CONNECT` 代理是一个 akio-http
服务），因此写在 akio-socks 里的客户端无法被 HTTP 或 WebSocket 客户端使用，否则会形成循环依赖。

## 决定

1. **只有一份 sans-io 客户端握手，放在 akio-ws**（`akio_ws::socks`，`#[doc(hidden)]`，紧挨着
   ADR-010 的 HTTP 代理隧道）。`Handshake::new(version, cmd, target, auth)` 拒绝协议无法表达的
   请求（SOCKS4 上的主机名或 IPv6、SOCKS4a 上的 IPv6、SOCKS4 上的 `UDP ASSOCIATE`、超过 255 字节
   的主机名和凭据、空的 SOCKS5 凭据）；`start` 写出问候（SOCKS5 提供“无认证”，有凭据时再加上
   用户名/密码，由代理选择）或 SOCKS4 请求；`feed` 消费代理发来的字节，写出需要回应的内容（RFC
   1929 凭据、请求），返回用掉的字节数和每个成功的应答（`BIND` 有两个）。最后一个应答之后的
   字节属于隧道数据。拒绝是携带 `ProxyRefused` 的错误；不是 SOCKS 的字节是 `InvalidData`。它是
   唯一的 SOCKS 客户端解析器：代理隧道、akio-socks 的客户端和模糊测试目标都运行它。

   *为什么放在 akio-ws*：它是两个客户端共享的最底层 crate，已经拥有代理隧道（`Connect`），而且
   这个握手和 `CONNECT` 形状相同（字节流开始前的一段前缀交换），所以接入同一个 `Transport`，
   客户端的结构不用改。

2. **HTTP 与 WebSocket 客户端支持 SOCKS 代理。** `Proxy::all/http/https` 与 `ProxyServer` 接受
   `socks5://`、`socks5h://`、`socks4://` 和 `socks4a://`（默认端口 1080；URL 中的凭据变成 RFC 1929
   凭据，或 SOCKS4 的 user id）。`Proxy::from_env` 还读取 `all_proxy` / `ALL_PROXY`，用于专门变量
   没有设置的协议（curl 的约定；SOCKS 通常就是这样配置的：`ALL_PROXY=socks5h://…`）。对 SOCKS
   代理，`Connect::new` 运行 SOCKS 握手而不是 `CONNECT`，所有请求都经隧道到达目标，包括
   `http://` 请求（不用绝对形式）。`socks5h` 和 `socks4a` 把主机名交给代理；`socks5` 和 `socks4`
   先用 `akio::dns` 解析目标（curl 的语义），并请求第一个 IPv4 地址（没有则用第一个；SOCKS4 只能
   IPv4），因为一条隧道只能指定一个地址，而 `localhost` 和双栈主机名常常把目标并未监听的 IPv6
   地址排在前面。

3. **`ProxyRefused` 涵盖 SOCKS。** SOCKS 的拒绝与客户端已经报告的错误类型相同：`status()` 是
   最接近的 HTTP 状态码（407：没有可接受的方法或认证失败；403：“规则集不允许”、identd 拒绝；
   502：无法到达目标；501：不支持的命令或地址类型；504：TTL 过期），`reason()` 是应答码的含义，
   新增的 `socks_reply()` 是 SOCKS5 的 `REP` / SOCKS4 的 `CD`（方法与认证失败为 0xff）。检查
   `status() == 407` 的代码对两种代理都有效。

4. **akio-socks 客户端：`SocksClient`。** `new(version, addr)`、`with_host(version, host,
   port)`、`from_url(url)`、`auth(user, password)`、`handshake_timeout`（10 秒）、`bind_timeout`
   （60 秒），以及 `Version`（`Socks5`、`Socks4`、`Socks4a`）。目标使用服务端的 `Dest`（地址或
   主机名；新增 `From<SocketAddr>`）。在引擎上，不阻塞：
   - `dial(engine, to, acceptor, on_error)`：`CONNECT`；acceptor 可以是 `Tls` acceptor（TLS 在
     隧道内运行）。与 TLS 拨号一样，到代理的 TCP 连接建立时就打开 handler：它发送的数据会被
     暂存到隧道打开为止，`on_data` 只看到目标的字节。
   - `bind(engine, from, on_bound, acceptor, on_error)`：`on_bound(SocketAddr)` 在 I/O 线程上、
     握手进行中收到第一个应答（未指定地址会被替换为代理的地址）。
   - `udp_associate(engine, on_datagram, done)`：在代理同族的未指定地址上通过 `Engine::bind_udp`
     绑定一个 UDP socket 并告知代理（`0.0.0.0:port`），`done` 收到一个 `UdpAssociation`
     （`send_to(payload, &Dest)`、`relay_addr`、`local_addr`、`is_open`、`close`）；中继发来的每个
     数据报（重组之后）都会调用 `on_datagram(&UdpAssociation, Dest, &[u8])`，其他来源的丢弃。

   **隧道打开前的所有错误都交给 `on_error`**：解析、连接（依次尝试代理的每个地址）、拒绝、不是
   SOCKS 的应答以及握手超时。引擎不会把 transport 的错误传给 `on_close`（TLS 失败时那里同样是
   `None`），所以隧道 transport 增加了隐藏的 `on_fail` / `on_open` 钩子，超时则使用 akio-socks 已有
   的看门狗加上一个 `on_fire` 回调（隧道打开时解除；隧道内的 TLS 保留自己的握手超时）。随后连接
   关闭，handler 的 `on_close` 收到的错误为空。

   基于 `std::net` 的阻塞辅助：`dial_blocking(&Dest) -> TcpStream`、
   `bind_blocking(&Dest) -> BlockingBind`（`bound_addr`、`accept() -> (TcpStream, SocketAddr)`，
   受 `bind_timeout` 限制）、`udp_associate_blocking() -> BlockingUdp`（`send_to`、带重组的
   `recv_from`、`set_read_timeout`、`relay_addr`、`local_addr`、`is_open`；drop 即结束关联）。
   应答逐字节读取，握手不会吃掉任何隧道字节。SOCKS4 的目标主机名由客户端解析（引擎上用
   `akio::dns`，阻塞时在调用线程上），只用 IPv4。

5. **UDP 分片重组（RFC 1928 第 7 节）**，用于服务端中继（客户端到目标）和两种客户端关联（中继
   到客户端），共用一份实现：每个关联一个队列（由客户端对应的中继 peer 持有，数据报路径上没有
   锁；`FRAG` 为 0 的数据报只多一次分支），只按 1、2、3……的顺序接收分片；出现缺口、重复或更小
   的位置（RFC 1928 的重置规则）、换了目标，或中途来了一个完整数据报，都会丢弃该序列（完整
   数据报照常转发）；最高位置位的分片结束序列；最多 65,507 字节（一个 UDP 数据报的载荷），自
   第一个分片起 5 秒后丢弃（RFC 1928 要求的最小计时；在下一个分片到达时检查，内存随关联释放）。
   分片没有序列号，丢失的分片与乱序的分片无从区分：只按顺序接收是唯一不会把两个序列拼接在
   一起的规则。访问控制钩子仍然按目标判定，在缓存分片之前。我们发出的数据从不分片。

6. **SOCKS4 `BIND`**，与 SOCKS5 的共用 `Socks::bind(true)` 开关和钩子（`Command::Bind`，版本
   4）：监听器和 accept 线程共用，应答使用 SOCKS4 格式（成功 `0x5a` 带端口和 IPv4 地址，失败或
   超时 `0x5b`）；IPv6 的控制连接无法表达，予以拒绝。只接受来自 `DSTIP` 的连接（为 `0.0.0.0` 或
   SOCKS4a 主机名时接受任意来源）；等待期间其他连接被丢弃，与 SOCKS5 相同，而不是像 SOCKS4 文本
   描述的那样以 `0x5b` 结束请求（对端口的扫描不应终止正当的等待）。

7. **不做 Linux `splice` 转发。** 任务只在测得收益时才允许做。当前转发是在引擎缓冲区上从回调
   到回调、带双向背压；`splice` 路径需要每条隧道一对管道，绕过引擎的队列和指标，而 akio-ebpf
   已经有内核内转发（`Relay::splice`，sockmap）。没有尝试。

公开 API（akio-socks）：`SocksClient`、`Version`、`UdpAssociation`、`BlockingBind`、
`BlockingUdp`、`DEFAULT_CLIENT_HANDSHAKE_TIMEOUT`、`DEFAULT_BIND_TIMEOUT`、`ProxyRefused`（重新
导出）、`impl From<SocketAddr> for Dest`。akio-ws：`ProxyRefused::socks_reply`。隐藏（不在 semver
承诺内）：`akio_ws::socks`、`ProxyServer::{kind, credentials, parse, is_http, resolves_locally,
is_socks4}`、`ProxyKind`、`proxy::pick_target`、`Connect::{socks, on_bound, on_fail, on_open,
handshake_timeout}`、`ProxyRefused::socks`。

## 影响

- `socks5://` / `socks5h://` 可直接用于 `akio_http::client::Client` 和 `akio_ws::client::dial`，
  无需新的客户端 API；`ProxyServer::parse` 不再拒绝 SOCKS 协议，未知协议的错误信息会列出支持的
  协议。
- 行为变化：`Proxy::from_env` 现在读取 `ALL_PROXY`；原来丢弃分片数据报的 SOCKS5 中继现在会转发
  完整的按序序列；在 `bind(true)` 的服务端上，SOCKS4 `BIND` 请求会被处理而不是拒绝。
- UDP 关联的数据报路径对 `FRAG` 为 0 的数据报除一次分支外没有变化；TCP 转发未改动。
- 验证：单元测试（编解码、transport、重组），集成测试（`tests/client.rs`：每个版本的阻塞与引擎
  方式、拒绝、超时、乱码、BIND、UDP、双向分片重组、HTTP 客户端经 `socks5h://` / `socks5://`；
  akio-ws：WebSocket 客户端经 SOCKS5 代理），模糊测试目标 `socks_client`，以及
  `tools/interop/socks/run.sh`（我们的客户端对 Dante 和 akio-socks；PySocks、curl 和手写客户端对
  服务端，包括分片和 SOCKS4 BIND）。

## 考虑过的其他方案

- *客户端编解码放在 akio-socks，不接入 HTTP/WebSocket*：最简单，但客户端仍无法使用
  `ALL_PROXY=socks5h://…`，以后还得写第二个解析器。
- *在 akio-ws 之下新建 `akio-socks-client` crate*：为约 400 行、只有 akio-ws 和 akio-socks 两个
  使用者的代码多一个 crate。
- *在 akio-core 中把 transport 错误传给 `on_close`*：通用的修法，但会改变所有 TLS 连接 handler 的
  行为；钩子把改动限制在本地。
- *按位置乱序重组*：没有序列号就无法安全实现（丢失一个分片会把两个数据报拼在一起）。
