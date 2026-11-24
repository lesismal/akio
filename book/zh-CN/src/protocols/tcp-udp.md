# TCP 与 UDP

## TCP 服务端

TCP 服务端就是一个服务某个 acceptor 的 `Listener::tcp(addr)`；见[快速上手](../getting-started.md)
和 [Handler](../concepts/handlers.md)。一些有用的细节：

- 端口 0 表示选择空闲端口；用 `Engine::local_addrs()` 读回实际端口。
- Linux 上每个 I/O 线程在该地址上绑定自己的 `SO_REUSEPORT` socket，由内核分发新连接；macOS
  上各线程共享一个 socket。
- `Config::backlog` 是 `listen(2)` 的 backlog（默认 1024），`Config::max_connections` 在打开的
  连接数达到上限后拒绝 accept（全 engine 计数，包括 dial 出的连接和 UDP peer）。
- 文件 body：协议代码可以通过有序响应的分段（`Part::File`）用 `sendfile(2)` 发送文件区间；
  akio-http 在明文 TCP 上用它发送静态文件。

### 运行时的 listener

重新加载配置时可以不重启地增加和移除 TCP listener（ADR-099）：

- `Engine::add_listener(listener)` 像 `build` 一样绑定 listener，使用它自己的后端、线程数、`Accel`
  与过滤器；engine 运行中时立即启动其线程；返回 `ListenerId`。`Engine::listeners()` 列出正在接受
  连接的 listener 及其 id、地址和线程数（builder 的 listener 的 id 为 `0..n`）。
- `Engine::remove_listener(id)` 停止接受连接并关闭监听 socket；已打开的连接继续运行，每个线程在
  其最后一个连接关闭后退出。
- `Engine::shutdown_listener(id, drain)` 还会对每个打开的连接调用 `on_shutdown`，并在 `drain`
  之后关闭仍打开的连接。
- 两者在该 listener 的线程都已让其 socket 停止监听后返回（对忙碌的线程最多等一秒；在 I/O 线程上
  调用时立即返回）。要在同一地址上无间隙地替换 listener，先加入新的（Linux 上两者通过
  `SO_REUSEPORT` 共享端口），再移除旧的：之后发起的连接都到达新的 listener。
- 会增删 listener 的 engine 应设置 `client_threads`：否则 dial 运行在 builder 最后一个 listener
  的线程上，这些线程在该 listener 被移除后仍会保留。

### accept 过滤器

`Listener::filter(|peer: &SocketAddr| -> bool)` 在 `accept` 之后立即在 I/O 线程上运行，早于
`max_connections`、acceptor 与 TLS；返回 `false` 立即关闭连接，并计入
`akio_connections_filtered_total`。允许 / 拒绝列表放在这里：只做查表。
`Engine::set_listener_filter(id, f)` 与 `clear_listener_filter(id)` 在运行时替换它；调用返回后的
每次 `accept` 都使用新的过滤器。

## TCP 客户端

```rust,ignore
{{#include ../../../../crates/akio/examples/guide-basics.rs:dial}}
```

`Engine::dial` 用与服务端连接相同的 `Acceptor`/`Handler` 模型运行客户端连接。给 engine 设置
`client_threads(n)`，让客户端连接不占用 listener 的线程。

## UDP 服务端

`Listener::udp(addr)` 把每个不同的对端地址变成一个*连接*：

- 对端的第一个数据报到达时执行 acceptor 的 `on_open`；
- **每个数据报**调用一次 `on_data`（保留边界）；
- `Conn::send` 向该对端发送**一个数据报**，可以在任何线程调用；
- 对端静默超过 `Config::udp_idle_timeout`（默认 60 s；设置了更短的 `idle_timeout` 时以它为准）
  就关闭，并执行它的 `on_close`。

```rust,ignore
{{#include ../../../../crates/akio/examples/udp-echo.rs}}
```

Linux 上 listener 的每个线程各绑定一个 `SO_REUSEPORT` socket，同一个对端总是落在同一个线程；
其他系统上由一个线程服务该 listener。接收用 `recvmmsg` 批量进行。`spawn_blocking`、
`close_after_send` 和有序槽位的用法与 TCP 相同。

Linux 上的发送批量化：处理一批接收时产生的回复会用 `sendmmsg` 跨对端一起发出，发给同一对端、
长度相同的连续数据报会合并成一次 UDP GSO 发送（运行时探测，遇到 `EIO`/`EINVAL` 永久关闭；
`AKIO_UDP_GSO=0` 可关闭）。`Conn::send_segments(buf, size)` 一次调用就把缓冲区按 `size`
字节切成连续的数据报发出；akio-quic 用它发送多数据报的 transmit。

保护公开的 UDP 端口：

- `Config::udp_max_peers`：每个 listener 最多这么多对端；超出后来自新对端的数据报被丢弃，
  不创建连接，并计数（`Engine::udp_stats().rejected`）。
- `Config::udp_gro`（Linux，在内核支持时默认开启）：让内核合并同一流的数据报；akio 按内核报告
  的分段大小再拆开，所以 `on_data` 仍然每次一个数据报。它对来自 GSO 发送方的大流量（QUIC
  传输）有帮助，请求/响应式流量没有可测的变慢。需要 `read_buffer` 至少 64 KiB；
  `AKIO_UDP_GRO=0` 可关闭。

## 无连接的 UDP 服务端

对端表是 QUIC、DTLS 或游戏服务器需要的，但 DNS、syslog、StatsD 一类服务器对每个数据报单独
应答，对端表只是负担（每个源地址一个 `Conn`、一个 handler 和一个空闲定时器，伪造的源地址还能
把表填满）。用 `serve_datagrams` 代替 `serve` 来服务 UDP listener，它就完全没有连接（ADR-065）：

```rust,ignore
{{#include ../../../../crates/akio/examples/udp-dns.rs:handler}}

{{#include ../../../../crates/akio/examples/udp-dns.rs:listener}}
```

- 工厂函数**每个 I/O 线程执行一次**（Linux 上每个线程有自己的 `SO_REUSEPORT` socket，内核
  把同一对端固定在一个线程；其他系统由一个线程服务该端口），所以 handler 的状态按线程划分，
  不需要锁。
- `on_datagrams` 以 `(peer, &[u8])` 对的形式拿到每个接收批次，只在这次调用内借用（GRO 合并的
  接收已拆回单个数据报）。没有 `on_open`、`on_close` 和空闲超时，`udp_max_peers` /
  `udp_idle_timeout` 不适用：内存不随发送方地址的数量变化。
- `Replies::send_to(data, addr)` 把发往**任意**地址的数据报排队；回调返回时，这一批的数据报
  一起发出：Linux 上每 64 条消息一次 `sendmmsg`，发往同一地址、长度相同的连续数据报合并为一条
  UDP GSO 消息（其他系统每个数据报一次 `sendto`）。socket 放不下的数据报会等待，在它们发出前
  该线程停止读取；队列受 `Config::max_queued_bytes` 限制（超出时 `send_to` 返回
  `WouldBlock`）。
- 在其他任意线程上，`DatagramSender`（`Send + Sync + Clone`；来自工厂函数、
  `Replies::sender()` 或 `Engine::datagram_sender(local)`）用一次 `sendto` 立即发送；socket
  满时以 `WouldBlock` 丢弃该数据报。慢的工作放到自己的线程上做，再用它从那里应答：回调运行在
  I/O 线程上，不能阻塞。
- `on_shutdown(out)` 让 handler 发出最后的数据报；engine 最多等待 `shutdown_timeout` 让它们
  发完。回调中的 panic 会被记录，handler 继续服务。
- 后端：epoll、kqueue 和 io_uring（由 ring 报告就绪，数据报走同一条 `recvmmsg` / `sendmmsg`
  路径）。不支持 DPDK（`build` 返回 `Unsupported`）。线程数固定（`Engine::set_threads` 会拒绝），
  与每对端连接的 UDP listener 相同。

片段来自 `crates/akio/examples/udp-dns.rs`，一个小型 DNS 风格应答器。在同一台主机上，
这样服务的 64 字节 echo 与每对端连接的 listener 处理的请求数相当，每个请求的服务端 CPU 更少
（见 `docs/BENCHMARKS.zh-CN.md`“无连接 UDP”）。

## UDP 客户端

```rust,ignore
{{#include ../../../../crates/akio/examples/guide-config.rs:udp_dial}}
```

`Engine::dial_udp(addr, acceptor, on_error)` 创建一个独立的 socket（因此有自己的本地端口），
`connect` 到 `addr`。`on_open` 立即执行（UDP 没有握手），每个数据报调用一次 `on_data`，
`close()` 结束它，收到 ICMP "port unreachable" 时以 `ConnectionRefused` 关闭。engine 需要
`udp_client_threads(n)`，或者有一个可以承载它的 UDP listener。

`Engine::dial_udp_from(local, peer, acceptor, on_error)` 则在绑定于 `local` 的 UDP listener 的
socket 上打开一个对端 `Conn`：数据报从 listener 的端口发出，这正是共享一个端口的点对点节点
（DHT 节点、uTP；见 [BitTorrent](bittorrent.md)）所需要的。若该对端在这个 listener 上已有连接，
它以 `AlreadyExists` 失败（其数据报会进入已有的连接）。在 Linux 上，对端的回复可能到达 listener
的另一个线程，该线程会通过 listener 自己的 acceptor 打开一个对端。

## 未提供

- io_uring 上的每对端连接 UDP listener：它们运行在 epoll 的 UDP 循环上（`recvmmsg` /
  `sendmmsg` 已经做到每批一次系统调用）。无连接的数据报 listener 可以运行在 io_uring 上。
