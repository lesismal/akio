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
  only-http 在明文 TCP 上用它发送静态文件。

## TCP 客户端

```rust,ignore
{{#include ../../../../crates/only/examples/guide-basics.rs:dial}}
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
{{#include ../../../../crates/only/examples/udp-echo.rs}}
```

Linux 上 listener 的每个线程各绑定一个 `SO_REUSEPORT` socket，同一个对端总是落在同一个线程；
其他系统上由一个线程服务该 listener。接收用 `recvmmsg` 批量进行。`spawn_blocking`、
`close_after_send` 和有序槽位的用法与 TCP 相同。

Linux 上的发送批量化：处理一批接收时产生的回复会用 `sendmmsg` 跨对端一起发出，发给同一对端、
长度相同的连续数据报会合并成一次 UDP GSO 发送（运行时探测，遇到 `EIO`/`EINVAL` 永久关闭；
`ONLY_UDP_GSO=0` 可关闭）。`Conn::send_segments(buf, size)` 一次调用就把缓冲区按 `size`
字节切成连续的数据报发出；only-quic 用它发送多数据报的 transmit。

保护公开的 UDP 端口：

- `Config::udp_max_peers`：每个 listener 最多这么多对端；超出后来自新对端的数据报被丢弃，
  不创建连接，并计数（`Engine::udp_stats().rejected`）。
- `Config::udp_gro`（Linux，默认关闭）：让内核合并同一流的数据报；only 会再拆开，所以
  `on_data` 仍然每次一个数据报。它对来自 GSO 发送方的大流量（QUIC 传输）有帮助，对请求/响应
  式流量反而有开销。需要 `read_buffer` 至少 64 KiB。

## UDP 客户端

```rust,ignore
{{#include ../../../../crates/only/examples/guide-config.rs:udp_dial}}
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

- 无连接的数据报 API（每个数据报一次回调、没有每对端状态）：每个对端都是一个 `Conn`。
- io_uring 上的 UDP。
