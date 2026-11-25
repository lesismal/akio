# ADR-121：Unix 域流监听器，以及限定 TLS 1.2 的 TLS 服务端

[English](121-unix-listeners-tls12-cap.md) | 简体中文

状态：已采纳（2026-11-25）

## 背景

akit（构建在 akio 上的网关）沿用 fit 的监听器设置，其中两项在 akio 中没有 API（akit 的
`docs/akio-api-requests.md`）：

- **A23。** 当 `admin.address` 为 `unix/<path>` 时，fit 的 Admin API 监听在 Unix 域套接字上：
  文件设为 `0600`，残留的套接字文件被替换，正在使用的被拒绝，于是只有属主的进程能访问 API，
  不占端口也不需要令牌。akio 的监听器只接受 `SocketAddr`（TCP 或 UDP）；ADR-120 加入的是拨号
  这种套接字，而不是在其上提供服务。
- **A9。** fit 的 `listeners[].tls.max_version` 可取 `1.2`（Go 的 `tls.Config.MaxVersion`），
  用于只卸载 TLS 1.2 的网卡。`ServerConfigBuilder` 只能通过隐藏的、供测试和互通工具用的
  `__tls12_only` 把服务端限定在 TLS 1.2。

## 决定

**A23：`Listener::unix`。**

- `Listener::unix(path)` 是套接字文件上的流监听器，像 TCP 监听器一样提供服务：同样的 acceptor
  （akio-http、TLS、akio-mux），支持 epoll、kqueue 和 io_uring，可在构建时加入，也可通过
  `Engine::add_listener` / `remove_listener` 在运行时增删。它的 I/O 线程共享同一个套接字，竞争
  accept，与 `Listener::tcp_from_std` 相同。
- `Listener::unix_from_std(UnixListener)` 服务一个已绑定并在监听的套接字。
- `Listener::unix_mode(mode)` 在 `bind` 之后、`listen` 之前设置文件的权限位，因此文件带着 umask
  的权限位时不会接受任何连接。用在其他监听器上（包括已在监听的 `unix_from_std`）时，`build`
  以 `InvalidInput` 失败。
- 路径上已有、却没有进程监听的套接字文件（非阻塞 connect 被拒绝）会被替换；正在使用的，或者
  不是套接字的文件，以 `AddrInUse` 失败。监听器被移除或引擎停止后文件保留：它归调用方，与
  `tcp_from_std` 相同。
- 连接没有 IP 地址：它的 `peer_addr` 和 `local_addr` 是 `UNIX_ADDR`（`0.0.0.0:0`，ADR-120），
  监听器在 `Engine::local_addrs` 中的条目也是；accept 过滤器看到的也是这个地址。DPDK 拒绝这种
  监听器（`Unsupported`）；`Accel::Ebpf` 无可引导。
- `akio_sys::listen_unix(path, backlog, mode)` 绑定它（非阻塞、close-on-exec；路径规则同
  `connect_unix_nonblocking`），`akio_sys::accept_stream(listener)` 在 accept 时不读取地址
  （Linux 上 `accept4`，macOS 上 `accept` 后 `fcntl`）：`std` 的 `TcpListener::accept` 会把
  `AF_UNIX` 对端变成错误并关闭连接。后端仍把套接字当作 `TcpListener` 持有，就像 ADR-120 把拨出
  的连接当作 `TcpStream` 持有：`EpollGroup::bind_unix_listener` 与
  `UringGroup::bind_unix_listener` 标记该组的循环，这些循环用 `accept_stream` 接受连接
  （epoll、kqueue），或接收 io_uring 多次 accept 的结果而不查询对端地址，并跳过 `TCP_NODELAY`
  和本端地址。

**A9：`tls12_only`。** `ServerConfigBuilder::tls12_only(bool)` 与
`ClientConfigBuilder::tls12_only(bool)` 成为公开 API（隐藏的 `__tls12_only` 保留，调用它们）。
TLS 1.3 的套件被去掉：同时提供 1.3 的客户端协商为 1.2，且没有 RFC 8446 的降级哨兵（1.2 已是这个
服务端支持的最高版本）；只提供 1.3 的客户端握手失败。`tls12_only` 与 `tls13_only` 同时设置时
`build` 失败。

被否决的方案：

- **`Conn` 上的枚举对端地址**（`Tcp(SocketAddr) | Unix(PathBuf)`）。akio 的每个处理器、过滤器、
  日志和指标读取的都是 `SocketAddr`；ADR-120 已为拨出的 Unix 域连接选择了占位地址，监听器沿用。
- **监听器移除时删除套接字文件。** 监听器无从得知此后是否有别的进程绑定了这个路径；下次绑定时
  的残留文件检查已覆盖重启。
- **接受 `TlsVersion` 的 `min_version` / `max_version`。** akio 只支持 TLS 1.2 和 1.3，两个开关
  已能表达所有组合。

## 影响

- akit 的 Admin API 像 fit 一样监听 `unix/<path>`，文件提供者的控制套接字也可以；akit 的
  `tls.max_version: 1.2` 用 `tls12_only` 构建它的监听器。
- `akio-sys/src/net.rs` 新增六个 `unsafe` 块（Unix 套接字的 `bind` 与 `listen`，accept 及接管其
  描述符，Linux 与 macOS 各一套），不变式与该文件中的其他套接字相同；Unix 套接字的创建和地址与
  ADR-120 的 connect 共用。
- 测试：`crates/akio-http/tests/unix_listener.rs`（请求与文件权限、双向大请求体与中途断开的
  客户端、替换残留文件、拒绝正在使用的文件和普通文件、错误路径、`unix_from_std`、运行时带过滤器
  增删监听器），在 epoll 和 io_uring 上运行；`akio-tls` 的
  `config_tests::a_server_capped_at_tls12`。
