# ADR-120：拨号 Unix 域套接字，以及在其上的 HTTP 客户端

[English](120-unix-socket-dial.md) | 简体中文

状态：已采纳（2026-11-24）

## 背景

引擎只拨 TCP：`Engine::dial` 和 `dial_from` 接受 `SocketAddr`，后端把正在连接的套接字当作
`TcpStream` 持有，连上时读取它的对端和本端地址。akio-http 的 `Client` 解析 URL 的主机再拨号。

akit（构建在 akio 上的网关）像 fit 一样从 Docker 容器的标签读取路由，并跟随守护进程的事件。
Docker 守护进程的 API 默认在 Unix 域套接字 `/var/run/docker.sock` 上。akit 的规则不让控制面使用
阻塞客户端和异步运行时，akio 缺的东西交给 akio；akit 以 A135 提出了这个需求
（`akit/docs/akio-api-requests.md`）。

## 决定

- **`akio_sys::connect_unix_nonblocking(path) -> io::Result<OwnedFd>`** 发起 `AF_UNIX` 流套接字
  的非阻塞连接（close-on-exec），并加入 `ffi::AF_UNIX` 和 `ffi::sockaddr_un`（在布局测试中与
  `libc` 对照）。空路径、含 NUL 字节的路径、或 `sun_path` 放不下的路径（Linux 107 字节，macOS
  103 字节）返回 `InvalidInput`；不支持抽象套接字。
- **`Engine::dial_unix(path, acceptor, on_error)`** 像拨出的 TCP 连接一样服务这个连接，使用同一个
  组（`client_threads`，否则是最后一个 TCP 监听器的组），通过新的 `Group::dial_unix`（默认不支持；
  epoll 和 io_uring 实现了它）。后端仍把套接字当作 `TcpStream` 持有（`TcpStream::from(OwnedFd)`，
  安全）：拨号命令上的一个标志让它们跳过 TCP 独有的操作（`TCP_NODELAY`、读取对端和本端地址），
  连接的 `peer_addr` 和 `local_addr` 是新常量 `UNIX_ADDR`，即 `0.0.0.0:0`。其余操作（读、写、
  `SO_ERROR`、shutdown、close）都是任何流套接字都支持的。
- **`Client::with_unix_socket(Option<PathBuf>)`** 把该客户端的每个请求都发到这个套接字，不论 URL
  的主机和端口，就像 Go 的 `http.Transport` 配 `DialContext`、curl 的 `--unix-socket` 那样：URL
  的主机仍是 `Host` 字段，也仍是空闲连接的键，`https://` 仍在套接字上跑 TLS，不解析名字，不用
  代理。请求的各项超时照旧生效。

## 后果

- akit 的 Docker 提供者用 akio 的客户端列出容器、跟随 `/events`，回调在 akio 的 I/O 线程上，
  没有任何阻塞。
- Unix 域连接没有 IP 地址；按 `peer_addr` 记日志或做键的代码看到的是 `0.0.0.0:0`。
- `akio-sys/src/net.rs` 新增六个 `unsafe` 块（置零的 `sockaddr_un`、`socket`、接管 fd、
  `connect`），不变量与那里其他套接字相同（任何可能失败的步骤之前先接管 fd，长度不越过结构体）。
- 测试（`crates/akio-http/tests/unix_socket.rs`）：一个保活连接上的多个请求；按写入节奏读取、
  中途被切断的分块流；套接字不存在、路径过长、套接字立即关闭都是错误；`Engine::dial_unix` 的
  地址和双向字节。epoll 和 io_uring（在监听器的组上拨号，所以跑在被测后端上）。
