# ADR-155：每个连接自己的空闲超时，以及 UDP listener 的移除与排空

[English](155-per-connection-idle-and-udp-listener-removal.md) | 简体中文

状态：2026-11-26 采纳。akit API 请求 A78 与 A22。

## 背景

**空闲超时。** 引擎有两个空闲超时，各自作用于它服务的所有连接：`Config::idle_timeout`（TCP，只把收到
的数据算作活动）和 `Config::udp_idle_timeout`（UDP 对端，HTTP/3 listener 的对端也在内）。网关的四层
服务（akit 的，沿用 fit 的设计）各有自己的空闲超时（默认 TCP 10 分钟、UDP 1 分钟），而客户端连接与
上游连接之间的转发只有在两边都不发送时才算空闲：下载时客户端连接只有写出。akit 目前在自己的定时器
线程上扫描连接，并把引擎的 UDP 空闲超时调高到各服务中最长的那个，免得 akio 先关掉会话。

**运行时的 UDP listener。** ADR-099 可以在运行中的引擎上添加、移除并排空 TCP listener；UDP listener
只能交给 builder（`remove_listener` 和 `shutdown_listener` 返回 `Unsupported`，`add_listener` 返回
`InvalidInput`），运行时绑定的 socket（`Engine::bind_udp`）只能连同其对端一起立即关闭
（`UdpBinding::close`）。akit 在这类 socket 上提供 HTTP/3，所以移除或修改提供 `h3` 的 listener 的
重载会被拒绝，直到重启；而重载添加的 HTTP/3 在移除时没有排空就被切断。按对端区分的 UDP listener 与
TCP listener 在这里有一个关键区别：它的对端没有自己的 socket，都在 listener 的 socket 上收发数据报
（在 Linux 上，每个 I/O 线程一个 `SO_REUSEPORT` socket）。

## 决定

1. **`Conn::set_idle_timeout(Option<Duration>)`** 让一个连接用自己的空闲超时代替引擎的：TCP 连接
   （接受的或拨出的）或 UDP 对端（listener 的、绑定 socket 的，或 `dial_udp` 的）。`Some(d)` 在
   `d` 没有活动后关闭它（至少 1 毫秒），`None` 永不因空闲关闭。**`Conn::set_idle_counts_writes(bool)`**
   把连接发出的数据也算作活动，无论超时是它自己的还是引擎的。两者都可在任何线程、任何时候调用；关闭
   发生在连接自己的 I/O 线程上，与引擎的空闲关闭完全相同（`on_close` 收到 `ErrorKind::TimedOut`
   "idle timeout"，计入 `idle_timeouts`）。连接关闭后返回 `Err(Closed)`；在沿用引擎超时的后端
   （DPDK、TUN）上返回 `Err(Io(Unsupported))`。
2. **I/O 路径不为它付任何代价。** 设置是 `ConnInner` 上的两个原子量，事件循环只在被告知时才读：
   setter 调用 `LoopLink::retime_conn(id)`（默认方法，返回 `false`），它向 epoll/kqueue、io_uring 和
   UDP 事件循环投递一条命令（轮次调度下则在调用线程上，持有分片锁，在 poller 的连接表中重新安排
   定时器）。事件循环把设置复制到该连接的 `IdleRule`，并从连接最后一次活动起重新安排定时器。从不
   设置的连接使用 `IdleRule::ENGINE`，其检查与事件循环一直以来所做的相同；读操作仍然只记录事件循环
   的时钟。
3. **写出按采样计算，而不是逐次打时间戳。** 在写路径上计算写出，会让每次 `send`（来自任何线程）都多
   一次读时钟（或一次共享写）。改为：计算写出的连接每隔超时的八分之一检查一次，自上次检查以来发出的
   字节（连接已有的 `sent` 计数）把它的最后活动时间移到本次检查的时间。这个时间从不早于实际，所以连接
   不会被提前关闭；最多晚八分之一个超时关闭。对转发所用的超时（数秒到数分钟）而言，每个这样的连接每个
   超时检查八次的开销测不出来。
4. **UDP listener 可以移除与排空。** `remove_listener` 和 `shutdown_listener(id, drain)` 接受按对端
   区分的 UDP listener：此后来自新地址的数据报被丢弃（不为它们打开对端，`open_udp_peer` 被拒绝），
   而 listener 已有的对端继续收发数据报；有排空时，每个对端立即收到 `Acceptor::on_shutdown`，到截止
   时间仍在的被关闭。listener 的 socket 在**所有线程上都没有对端时**（或到截止时间）才关闭：在 Linux
   上各线程的 socket 组成一个 `SO_REUSEPORT` 组，某个 socket 提前离开，会让内核把其余对端的流哈希到
   不认识它们的 socket 上。等待其他线程期间，每个线程每 50 毫秒看一次。随后线程退出，除非它们还服务
   `dial_udp` 和 `bind_udp`（builder 的最后一个 UDP listener 且没有 `udp_client_threads`），此时保留。
   `add_listener` 接受按对端区分的 UDP listener，并给它独立的线程（UDP 组不共享，ADR-130）；它不会
   成为 `dial_udp` 或 `bind_udp` 的目标。数据报 listener（ADR-065）和 DPDK 仍为 `Unsupported`。
5. **`UdpBinding::shutdown(drain)`** 对运行时绑定的 socket 做同样的事：不接受新对端，已有对端收到
   `on_shutdown`，对端都走后或到截止时间关闭 socket。`close` 提前结束排空；第二次 `shutdown` 什么也不做。
6. **HTTP/3 会排空。** `akio_quic::QuicHandler::on_shutdown`（默认什么也不做）会传给服务端中这样的
   连接：其对端的 UDP 连接收到了 `on_shutdown`（listener 或绑定 socket 被排空，或引擎关闭）。akio-h3
   在自己的控制流上发送 `GOAWAY`，携带它尚未见过的第一个客户端请求流（RFC 9114 第 5.2 节），回答已有
   的请求，以 `H3_REQUEST_REJECTED` 拒绝之后的请求，并立即关闭从未有过请求的连接。

## 影响

- akit 按服务为每个被转发的连接和 UDP 会话设置空闲超时（转发两侧都计算写出），由 akio 关闭；它的
  定时器扫描以及调高的引擎 UDP 空闲超时都可以去掉。重载可以像对 TCP listener 一样移除、修改并排空
  HTTP/3 listener。
- `IdleRule` 让各事件循环的每连接记录增大 16 字节。
- 被移除的 UDP listener 在同一地址的新 listener 旁排空时，内核仍会把一部分新对端哈希到旧 socket 上，
  旧 socket 在排空结束前丢弃它们：较短的排空（或换一个端口）能把这段空档缩小。没有排空
  （`remove_listener`）时，空档持续到旧对端都离开，所以 UDP 应当使用 `shutdown_listener`。
- 在排空截止时间被关闭的 UDP 对端，其上的 QUIC 连接收不到 `CONNECTION_CLOSE`（socket 已经没了），
  由它的空闲超时结束。
- 引擎自身关闭时也会给 HTTP/3 客户端发送 `GOAWAY`（它本来就会对 UDP 对端调用 `on_shutdown`）。
