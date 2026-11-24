# ADR-099：运行时增加、移除和排空 TCP 监听器，以及对已接受连接的过滤器

[English](099-runtime-listeners-accept-filter.md) | 简体中文

状态：已采纳（2026-11-23）

## 背景

网关在不重启的情况下重新加载配置：监听器会出现、消失或更换 TLS 设置，而消失的监听器上的连接要么继续运行，要么被排空。
fit 底下的 fib 为此提供了 `AddBinding`、`RemoveBinding` 和 `ShutdownBinding`，并用 `Binding.Filter` 在 accept 时检查
允许 / 拒绝列表。akit 是 fit 基于 `akio` 的 Rust 对应项目，它请求了这两项能力（akit `docs/akio-api-requests.md`，A1 与 A3）。

`akio` 的 TCP 监听器在 `EngineBuilder::build` 时就固定了。运行时已有 `bind_udp`、`adopt_tcp`（在别处 accept 的流）、
线程数调整（`set_threads`，ADR-028）和整个引擎的 `shutdown`，但不能增加或关闭引擎自己的任何监听器，在 `accept` 与
acceptor 之间除了 `max_connections` 检查也没有其他逻辑。

`akio` 处于 1.0.0-rc.1：改动必须是增量的。`Engine::local_addrs`、`threads`、`accel_status` 与 `set_threads` 以构建时的
序号指称监听器，且 `accel_status` 返回借用的切片，所以它们无法在不破坏兼容的前提下在运行时增长。

## 决策

### 监听器 id

1. **`ListenerId`**：不透明、可复制的 id（`ListenerId::get() -> u64`）。交给 builder 的监听器按加入顺序得到 id `0..n`
   （即它们在 `local_addrs` 中的序号）；运行时加入的监听器依次得到后续的 id。同一引擎内 id 从不复用。
2. **`Engine::listeners() -> Vec<ListenerInfo>`**：仍在接受连接的监听器，先是构建时的，再是运行时加入的，每项含 `id`、
   `local_addr`、`threads` 与 `accel`（`AccelStatus`）。UDP 与数据报监听器也会列出（`udp: true`），使 id 与 `local_addrs`
   对齐，但只有 TCP 监听器可以移除或设置过滤器。
3. 基于序号的方法仍然只覆盖 builder 建出的内容（监听器，然后是客户端组），行为不变：被移除的构建时监听器仍留在
   `local_addrs` / `threads` 中（序号稳定，随着线程退出其线程数降为 0）。运行时监听器只能通过 id 访问：
   `Engine::set_listener_threads(id, n)` 就是按 id 的 `set_threads`（适用于任何 TCP 监听器）。

### 增加

4. **`Engine::add_listener(Listener) -> io::Result<ListenerId>`** 用与 `build` 相同的代码绑定 TCP 监听器：它的后端
   （epoll / kqueue / io_uring，含 io_uring 的回退和 `strict`）、构建时读取一次的 `AKIO_DEFAULT_BACKEND`（ADR-029）、
   线程数（Linux 上每线程一个 `SO_REUSEPORT` socket，其他系统共享一个 socket）、继承来的 socket（`Listener::tcp_from_std`）、
   `Accel::Ebpf` 分流（strict 或降级，在 `ListenerInfo::accel` 中报告）、引擎的 `Config` 与实时设置、线程池与遥测，
   以及引擎做线程放置时的 NUMA 放置（`NumaReport` 仍只描述构建时）。引擎已启动时新线程立即启动；在 `start` 之前加入的则由
   `start` 启动。绑定错误由调用返回，与 `build` 一样。
5. 拒绝：UDP 与数据报监听器（`InvalidInput`：运行时的 UDP API 是 `bind_udp`）、DPDK 监听器（`Unsupported`：其 I/O 线程按
   设备共享）、没有 `serve` 的监听器（`InvalidInput`）、`shutdown` 之后（`NotConnected`），以及超过下面的上限。
6. **上限**（规则 10）：`EngineBuilder::max_listeners(n)`，默认 1024，计入正在接受连接的监听器（任何类型），加上已移除但线程仍在
   服务连接的监听器（它们占着线程）。超过上限时 `add_listener` 以 `io::ErrorKind::QuotaExceeded` 失败。构建时的监听器计入，
   但上限不约束 builder 本身。

### 移除与排空

7. **`Engine::remove_listener(id)`**：监听器停止接受连接，其监听 socket 被关闭；它已打开的连接不受影响地继续运行在拥有它们
   的线程上（连接从不迁移，ADR-001）。每个 I/O 线程在最后一个连接关闭后退出。
8. **`Engine::shutdown_listener(id, drain: Duration)`**：同上，并且监听器的每个打开连接立即收到 `Acceptor::on_shutdown`
   （与引擎关闭时相同：HTTP 服务器发送 `Connection: close` / GOAWAY），`drain` 之后仍打开的连接被关闭（`on_close` 会运行）。
   `Duration::ZERO` 在下一次循环迭代时关闭它们。
9. 两者在该监听器的每个 I/O 线程都处理完命令后返回，对忙碌的线程最多等待一秒（`Group::await_unlisted`，调用时已释放引擎
   的锁；在 I/O 线程上调用时不等待，规则 1）。线程关闭其监听 socket（epoll / kqueue）；在 io_uring 上则先用
   `shutdown(SHUT_RD)` 让它停止监听，因为其 multishot accept 在取消完成前一直持有该 socket，而期间仍在监听的
   `SO_REUSEPORT` socket 会分走一部分新连接，并在关闭时重置它们。内核已排队但尚未 accept 的连接会被重置，与关闭任何监听
   socket 时一样。要无间隙地替换监听器，先加入新的：在 Linux 上两者共享端口（`SO_REUSEPORT`），直到旧的被移除；移除返回
   之后，新连接只会到达新的监听器。移除后再次绑定同一地址，在旧 socket 关闭后（一次循环迭代之内）即可成功。最初的
   版本在命令投递后即返回，且 io_uring 在取消完成前一直让旧 socket 处于监听：akit 的 reload 在同一地址替换监听器时，在
   io_uring 上约四次运行中有一次首个请求被重置（epoll 上较少）。
10. 被移除的监听器若其线程同时服务 `dial` / `adopt_tcp`（没有 `client_threads` 时 builder 的最后一个 TCP 监听器），这些
    线程会为它们一直保留到引擎关闭；对它调用 `shutdown_listener` 也会排空拨出的连接，因为它们运行在同样的线程上。会增删
    监听器的应用应设置 `client_threads`。
11. 错误：未知或已移除的 id 返回 `NotFound`，UDP / 数据报 / DPDK 监听器返回 `Unsupported`。被移除监听器的组在其线程退出后
    被 join（在下一次监听器相关调用时，以及 `wait` 中），它们的每线程计数器离开 `Metrics::loops`；其累计值保留在
    `Metrics::total` 中，因此总数永不回退。
12. `Engine::wait` 阻塞到 `shutdown` 被调用且所有线程（包括运行时加入的监听器的线程）都已退出；一个完全没有监听器的引擎
    （打算在运行时再加入）现在也会等待 `shutdown`，而不是立即返回。

### accept 过滤器

13. **`Listener::filter(Fn(&SocketAddr) -> bool + Send + Sync + 'static)`**：在 `accept` 之后立即在 I/O 线程上以对端地址
    调用，早于 `max_connections` 检查、acceptor 的 `on_open` 以及任何传输层（TLS）工作；返回 `false` 则立即关闭该流。
    过滤器 panic 时拒绝该连接（并记录日志）。被拒绝的连接按线程计入新计数器 `LoopCounters::filtered`
    （`akio_connections_filtered_total`），不计入 accepted。
14. **`Engine::set_listener_filter(id, f)`** / **`clear_listener_filter(id)`** 在运行时替换过滤器，调用返回后开始的每次
    `accept` 都使用新过滤器（拒绝立即在所有线程上生效）。组把过滤器放在一个带代数计数器的单元中，在锁内替换；每个线程保留
    自己的副本，每次 accept 读取一次代数（对一个很少写入的缓存行的一次原子读），仅在代数变化时取新过滤器。`set_threads`
    新建的线程共享该单元。第一版把过滤器作为循环命令投递给各线程：线程在同一批事件中同时收到命令和新连接时，会先用旧过滤器
    接受该连接（事件先于命令处理），Linux 上的测试发现了这一点。
15. 适用于 epoll、kqueue 与 io_uring 上的 TCP 监听器。UDP 或数据报监听器上的 `filter` 使 `build` / `add_listener` 以
    `InvalidInput` 失败，DPDK 监听器上以 `Unsupported` 失败。

### 后端

16. `akio_core::Group` 增加 `stop_listening(drain: Option<Duration>, exit_when_idle)`、`set_filter`、`finished` 与
    `loop_stats`（隐藏，默认 `Unsupported` / 空操作），以及隐藏的 `FilterCell` / `FilterView`；epoll / kqueue 与
    io_uring 组用循环命令 `StopListening` 和共享的过滤器单元实现它们。已停止监听的循环会丢弃之后才交给它的监听 socket（正在进行的 `set_threads` 交接）。在 io_uring 上
    multishot accept 被取消；在取消完成前它仍交付的连接会被服务（排空时，与引擎关闭一样，在其首批数据之后关闭）。

## 影响

- `akio` 的增量 API：`ListenerId`、`ListenerInfo`、`Engine::{add_listener, remove_listener, shutdown_listener, listeners,
  set_listener_threads, set_listener_filter, clear_listener_filter}`、`EngineBuilder::max_listeners`、`Listener::filter`；
  `akio-core` 中的计数器 `filtered`，以及隐藏的 `Group` 方法、`AcceptFilter`、`FilterCell` 与 `FilterView`；隐藏的 `Telemetry::unregister_loops`。
- 读写路径不变。accept 多一个分支，在监听器组上多一次原子读。
- 没有监听器的引擎上的 `wait` 会阻塞到 `shutdown`（之前立即返回）。

未做：运行时的 UDP 与数据报监听器（用 `bind_udp`）；移除 DPDK 后端的监听器；UDP 对端的过滤器。

## 验证

- `tests/runtime_listeners.rs`（akio），在 epoll 与 kqueue 上，以及以 `AKIO_TEST_BACKEND=uring` 在 io_uring 上：在引擎
  运行中与启动前加入监听器，同时其他监听器上有流量；在流量下移除，已打开的连接继续回显而新连接被拒绝，连接关闭后线程退出；
  `shutdown_listener` 调用 `on_shutdown`，并在排空截止时（而非之前）关闭剩余连接；被移除监听器的端口可以再次绑定；
  `max_listeners` 在上限之下、恰好、之上，以及计入仍在排空的已移除监听器；id、`listeners()`、未知 id；运行时监听器上的
  `set_listener_threads`；在同一地址上替换监听器 50 次，每次移除后立即发起的连接都必须得到服务（Linux）。
- 过滤器按地址拒绝与接受，在流量下于运行时替换和清除，`filtered` 计数器，panic 的过滤器，UDP 监听器上的过滤器被拒绝。
- 工作区测试套件：macOS、Docker 中的 Linux arm64（epoll 与 io_uring）以及 x86_64（gpu51）。
