# ADR-178：UDP 监听器、绑定的套接字和 QUIC 服务端的接入过滤器

[English](178-udp-accept-filter.md) | 简体中文

状态：已采纳（2026-11-26）。akit 的 A220。

## 背景

ADR-099 给 TCP 监听器加了接入过滤器：`Listener::filter`，一个 `Fn(&SocketAddr) -> bool`，在 `accept`
之后立即调用，引擎运行时用 `Engine::set_listener_filter` 替换。akit 的访问控制列表（客户端地址的允许和
拒绝列表，其决定 034）建立在它之上，每次重载都替换过滤器而不重新绑定。UDP 没有对应的东西：在 UDP 或
数据报监听器上 `Listener::filter` 让构建以 `InvalidInput` 失败，`set_listener_filter` 答 `Unsupported`。

于是 akit 无法像 fit 那样（fib 的 `Binding.Filter`），在为被拒绝的客户端建立会话或 QUIC 连接之前丢弃它的
数据报。被拒绝的 HTTP/3 客户端要先完成整个 QUIC 握手（它发的每个 Initial 都要做 TLS 计算），请求才被以
403 应答；被拒绝的 `udp` 客户端的每个数据报都会打开一个按对端区分的连接，再被 akit 立即关闭。akit 运行时
增加的 UDP 监听器是 `Engine::bind_udp` 的套接字，同样没有过滤器。

## 决定

1. **UDP 监听器上的 `Listener::filter`。** 在按对端区分的 UDP 监听器（`Listener::udp(..).serve`）上，
   对来自尚无连接的对端的每个数据报，在 I/O 线程上、在 `udp_max_peers` 检查和 acceptor 的 `on_open`
   之前询问过滤器：`false` 丢弃该数据报。被拒绝的对端不留任何记录，它的下一个数据报会再次询问：替换后的
   过滤器立即生效，也没有东西随被拒绝的对端增长（fit 在 I195 上的决定 7）。已经有连接的对端不再询问，
   正如替换前已接受的 TCP 连接不再检查。按对端区分的 UDP 循环无论监听器要求哪种后端或调度方式，都是
   epoll / kqueue 的那个，过滤器在那里同样有效。
2. **数据报监听器**（`serve_datagrams`，ADR-065）不保存对端，因此每个数据报都询问：被拒绝的在生成
   handler 的批次之前丢弃（epoll、kqueue 和 io_uring 共用的 `DatagramPort`），不计入接收数。每个接收批次
   读一次过滤器视图（一次原子读），再对每个数据报调用过滤器。
3. **计数**在 `LoopCounters::filtered`（`akio_connections_filtered_total`）：在 UDP 上，每个因过滤器拒绝
   其对端而丢弃的数据报计一次。panic 的过滤器视为拒绝，与 TCP 相同。
4. **运行时替换**：`Engine::set_listener_filter` / `clear_listener_filter` 对 UDP 和数据报监听器有效，
   沿用 ADR-099 的单元（代数计数器，在锁下替换过滤器，每个循环保留自己的视图）：对调用返回之后收到的
   每个数据报生效。只有 DPDK 监听器仍答 `Unsupported`（带过滤器时 `build` 失败）。
5. **绑定的套接字。** `Engine::bind_udp_filtered(addr, acceptor, filter)` 绑定时过滤器从套接字的第一个
   数据报起就生效（单元在循环得知该套接字之前就已填好）。epoll / kqueue UDP 组生成的每个 `UdpBinding`
   都带有自己的单元：`UdpBinding::set_filter` / `clear_filter` 替换它（在 `bind_udp` 返回之后才设置的
   过滤器，管不到此前到达的数据报）。组的 trait 新增 `Group::bind_udp_filtered`，默认实现拒绝过滤器
   （`Unsupported`）；对没有单元的绑定调用 `UdpBinding::set_filter` 也答 `Unsupported`。
   `Engine::set_listener_filter` 管不到绑定：它们没有监听器 id。
6. **QUIC 连接再询问一次。** 一个 UDP 对端的连接可以承载多个 QUIC 连接（从同一端口重连的客户端），
   对端建立之后替换的过滤器必须对新的连接生效。UDP 连接保存它所来自的监听器或绑定套接字的单元
   （akio-core 的 `Sock::Udp`，一个指针），新增的 `Conn::filter_allows(peer)` 询问它（只有在曾经装过
   过滤器之后才取单元的锁），并把拒绝计入 `filtered`。akio-quic 的服务端在 Initial 包将要建立新连接时
   询问它，在 `max_connections` 检查、令牌检查和任何 TLS 计算之前（`Endpoint::handle_gated`）：被拒绝
   时丢弃该数据报，不保留任何东西，也不发送任何东西（不发 Retry，也不发 CONNECTION_REFUSED，否则就等于
   告诉被拒绝的客户端服务端在那里）。发往已有连接的数据报（包括迁移）不询问。akio-h3 通过 `QuicServer`
   提供服务，所以 HTTP/3 监听器同样适用。

## 影响

- 新增 API：`Engine::bind_udp_filtered`、`UdpBinding::set_filter` / `clear_filter`、`Conn::filter_allows`；
  `Listener::filter` 和 `Engine::{set,clear}_listener_filter` 接受 UDP 和数据报监听器。隐藏的、面向后端的：
  `Group::bind_udp_filtered`、`UdpBinding::with_filter_cell`、`DatagramPort::with_filter`、
  `FilterCell::allows`、`FilterView::{current, check, cell}`，以及 `ConnInner::new_udp` 的 `filter` 参数。
- 以前在 UDP 监听器上设置过滤器会让构建失败；现在带着过滤器运行。
- 没有过滤器时的开销：每个新 UDP 对端一次原子读；数据报监听器每个批次一次原子读；每个新 QUIC 连接一次
  原子读。有过滤器时：每个新对端调用一次过滤器，数据报监听器上每个数据报调用一次，每个新 QUIC 连接取一次
  锁以拿到过滤器。已知对端的读路径不变。每个 UDP 连接大一个指针。
- akit 可以把 TCP 端的访问策略装到 UDP 端，去掉按请求的 HTTP/3 检查和 `udp` 会话的检查。

未做：DPDK 的 UDP 监听器（没有过滤器，与 TCP 相同）。

## 验证

- `crates/akio/tests/udp_filter.rs`：UDP 监听器拒绝一个对端（丢弃，按数据报计数，不保留对端，之后再允许），
  在运行的监听器上替换和清除过滤器（已知对端保留），被拒绝的对端不占 `udp_max_peers` 的名额（刚好低于、
  等于和超过上限），panic 的过滤器，要求工作窃取的 UDP 监听器，从第一个数据报起就过滤、经 `UdpBinding`
  替换的绑定套接字，之后才加过滤器的普通绑定，以及在被测后端上的数据报监听器（`AKIO_TEST_BACKEND=uring`
  时为 io_uring）。
- `crates/akio-quic/tests/filter.rs`：被拒绝的 QUIC 客户端得不到连接，也收不到任何回应，直到过滤器被替换；
  来自服务端已有的 UDP 对端的新 QUIC 连接，被再次询问的过滤器拒绝，替换之后得到服务；绑定套接字上的
  QUIC 服务端。
- `crates/akio/tests/runtime_listeners.rs` 不再预期 UDP 过滤器被拒绝。
- macOS（kqueue）和 gpu51（epoll，以及 `AKIO_TEST_BACKEND=uring` 的 io_uring）上的整个工作区测试。
