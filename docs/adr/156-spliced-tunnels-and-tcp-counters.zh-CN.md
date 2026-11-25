# ADR-156：拼接隧道与连接的 TCP 计数器

[English](156-spliced-tunnels-and-tcp-counters.md) | 简体中文

状态：已采纳（2026-11-26）。扩展 [ADR-027](027-ebpf-xdp-pinning-socks-splice.zh-CN.md)；应 akit
请求（A170）。

## 背景

ADR-027 为 akio-socks 的 `CONNECT` 隧道提供了内核快速路径：sockmap `Relay`、一个回调中先于被中继
字节写出 SOCKS 应答的拼接（`splice_inner_with`），以及 `byte_counts(&TcpStream)`——socks 用它维持
空闲超时，并且只在另一侧的数据到达后才关闭一侧（私有的 `SpliceCtl`，带自己的 drain 线程）。

akit 以同样方式拼接其 `tcp` 服务，只能通过文档隐藏的 `Conn::inner` 拿到 socket，复制 socks 的 drain
机制，并统计用户态从客户端读走的字节，以确定内核从哪里开始中继。akio-mux 的 `ProxyProtocol` 读取的
PROXY 头被消费却不报告长度，因此 akit 让这类连接留在用户态中继。

## 决定

1. **连接的计数器。** akio-ebpf 中的 `conn_byte_counts(&Conn<H>)` 与 `inner_byte_counts(&ConnInner)`
   （计数器是 Linux 套接字选项，akio-ebpf 本来就在读取）。`ByteCounts`（`#[non_exhaustive]`）新增
   `unread`（`SIOCINQ`）与 `consumed()`（`received - unread`）：用户态读走的字节，不论哪一层读的，
   因此代理无需自己计数。`TCP_INFO`、`SIOCINQ`、`SIOCOUTQ` 是三次调用；会重读（最多八次），直到两次
   `ioctl` 前后的 `TCP_INFO` 一致。内核把 FIN 计为一个字节：当 `tcpi_state` 表明已收到对端 FIN
   （`CLOSE_WAIT`、`LAST_ACK`、`CLOSING`、`TIME_WAIT`）时 `received` 不计它，当本端 FIN 已被确认
   （`FIN_WAIT2`、`TIME_WAIT`）时 `written` 不计它，因此 drain 不会等待一个永远不会到来的字节。
   拨出的 socket 的 SYN 仍计入 `written`（无法区分拨出与接受的 socket）：`written` 只与同一 socket
   的 `written` 比较，基准运算正是如此。在 7.0 上观察到并写入了顺序约定：内核会从段首开始中继一个
   被部分读取的段的剩余部分，因此拼接必须在用户态读完已到达的全部数据或一点都未读时进行。
2. **连接间的每次拼接都带基准计数器。** `RelayInner::splice` 在闸门（`SO_RCVLOWAT`）拦住 verdict 时
   读取：每个 socket 的 `consumed` 在进入 map 之前读取（socket 有了 psock 之后，`tcp_bpf_ioctl` 可能
   用 psock 的队列回答 `SIOCINQ`），`received` / `written` 在 `before_relaying` 写出之后读取。基准中
   的 `unread` 为 `received - consumed`。`Splice::base() -> Option<[ByteCounts; 2]>`：连接一定为
   `Some`（读取失败则拼接失败并撤销），原始 fd 尽力而为。
3. **无需回调的首写。** `splice_conns_with(&Conn<A>, &Conn<B>, first)`（以及 `splice_inner_first`）
   在闸门内把 `first` 写入 `b` 的非阻塞 socket。写不完则拼接失败（`WouldBlock`）并撤销；
   `SpliceError { error, written }` 告诉调用方还需经引擎发送什么。
4. **公开的 `Tunnel`。** socks 的 `SpliceCtl` 变为 `akio_ebpf::Tunnel`（`Relay::tunnel`、
   `tunnel_inner`）：`base`、`counts`、`relayed_from`、`activity`、`moved`、
   `close_after_forward(TunnelSide, stall)` 与 `late_payload`。它以 `Weak<ConnInner>` 持有连接（经由
   持有隧道的 handler 不会形成环）。drain 运行在进程唯一的 `akio-ebpf-drain` 线程上，有等待项时每
   毫秒轮询一次；轮询时不持有列表锁，因此添加 drain 的 I/O 线程不会等待轮询。每个隧道每侧最多添加
   一个 drain。一侧的 drain 目标为 `base(to).written + received(from) - base(from).consumed()`，也计入
   拼接时还在 `from` 接收队列里的字节（socks 旧的目标没有）。akio-socks 只保留自己的部分（持有客户端
   早到字节时拒绝拼接、它的计数器）。
5. **PROXY 头的长度。** `ProxyHeader` 新增私有的 `wire_len`，由 `parse` 设置（因而 `ProxyProtocol`
   附加的头也有），通过 `wire_len() -> Option<usize>` 读取。头长度无法由字段重新算出：`LOCAL` 块、
   `UNKNOWN` 行与填充都会被丢弃。用私有字段而不是第二个附加值，使 `Conn::attachment::<ProxyHeader>()`
   保持可用；相等比较与哈希忽略该字段。akio-mux 之外的结构体字面量不再能编译（预发布版本的变更，见
   `docs/api-stability.zh-CN.md`）；用 `proxy` 与 `local` 构造头。

## 影响

- akit 不再使用 `Conn::inner` 和它复制的 drain：`Relay::tunnel` 取代 `sockmap::splice`，
  `Tunnel::moved` 取代其探测，`close_after_forward` 取代其 `Drain`；带 `proxy_protocol` 的 listener 的
  连接也可以拼接（基准计入了头）。
- 计数器与隧道和中继一样仅限 Linux：其他平台报告 `Unsupported`，无法创建隧道。
- 有 drain 等待时 drain 线程每 1 ms 轮询一次，否则在条件变量上休眠。
