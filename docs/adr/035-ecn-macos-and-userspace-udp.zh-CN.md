# ADR-035：macOS 上与用户态协议栈 UDP 上的 ECN

[English](035-ecn-macos-and-userspace-udp.md) | 简体中文

状态：已接受（2026-11-18）

## 背景

`akio-quic` 已实现 ECN（RFC 9000 第 13.4 节、RFC 9002 第 7.1 节）：发送的包标记 ECT(0)、
ACK_ECN 计数、十个包的测试期、校验对端计数并在失败时回退、把 CE 标记当作拥塞事件。兼容版本协商
（RFC 9368，在一次握手内从 v1 切换到 v2，ADR-013 与 ADR-014）同样已完成。该 crate 的 README
仍把两者列为缺口；真正缺的是 Linux 以外 QUIC 之下传递码点的那一层：

- **macOS**：kqueue 的 UDP 循环用 `recv_from` 接收、`send_to` 发送，码点既发不出去也收不进来，
  `akio-quic` 在那里根本不尝试 ECN。
- **用户态协议栈**（`akio-dpdk`）：其 UDP 构造的每个 IP 头 TOS 都为 0，并丢弃收到的包的码点；
  `Conn::send_segments_ecn` 对虚拟套接字也丢弃码点。在 Linux 上经它运行的 QUIC 连接会尝试
  ECN，校验失败后回退。

## 决定

1. **akio-sys，macOS**（新模块 `udp_mac`）：`enable_ecn`（`IP_RECVTOS` 与
   `IPV6_RECVTCLASS`）、`ecn_available`（与 Linux 一样，`AKIO_UDP_ECN=0` 将其关闭）、
   `recv_from_ecn`（一次 `recvmsg`，码点取自 `IP_RECVTOS` / `IP_TOS` 字节或 `IPV6_TCLASS`
   int）与 `send_to_ecn`（一次 `sendmsg`，带一个 `IP_TOS` / `IPV6_TCLASS` int 控制消息；
   IPv6 套接字经 IPv4 映射地址到达 IPv4 对端）。含义相同的函数与 Linux 同名。控制数据按普通
   字节构造与解析，以 `msg_controllen` 为界：只有 `recvmsg`、`sendmsg`、`setsockopt` 与两个
   清零的 `sockaddr_storage` 是 `unsafe`（5 个块；`msghdr` 与 `cmsghdr` 在布局测试中与 `libc`
   对照）。XNU 在 IPv4、IPv6 与双栈套接字上都遵从逐消息的码点（已在回环上测试）。
2. **macOS 上的 akio-epoll** 在服务端与拨号套接字上用 `recv_from_ecn` 接收（以 `recvmsg`
   代替 `recvfrom`：每个数据报仍是一次系统调用），并在每个 UDP 套接字上开启 `IP_RECVTOS`。
   **macOS 上的 akio-core** 用 `send_to_ecn` 发送带码点的数据报；不带标记的数据报仍用
   `send_to` / `send` 发出。
3. **akio-dpdk**：`Iface::udp_send_ecn` 把码点写入 IPv4 TOS / IPv6 traffic class；收到的
   数据报保留其 IP 头的码点（重组时取最后一个分片的），与内核循环一样通过 `Conn::rx_ecn` 报告。
   akio-core 新增隐藏的 `ConnInner::drain_output_ecn`（循环连同码点取出数据报），并对任何数据报
   套接字（内核或虚拟）保留码点。
4. **akio-quic** 在 Linux 与 macOS 上尝试 ECN（`AKIO_UDP_ECN=0` 仍可关闭）；经 akio-dpdk 时
   码点现在能到达，路径传递码点时校验即可通过。协议逻辑没有任何改动。
5. `quic_conn` 模糊测试目标增加一种由输入选择的路径模式（保留、漂白、标记 CE、改标 ECT(1)），
   作用于这对连接交换的每个数据报，外加一个码点由输入决定的数据报。此前这对连接收到的数据报
   全都不带标记，模糊测试从未触及 ECN 校验与 CE 响应。

## 后果

- 公共 API：`akio-sys` 仅在 macOS 上新增的函数（不在 Linux 的 API 快照中）；其余均为隐藏
  （`akio-core` 的 `ConnInner`）或 crate 私有（akio-dpdk 的 `Iface`）。快照无变化。
- macOS 上的 QUIC 连接在回环及传递码点的路径上通过 ECN 校验，对端为 akio-quic 或 quic-go
  （`tools/interop/quic/run.sh` 现在在 macOS 上也检查 ECN）；在漂白或丢弃标记的路径上沿用已有
  的回退（最多损失一个 PTO）。
- macOS 上带标记的数据报是一次带 16 字节控制消息的 `sendmsg`，不带标记的仍是一次 `sendto`：
  没有批量（macOS 没有 `sendmmsg`），没有分配。
- 未做：其他 Unix 系统上的 ECN（那里没有后端）；akio-dpdk 中 RFC 3168 第 5.3 节的重组规则
  （任一分片为 CE 则整体为 CE），目前保留最后一个分片的码点（QUIC 从不分片）；Accurate ECN / L4S。
