# ADR-068：用户态协议栈的 IPv6 自动配置、Accurate ECN，以及 AF_XDP 共享 UMEM / 多缓冲帧

[English](068-userspace-stack-slaac-accecn-af-xdp-multibuffer.md) | 简体中文

状态：已采纳（2026-11-21）

## 背景

ADR-026（IPv6）与 ADR-063（AF_XDP）之后，only-dpdk 自研的 TCP/IP 栈（`only-dpdk/src/net`）
还留着三组缺口：

- **IPv6 地址只能静态配置。** 必须给出 `DpdkConfig::address6` 与 `gateway6`；路由器通告被忽略；
  栈会回应其他节点的重复地址检测（DAD）探测，但从不探测自己的地址，地址冲突时照用不误。
- **ECN 反馈只有 RFC 3168。** 每个往返一个 ECE 位，只说明“有标记”，不说明“有多少”。
  Accurate ECN（RFC 9768，AccECN）在每个 ACK 上报告 CE 标记的包数，并用一个选项报告各码点的
  字节数。Linux 从 6.18 起实现（`net.ipv4.tcp_ecn = 3`）。
- **AF_XDP 每个队列一个 UMEM、每帧一个 chunk。** 每个队列各自注册并锁定一块 UMEM；一帧必须
  放进一个 4 KiB chunk（MTU 最大 3826），因此用不了巨帧。

## 决定

### 1. SLAAC、路由器通告与 DAD（按需开启）

- `DpdkConfig::ipv6_slaac`（默认 `false`）即使没有 `address6` 也会打开 IPv6。栈发送至多三次
  路由器请求（RFC 4861 第 10 节：间隔 4 秒，首次前随机延迟至多 1 秒），并从每个合法的路由器
  通告（链路本地源地址、跳数限制 255、选项长度非零）中取得：
  - 默认路由器（按其生存期；至多 4 个，静态 `gateway6` 优先）；
  - 链路上前缀（L 标志；至多 16 个，按有效生存期）；
  - 每个自治 /64 前缀（A 标志）一个地址：前缀加上 MAC 的修改型 EUI-64 接口标识（与链路本地
    地址相同的标识；至多 8 个地址），按 RFC 4862 5.5.3 的首选与有效生存期，包括防止通告把有效
    生存期截短的“两小时”规则。过了首选生存期，地址被弃用（保留，但不再被选为源地址）；
    过了有效生存期则移除；
  - MTU 选项（1280 到设备 MTU 之间：IPv6 包与新 IPv6 连接的 MSS 随之调整）与跳数限制。
  对全局目的地址，源地址选择取与之最长前缀匹配的可用全局地址，首选地址优先于已弃用地址。
- `DpdkConfig::ipv6_dad`（默认 `false`）在每个地址使用前执行 DAD（RFC 4862 5.4）：链路本地
  与静态地址在启动时（随机延迟之后），SLAAC 地址在生成时。一次探测
  （`DupAddrDetectTransmits = 1`），等待一秒（`RetransTimer`）。暂定地址不作源地址，发往它的
  包被丢弃；会加入它的请求节点组（链路本地地址仍暂定时 MLD 报告从 `::` 发出）。收到针对它的
  通告，或其他节点对它的探测，即判为重复。探测带 RFC 7527 的 nonce，链路回送的自身探测不会被
  当作冲突。重复地址永不使用；链路本地地址重复则关闭该设备的 IPv6（RFC 4862 5.4.5）。
- 多队列设备：各队列的栈走同一时间线，都能看到路由器通告（像邻居请求与通告一样复制到每个
  队列），但只有队列 0 发送请求、探测与 MLD 报告。
- `only_dpdk::ipv6_addresses(&Device)` 报告当前可用的地址（由队列 0 维护）。
- 不开 `ipv6_slaac` 时通告照旧被忽略；不开 `ipv6_dad` 时地址照旧立即可用。两者默认关闭，
  因为默认值不能改变已有配置的行为（DAD 还会让地址的首次使用推迟约一秒）。
- 接口标识用 EUI-64，而不是 RFC 7217 的稳定隐私标识（RFC 8064）。后者需要配置一个各队列共享
  的稳定密钥；EUI-64 不需要任何配置，与链路本地地址一致，对端也能算出地址。因此重复的 SLAAC
  地址会被放弃，而不是换一个标识重试。

### 2. Accurate ECN（按需开启）

`DpdkConfig::tcp_accecn`（默认 `false`）在用户态 TCP 中实现 RFC 9768：

- 协商：SYN 带 AE、CWR、ECE；SYN-ACK 反馈 SYN 的 IP-ECN 字段（表 2）并带 AccECN 选项；客户端的
  第一个 ACK 以握手编码（表 3）反馈 SYN-ACK 的 IP-ECN 字段，且单独用一个纯 ACK 发送。对端只回
  RFC 3168 ECN 则用 RFC 3168 ECN，不支持 ECN 则不用，“反射型故障”服务器也不用。开了
  `tcp_accecn` 的服务器以 RFC 3168 ECN 回应 RFC 3168 的 SYN。SYN 第一次重传仍请求 AccECN，之后
  不再请求（3.1.4.1）；重传的 SYN-ACK 去掉选项，第二次重传连 AccECN 标志也去掉，此后服务器
  不再发送 ECT（3.1.5、3.2.3.2.2）。SYN cookie 可用：cookie SYN-ACK 反馈 SYN 的 IP-ECN 字段，
  完成握手的 ACK 的 ACE 字段再告知模式（5.1）。
- 接收方：握手后的每个报文段在 ACE 字段中携带 CE 包计数（初值 5），并在计数变化后的每个 ACK
  上用 AccECN 选项携带 ECT(0)、CE、ECT(1) 的字节计数（order 0，截短到曾经变化过的计数，至少
  包含本次变化的；与两个 SACK 块争空间时让位，3.2.3.3）。实现变化触发与增量触发的 ACK
  （3.2.2.5.1）。
- 发送方：解码 ACE 字段（取最小增量），有选项时用其 24 位计数；按附录 A.2 防范丢失的 ACK
  掩盖 ACE 回绕（有选项时用 A.2.2；没有选项时，只在 ACK 通常只覆盖少量报文段时启用，避免把
  拉伸 ACK 当成回绕）。篡改检测：握手包 IP-ECN 字段的非法变化、握手 ACK 上 ACE 为零、选项初始
  计数被清零、两个都带 CE 字节计数的 ACK 之间出现 CE 字节却没有 CE 包（确认 Not-ECT 重传的 ACK
  只带 ACE 增量、不带选项，否则会被误判为篡改）。
- 拥塞响应：新的 CE 标记按 RFC 3168 的 ECE 处理：每个窗口的数据至多减窗一次，不重传。永不设置
  CWR（该位是 ACE 的一部分）。响应不随标记数缩放：那需要可伸缩的拥塞控制（DCTCP / Prague，
  L4S），本栈没有；AccECN 的计数使其成为可能。
- 数据与 RFC 3168 一样以 ECT(0) 发送；控制包与重传保持 Not-ECT。
- `only_dpdk::tcp_ecn_stats()`（`#[doc(hidden)]`）统计 AccECN 与 RFC 3168 连接数、收到的 CE
  标记与拥塞响应次数，供测试与基准使用。

### 3. AF_XDP 共享 UMEM 与多缓冲帧（按需开启）

- `AfXdpConfig::shared_umem`：所有队列共用一个 UMEM（`XDP_SHARED_UMEM`，跨队列需 Linux
  5.10+）。第一个 socket 注册它，其余 socket 带各自的 fill 与 completion 环绑定到它。此时
  `frames` 为总数，平均分配：每个 socket 拥有固定的一段 chunk（内核只会把一个 socket 放进自己
  环上的 chunk 还给它，且每个 socket 都检查所访问的地址在自己的段内），各 I/O 线程之间没有锁。
  后续 socket 沿用第一个的模式（内核拒绝它们再带模式标志）。
- `AfXdpConfig::multi_buffer`：`XDP_USE_SG`（Linux 6.6+）。跨多个描述符（`XDP_PKT_CONTD`）
  收到的帧被重组（至多 64 KiB，更大的丢弃）；大于一个 chunk 的待发帧写入多个 chunk（至多 18 个），
  其描述符一次性发布到 TX 环。重定向程序以 `BPF_F_XDP_HAS_FRAGS` 加载，这也让 veth 在 MTU 超过
  约 3.5 KB 时仍能运行原生 XDP。开启后，AF_XDP 上的 `DpdkConfig::mtu` 可达栈的上限 9000。

### 验证与热路径

- 模拟链路：RS / RA / SLAAC 生存期与两小时规则、MTU 与跳数限制选项、DAD 成功、冲突（通告、
  其他节点的探测、链路本地地址重复）、回送的自身探测、非零队列静默跟随时间线；AccECN 协商矩阵、
  经 CE 标记瓶颈的精确反馈（IPv4 与 IPv6）、ACK 丢失下数百次标记、SYN cookie、SYN 与 SYN-ACK
  重传回退、选项线格式；路由器通告与 DAD 探测的 fuzz 种子，`dpdk_ipv6` / `dpdk_icmpv6` 目标中的
  路由器通告解析，TCP 选项往返中的 AccECN 选项。
- 对 Linux 7.0（gpu51，特权容器内：只改容器网络命名空间的 sysctl）：双向 AccECN，netem 双向打
  CE 标记，从内核 `TCP_INFO` 核对（`tcpi_ecn_mode` 为 AccECN、看到带计数的 AccECN 选项、无失败、
  CE 标记与 CE 字节已被反馈）；来自 radvd 的 SLAAC（MTU 1400 反映到内核的 MSS，经通告的默认路由器
  拨号），内核对我们地址的 DAD 失败、我们对内核地址的 DAD 失败；AF_XDP 两队列共享 UMEM 与巨帧
  （MTU 9000，原生与通用 XDP）。
- IPv4 路径保持单态：IPv6 自动配置只在 IPv6 代码与定时器中；AccECN 为每个 AccECN 连接增加一份
  装箱状态，并在 RFC 3168 ECN 已有分支处多一个分支。gpu51 上 `stack-bench` 的同轮 A/B 见
  docs/BENCHMARKS.md。

## 影响

- 在有路由器的 IPv6 网络上无需静态 IPv6 配置；地址冲突会被检测到，而不是悄悄弄坏两台主机。
- 有了 AccECN，对端能知道拥塞有多少，而不只是有没有；本栈的反应仍与 RFC 3168 相同。
- AF_XDP 上可用巨帧；各队列可共用一块锁定内存。

## 未做

- epoll / io_uring 内核栈后端上的 AF_XDP：设计不同（内核 TCP 下面不可能接 AF_XDP socket，只能
  是这些后端的 UDP 走 AF_XDP），需要单独的 ADR。
- mbuf 或 AF_XDP 元数据中的校验和 / TSO / LRO 卸载：这里没有网卡可以验证。
- RFC 7217 稳定隐私标识与 RFC 8981 临时地址；DHCPv6（忽略 “M” 与 “O” 标志）；路由信息选项
  （RFC 4191）；路由器优先级。
- SYN、纯 ACK 或重传上的 ECT（RFC 8311 实验），以及利用 AccECN 计数的可伸缩拥塞控制（L4S）。
- 在真实网卡上测量零拷贝 AF_XDP（veth 不支持）。
