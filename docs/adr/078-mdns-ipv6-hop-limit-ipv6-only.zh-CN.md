# ADR-078：IPv6 上的 mDNS：跳数限制 255、纯 IPv6 链路、与 Chrome、avahi 和 mDNSResponder 互通

[English](078-mdns-ipv6-hop-limit-ipv6-only.md) | 简体中文

状态：已采纳（2026-11-22）

## 背景

ADR-044 经 IPv4（`224.0.0.251`）解析并隐藏 `<uuid>.local` ICE 候选，留下“IPv6 组播上的 mDNS”未做。
ADR-054（2026-11-20）补上了它：第二个 `[::]:5353` 套接字在每个有链路本地地址的接口上加入 `ff02::fb`
（`Engine::bind_udp_multicast_on`），按链路查询，在查询所来的链路上应答，AAAA 记录，并记住远端链路本地
地址的作用域 ID。ADR-044 的“未完成”一行一直没有更新；检查 ADR-054 留下的部分，发现三处缺口：

- **跳数限制。** RFC 6762 §11 要求每个 mDNS 应答的 IP TTL / 跳数限制为 255，以照顾在接收时检查它的
  查询方（2004 年草案的实现；设置了 `check-response-ttl=yes` 的 avahi）。引擎把 IPv4 组播 TTL 设为
  255，IPv6 组播却以内核默认跳数限制 1 发出：std 没有 `set_multicast_hops_v6`，而 `akio` 禁止 unsafe
  代码。
- **纯 IPv6 链路。** `conceal_host_candidates` 要求 IPv4 套接字绑在共享端口上。在没有 IPv4 的链路上
  （`224.0.0.251` 无路由），该套接字退回到临时端口，于是即使 IPv6 套接字占着 5353、能够应答，隐藏也
  会失败。
- **互通。** ADR-054 的 IPv6 测试只在我方套接字之间进行；没有浏览器或其他应答器经 `ff02::fb` 解析或
  应答过，也没有测试在纯 IPv6 链路上运行。

## 决策

1. **akio-sys：`set_multicast_hops_v6(&UdpSocket, u32)` 与 `multicast_hops_v6(&UdpSocket)`**
   （`IPV6_MULTICAST_HOPS`，Linux 与 macOS；大于 255 的值在系统调用之前以 `InvalidInput` 拒绝）。新增
   的公开 API。
2. **akio：带 IPv6 组的 `Engine::bind_udp_multicast_on`** 把跳数限制设为 255 并打开组播回环，与 IPv4
   路径设置 TTL 255 一致（IPv4 路径现在也显式打开回环）。接口仍按数据报选择：目的地址的作用域 ID
   （`ff02::fb%<index>`）决定链路，这正是 `IPV6_MULTICAST_IF` 按套接字所做的事。UDP 客户端线程在任何
   后端上都是 epoll / kqueue，所以在 `AKIO_TEST_BACKEND=uring` 下这条路径不变。
3. **akio-webrtc：由持有共享端口的那个地址族应答名字。** IPv4 *或* IPv6 套接字绑在 5353 上时，
   `conceal_host_candidates` 即成功；在纯 IPv6 链路上，被隐藏的 IPv4 与 IPv6 地址都经 `ff02::fb` 应答
   （A 与 AAAA 记录）。解析出名字的 debug 日志现在注明应答的来源（`mdns: <name> is [...] (from <addr>)`），
   从日志即可看出它经哪个地址族到达。
4. 不变并经确认：每条消息一个问题（A 与 AAAA 查询分开，Chromium 的应答器需要这样）、两个地址族都发查询、
   与系统应答器共享端口（`SO_REUSEADDR` / `SO_REUSEPORT`）、缓存（按 TTL，最多 2 分钟、256 个名字）与
   超时和 IPv4 一样；套接字由引擎 I/O 线程服务，接口扫描在调用方线程上的 `resolve_mdns` 中进行。

未完成：单播应答（发给设置了 QU 位的查询方，以及传统单播回复）使用系统的单播 TTL / 跳数限制，而不是
255；本项目的查询方在共享端口上从不设置 QU，浏览器也不设置。

## 后果

- akio-sys 新增公开 API（两个函数）；`akio` 与 `akio-webrtc` 的签名不变。
- 纯 IPv6 网络上的 mDNS 应答方可以隐藏地址；此前 `conceal_host_candidates` 在那里返回错误。
- 带 IPv6 组的 `bind_udp_multicast_on` 对任何协议都以跳数限制 255 发送，就像 IPv4 路径一直以 TTL 255
  发送一样。

## 验证

- 单元测试：akio-sys 的 `multicast_hops_v6_round_trip`（默认 1；设置 255 与 0 并读回；拒绝 256 且值
  不变）。引擎的组播测试（`crates/akio/tests/shared_ports.rs`）在主机没有 IPv4 组播时跳过其 IPv4 部分，
  而不是失败。
- **纯 IPv6 链路**（`tools/interop/webrtc/mdns6.sh`，gpu51 上的 Docker）：一个没有 IPv4 网络的容器
  （`--network none`；`224.0.0.251` 无路由），一对带链路本地与 ULA 地址的 veth。akio-webrtc 的 mDNS
  测试在其中运行，epoll 与 `AKIO_TEST_BACKEND=uring` 各 6/6，无一跳过（两个隐藏地址的 IPv4 端点经
  `ff02::fb` 上应答的 A 记录互相解析，在第 3 项之前会失败）；引擎组播测试 4/4（IPv4 部分跳过）。
- **avahi 0.8**（同一容器，`use-ipv4=no`，在 veth 的一端，`check-response-ttl=yes`）：`avahi-resolve -6`
  解析出 `Endpoint` 用来隐藏 `fd00:6::1` 的名字；`Endpoint` 解析一个只有 avahi 发布的名字
  （`avahi-publish -a`，`fd00:6::2`；应答来自 `[fd00:6::2]:5353`）并与之连通、数据通道回显，另一端
  拿不到任何候选，只有解析才能让双方连通（`webrtc-interop` 新增 `mdns-conceal` 与 `mdns-resolve` 模式）。
  对照：去掉第 2 项（跳数限制 1）的构建被同一个 avahi 忽略（`avahi-resolve` 超时），改为
  `check-response-ttl=no` 后即可解析。
- **Chrome 157**（`browser.sh`，macOS，新增一节）：唯一主机候选为其全局 IPv6 地址并被隐藏的
  `Endpoint` 向开启 mDNS 隐藏的无头 Chrome 发起 offer。Chrome 在每条链路上经 `ff02::fb` 查询该名字，
  我方在那里应答（AAAA，在查询所来的链路上）；我方解析 Chrome 被隐藏的 IPv6 候选（它的第一个应答经
  IPv4 到达：Chrome 在查询所用的地址族上应答，而我方两个地址族都查询）；选中的候选对是 IPv6，100 条
  数据通道消息回显。
- **mDNSResponder**（macOS，手动）：`dns-sd -G v6` 解析出被隐藏的链路本地地址（en1 与 lo0 上的应答，
  AAAA，TTL 120）；`mdns-resolve` 从经 IPv6（`fe80::1%lo0`）到达的应答解析出用 `dns-sd -P` 发布的名字。
- macOS 与 gpu51（epoll 与 io_uring）上 akio-sys、akio、akio-webrtc 的 `cargo test`，两处 clippy 均无
  警告（rustc 1.100）。

## 更新（2026-11-22）：声明我方名字、告别、单播跳数限制

本 ADR 与 DEV-PLAN 留下的两项已完成：

- **单播应答使用跳数限制 255。** RFC 6762 §11 要求每个响应（包括单播响应：对 QU 问题的应答、传统单播
  回复）都以 TTL / 跳数限制 255 发出。共享的 mDNS 套接字现在也为单播设置它：新增
  `UdpBinding::set_unicast_hops(u32)`（`IP_TTL` / `IPV6_UNICAST_HOPS`，0..=255，`akio-core` 与 `akio`
  中只有新增）与 `akio_sys::{set_unicast_hops_v6, unicast_hops_v6}`（std 只有 IPv4 的 `set_ttl`）。
  `Engine::bind_udp_multicast_on` 本身不变：单播限制由协议决定，所以由 akio-webrtc 在它的 mDNS 绑定上设置。
- **探测与宣告（RFC 6762 §8）、冲突（§9）、告别（§10.1）。** 被隐藏的名字按唯一记录的要求声明：三次探测，
  间隔 250 ms（带 QU 位的 `ANY` 问题，提议的 `A` / `AAAA` 记录放在权威段；akio-ice 新增 `Message::probe`），
  最后一次探测 250 ms 后声明成功，然后两次宣告，间隔 1 s（带缓存刷新位的主动响应）。声明不会推迟候选：
  名字是随机 UUID，描述中立即携带，并且从一开始就应答。冲突时放弃名字：另一台主机以另一个地址应答它（§9），或在我方仍在探测时用在 §8.2 平局裁决中胜出的记录
  探测它（依次比较类、类型、记录数据的字节；新增 `Record::tiebreak`）。放弃的名字不再应答，其地址为此后
  创建的 peer 换一个新名字；已持有旧名字的 peer 保持不变（记录一条警告）。经组播回环回来的我方探测或相同
  的声明由提议的记录识别，不予应答；声明之后到达的探测会得到应答，从而守住名字。`Endpoint::close` 在关闭
  套接字前为每个名字发送告别（TTL 0）。
- akio-ice 的 `Message` 新增 `authority`（权威段的地址记录；akio-ice 是内部 crate，其 API 可在任何版本中
  变化）。

当时未做：首次探测前 0–250 ms 的随机延迟、按接口宣告只带该接口的地址（§6.2）。两项都在同日稍后完成
（见下面的更新 2）。

验证：

- akio-ice：探测往返（QU `ANY` 问题，权威段记录不带缓存刷新位，与应答分开）、平局裁决顺序；`ice_mdns`
  模糊测试目标也把解析出的权威段记录重建为探测（新增种子）。
- akio-webrtc `tests/mdns.rs`，对 `ff02::fb` 上的原始套接字：新名字被探测三次，间隔至少 200 ms，最后一次
  探测至少 200 ms 后声明，宣告两次，间隔至少 900 ms，不应答自己的探测，关闭 endpoint 时发送告别；以另一
  地址应答会使名字被放弃（下一个 offer 带新名字，旧名字的查询不再得到应答）；同时到达的探测中，`A` 记录
  输给我方的 `AAAA ::1`，`AAAA fd00::99` 胜出。akio `tests/shared_ports.rs`：IPv4 与 IPv6 绑定上的
  `set_unicast_hops`。akio-sys：IPv6 单播跳数限制的往返。
- `tools/interop/webrtc/mdns6.sh`（gpu51，纯 IPv6 容器）：epoll 与 io_uring 下的 mDNS 测试（各 9/9，
  无跳过），avahi 0.8 仍能解析我方名字、发布我方能解析的名字，以及新的一步：avahi 用 fd00:6::2 发布
  Endpoint 已声明的名字（`avahi-publish -a -R`），探测时得到我方应答并报告 "Name collision"；Endpoint
  保住名字（avahi-publish 随后在为 UUID 标签寻找替代名时触发自身的断言而中止）。

## 更新 2（2026-11-22）：探测前延迟，链路本地地址只在本链路上

- **首次探测前的随机延迟**（RFC 6762 §8.1）：名字的第一次探测在随机 0–250 ms 后发出
  （`akio_sys::fill_random`），同时启动的 endpoint 或主机不会同步探测。名字仍然立即写入描述并得到应答。
- **链路本地 IPv6 地址只在其链路上**（§6.2：地址记录只应在地址可用的接口上发出）。链路本地地址的名字
  保留所隐藏主机候选的作用域 ID；它的探测、宣告与告别只发往该链路上的 `ff02::fb`（不经 IPv4，IPv4 只有
  默认接口上的一个组），经 IPv6 从其他链路到达的查询不以它应答。经 IPv4 的查询仍会应答（无法得知其链路）。
  其他地址（全局、ULA、IPv4）照旧在每条链路上发出：要知道它们在哪个接口上需要接口地址列表（`getifaddrs`），
  本项目不读取它。

未做：按接口区分 IPv4 与非链路本地 IPv6 记录（没有接口地址列表）；在默认接口以外的接口上做 IPv4 组播。

验证：akio-webrtc `tests/mdns.rs` 的 `link_local_names_stay_on_their_link`（endpoint 绑定在链路本地地址
上：其探测与宣告的每份副本都以该地址为源地址，在其他链路上发出则不会如此；来自另一条链路的查询得不到应答，
来自其链路的查询得到应答；少于两条链路时跳过），声明相关测试在加入延迟后不变。macOS（lo0 与 en*：全部检查）
以及 gpu51 上的 `tools/interop/webrtc/mdns6.sh`（epoll 与 io_uring，avahi 各步骤；容器的两条链路是同一对
veth 的两端，即同一根线，测试发现在一端发出的查询会到达另一端，于是在那里跳过"其他链路"的检查）。
