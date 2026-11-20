# ADR-055：only-ice 中每个 ICE 数据流支持多个组件

[English](055-ice-components.md) | 简体中文

状态：已采纳（2026-11-20）

## 背景

`only_ice::IceAgent`（自研 WebRTC 协议栈的 ICE 层，最近的新增见 ADR-044）只处理一个组件：组件号
不是 1 的候选一律丢弃，选定候选对、提名、同意新鲜度和 lite 代理的状态都是单个值。WebRTC 总是复用
RTP 与 RTCP（rtcp-mux、BUNDLE），这对 only-webrtc 足够；但 RFC 8445 的数据流可以有多个组件，最典型
的情形是 RTP 用一个端口、RTCP 用下一个端口（SIP 终端、较老的 RTP 协议栈、只有 `a=rtcp` 没有
`a=rtcp-mux`），需要两个组件。crate README 把“多组件”列为未实现。

RFC 8445 每个数据流保持一个检查列表，包含所有组件的候选对（§6.1.2），只有一个节奏定时器
（§6.1.4.2）。foundation 与组件无关（§5.1.1.3），因此同一对套接字上的 RTP 与 RTCP 候选共享
foundation；初始状态下，每个 foundation 中组件号最小的候选对为 Waiting，其余为 Frozen（§6.1.2.6）；
一个检查成功会解冻所有组件中同一 foundation 的候选对（§7.2.5.3.3），于是某条路径上 RTP 通了之后
才检查该路径上的 RTCP。提名与选定按组件进行（§8.1），每个组件都有被提名的候选对时检查列表完成
（§8.1.2），同意新鲜度在每个选定候选对上运行（RFC 7675 §5），检查的 PRIORITY 用组件号计算
（§7.1.1）。角色（及其 tie-breaker）属于代理而不是组件。

单组件 API 被 only-webrtc 使用，而另一个会话正在同时修改 only-webrtc；它必须保持源码兼容、行为
完全不变。

## 决定

1. **组件是数据流的属性**：`IceConfig::components`（默认 1，限制在 1..=256）。本地候选用
   `Candidate::with_component(n)` 指定组件，它改写优先级的低字节（`256 - n`，RFC 8445 §5.1.2.1），
   foundation 不变；远端候选照旧在 SDP 行中带着组件号。数据流没有的组件的候选仍被忽略
   （`add_local_candidate` 返回 `false`），所以默认代理和以前一样忽略组件 2。候选只与同组件的候选
   配对。
2. **一个检查列表，按组件的状态。** 所有组件的候选对仍在一个列表里，共用一个触发队列和一个 `Ta`
   节奏；每个候选对记录自己的组件。原先的单个值改为每个组件一份：选定候选对、正在提名的候选对、
   为常规提名计时的首个有效时间 / 改进时间、受控方收到的最大 NOMINATION 值、同意新鲜度（下次检查、
   最后响应、失效标志、事务）以及 lite 代理的最后一个有效检查。控制方只保留一个 NOMINATION 计数器
   （取值只需在每个组件内递增）。
3. **按 RFC 8445 §6.1.2.6 的 Frozen 与 Waiting，并支持 trickle。** 候选以任意顺序到达，所以初始状态
   作为不变量维护，而不是只计算一次：新候选对在同一 foundation 中存在组件号更小且未失败的候选对、或
   同组件中有 Waiting / 正在检查的候选对时为 Frozen；组件号更小的新候选对会把同一 foundation 中更大
   组件的 Waiting（尚未检查、不在触发队列中）候选对重新冻结。检查成功会解冻所有组件中该 foundation
   的候选对（原有规则，现在跨组件）。没有 Waiting 候选对时检查优先级最高的 Frozen 候选对（与以前
   相同），所以即使某个 foundation 的 RTP 候选对全部失败，其 RTCP 候选对仍会被检查。
4. **按组件提名、选定和同意新鲜度。** 控制方对每个组件分别执行常规提名（该组件没有更优候选对待检查
   时，或其首个有效候选对出现 `nomination_delay` 之后，提名最佳有效候选对）、激进提名和重新提名；
   一次选定只停止本组件的其他检查。受控方按组件接受提名。lite 代理根据检查目的地址上的本地候选
   确定其组件（该地址没有候选时为组件 1，与以前相同）。同意检查在每个选定候选对上运行，各有定时器
   和事务；同意响应计入其所应答事务所属的组件。
5. **代理状态综合所有组件**：每个组件都有选定候选对（任一代）时为 `Connected`；每个组件都有当前
   代的选定候选对且没有剩余检查时为 `Completed`；任一组件同意失效时为 `Disconnected`；在
   end-of-candidates 或 `failed_timeout` 之后，某个尚无选定候选对的组件既没有触发检查、其候选对又
   全部失败（或从未有过候选对）时为 `Failed`。只有一个组件时这些规则与以前相同。
6. **ICE 重启覆盖整个数据流**：`restart` 与新的远端凭据为所有组件重建检查列表；每个组件保留原选定
   候选对（以及基于旧凭据的同意检查），直到新一代为该组件提名。
7. **API，只有新增**：`IceConfig::components`、`Candidate::with_component`、
   `IceAgent::{components, selected_pair_of, send_pair_of}` 以及
   `IceEvent::ComponentSelectedPair { component, local, remote }`（`IceEvent` 是
   `#[non_exhaustive]`）。`IceEvent::SelectedPair`、`selected_pair()` 与 `send_pair()` 仍是组件 1
   的，所以匹配 `SelectedPair { local, remote }` 的调用方（only-webrtc）照常编译、行为不变。
   `Transmit` 不增加组件字段：它的 `source` 就是调用方需要的本地套接字。ICE 状态的文档改为针对所有
   组件。唯一的源码级不兼容：crate 外部用结构体字面量构造 `IceConfig` 时必须加上
   `components: 1`（only-ice 属于内部层级；workspace 中都用 `IceConfig::new` 构造配置，它会设置该
   字段）。

## 影响

- 模拟网络（`tests/sim.rs`）：双组件数据流在每种提名方式和两种角色下都在一秒内连通，两个组件都
  选定后才进入 `Connected`，并在两个组件都有数据的情况下保持 `Completed` 120 s；25 % 丢包、10 %
  重复、300 ms 乱序下的 12 个种子（IPv4 与 IPv6，部分对端为 lite）全部完成，每个组件只选定一次；
  角色冲突得到解决；经 NAT 为每个组件发现 peer-reflexive 候选对；检查顺序体现了 Frozen 规则（无论
  候选以何种顺序 trickle 进来，两个 RTP 候选对都先于优先级高于 IPv4 RTP 候选对的 IPv6 RTCP 候选对
  被检查；关闭该规则后测试失败）；RTCP 端口不可达时即使 RTP 已选定也会 `Failed`（有
  end-of-candidates 时 6-10 s 后，否则在 30 s 超时后）；只有 RTCP 失去同意时 23-31 s 后为
  `Disconnected`，恢复后回到 `Completed`；任一方发起的 ICE 重启会为两个组件重新选定。原有 46 个
  测试（28 个模拟、18 个单元）不加修改全部通过。
- 互通（`tests/libnice.rs`、`tools/interop/ice/run.sh`）：通过回环 UDP 与 libnice 0.1.21（Debian 12）
  的一个双组件数据流互通五种组合（libnice 控制方分别用激进提名与常规提名、libnice 受控、libnice
  lite、only-ice lite）：双方为每个组件选定同一候选对，libnice 报告两个组件都 `ready`，两个组件上
  都双向传输数据。pion/ice 只有一个组件，因此 `tests/pion.rs` 不变。
- 模糊测试：`ice_stun` 也驱动双组件代理（完整控制方、启用激进提名与重新提名的受控方、lite），在两个
  组件的地址上输入数据报；新增一个带组件 2 候选行的种子。
- 代价：每个组件有自己的同意定时器和检查（每个选定候选对每 5 s ±20 % 一次）；100 个候选对的上限由
  所有组件共享。
- 未做：在 only-webrtc 中接入不带 rtcp-mux 的数据流（提供或接受只有 `a=rtcp`、没有 `a=rtcp-mux` 的
  媒体、每个 m 行第二个套接字、组件 2 上的 RTCP）：only-webrtc 仍只用组件 1，未作修改。当多条路径
  同样可用时，把所有组件提名到同一 foundation 上（每个组件独立选择自己的最佳候选对；由于 foundation
  共享且有 Frozen 顺序，它们通常落在同一路径上）。
