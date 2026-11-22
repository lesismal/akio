# akio-ice

[English](README.md)

[`akio`](https://github.com/lesismal/akio) 的 sans-io ICE（RFC 8445）实现：完整（full）与精简
（lite）代理、同意新鲜度（consent freshness，RFC 7675）、Trickle（RFC 8838）、ICE 重启，常规提名、
激进提名与重新提名，面向 UDP 与 TCP 上单组件（RTP/RTCP 复用，BUNDLE）或多组件（RTP 与 RTCP 各用
各的端口）的数据流，并带有处理浏览器
`.local` 候选的 mDNS 编解码。基于 [`akio-turn`](../akio-turn) 的 STUN 编解码和
[`akio-crypto`](../akio-crypto)，纯安全 Rust（`#![forbid(unsafe_code)]`），没有其他依赖。它是自研
WebRTC 协议栈的 ICE 层，用来替换 str0m 的实现。这是内部 crate（docs/api-stability.md）：API 跟随
该协议栈的需要，任何版本都可能变化。

## 驱动代理

`IceAgent` 不持有套接字、线程或时钟。调用方收集候选地址、完成信令，把收到的每个数据报和当前
时间传进来，再把产生的数据发出去：

```rust,ignore
use std::time::Instant;
use akio_ice::{Candidate, Credentials, IceAgent, IceConfig, IceEvent};

let mut agent = IceAgent::new(IceConfig::new(false, /* controlling */ true), Instant::now());
agent.add_local_candidate(Candidate::host(socket.local_addr()?));
// SDP：a=ice-ufrag / a=ice-pwd 取自 agent.local_credentials()，a=candidate 取自 to_sdp()。
agent.set_remote_credentials(Credentials::new(remote_ufrag, remote_pwd));
agent.add_remote_candidate(Candidate::parse(line)?); // trickle：任何时候都可以
loop {
    while let Some(t) = agent.poll_transmit() { /* 从 t.source 向 t.destination 发送 t.contents */ }
    while let Some(e) = agent.poll_event() {
        match e {
            IceEvent::StateChanged(s) => { /* New、Checking、Connected、Completed …… */ }
            IceEvent::SelectedPair { local, remote } => { /* DTLS/SRTP 走这里 */ }
            _ => {}
        }
    }
    // 等待数据报直到 agent.poll_timeout()，然后：
    // if !agent.handle_receive(now, from, local_addr, &datagram) { /* DTLS、SRTP …… */ }
    // 或 agent.handle_timeout(now)
}
```

- `send_pair()` 给出应用数据的发送路径：已选定的候选对；提名之前是最佳的有效候选对；lite
  代理则是最后一个带 USE-CANDIDATE 的检查所在的候选对。
- `restart(new_credentials, keep_local_candidates)` 以及用新值调用 `set_remote_credentials`
  会重启 ICE；在新一代完成提名之前，旧的选定候选对继续工作。
- 对端是 `a=ice-lite` 时调用 `set_remote_lite(true)`；`end_of_remote_candidates()` 使代理能进入
  `Failed`；`close()` 停止代理。
- `Candidate::parse` 把 mDNS（`*.local`）和 FQDN 候选报告为不同的 `ParseError` 变体
  （`is_unsupported()`）；`Candidate::parse_resolved(line, |name| ...)` 把名字交给解析器并采用其返回
  的地址（名字保存在 `hostname()`）。`mdns` 模块构造一次性查询、读取应答（RFC 6762；每条消息一个
  问题，这是 Chromium 应答器的要求），并应答对我方名字的查询：`Candidate::with_hostname(name)` 让
  SDP 写名字而非 IP（配合 `with_related(Some(0.0.0.0:0))` 隐藏相关地址）。套接字由调用方负责
  （akio-webrtc 的 `Endpoint::resolve_mdns`）。
- 提名：默认常规提名；`IceConfig::aggressive_nomination`（每个检查都带 USE-CANDIDATE，最终取能用
  的最佳候选对）与 `IceConfig::renomination` 加 `set_remote_renomination(true)`
  （draft-thatcher-ice-renomination：提名后发现的更好候选对会以更大的 NOMINATION 值再次提名）。
  受控代理遵循最大的 NOMINATION 值，没有该属性时取优先级最高的被提名候选对。
- 多组件（RFC 8445；不使用 rtcp-mux 的 RTP 与 RTCP）：`IceConfig::components = 2`，本地候选用
  `Candidate::host(rtcp_addr).with_component(2)`（优先级随之改变，foundation 不变），对端的
  `a=candidate` 行自带组件号。每个组件都有选定候选对后状态才进入 `Connected` / `Completed`；组件 2
  的选定通过 `IceEvent::ComponentSelectedPair { component: 2, .. }`、`selected_pair_of(2)` 与
  `send_pair_of(2)` 给出（`SelectedPair`、`selected_pair()` 与 `send_pair()` 仍是组件 1 的）。
  收到的数据报属于其到达的本地候选所在的组件。
- TCP 候选（RFC 6544）：`TcpType`、`Candidate::host_tcp`、SDP 中的 `tcp ... tcptype`、低于 UDP 的
  RFC 6544 优先级、只在同一传输内且类型兼容时配对（主动配被动，`so` 配 `so`）。主动和 `so` 本地
  候选像 UDP 候选一样发送检查（调用方在第一个检查发出时建立连接）；被动本地候选只应答：经接受的
  连接到达的检查形成候选对。调用方用 `tcp::FrameReader` / `tcp::frame`（RFC 4571）对连接分帧。

## 协议覆盖

- 候选：RFC 8445 §5.1 的优先级与 foundation；RFC 8839 §5.1 的 SDP 语法，以及 `generation`、
  `ufrag`、`network-id`、`network-cost` 扩展。
- 检查列表：每个数据流一个、涵盖所有组件，按组件与 IP 协议族配对、候选对优先级、按 base 剪除
  冗余、Frozen/Waiting/InProgress/Succeeded/Failed 状态，采用 RFC 8445 §6.1.2.6 的初始状态（每个
  foundation 中组件号最小的候选对为 Waiting；候选以其他顺序 trickle 进来时也是如此），并跨组件按
  foundation 解冻，最多 100 个候选对；每个 `Ta`（50 ms）发起一个检查，
  触发检查队列；重传从 250 ms 开始翻倍，上限 1.6 s，共 7 次（首发约 8 s 后候选对失败）。
- 检查：USERNAME、PRIORITY、带随机 tie-breaker 的 ICE-CONTROLLING/ICE-CONTROLLED、USE-CANDIDATE、
  MESSAGE-INTEGRITY、FINGERPRINT；400/401 应答，双方的角色冲突处理（487）；对端反射
  （peer-reflexive）候选；只接受对称的响应；远端凭据到达之前的请求照常应答，其触发检查等待凭据。
- 提名（按组件进行）：常规提名（该组件没有更优候选对待检查时，或其首个有效候选对出现 500 ms 后，
  提名最佳有效候选对；
  对端为 lite 时立即提名）；激进提名（RFC 5245 §8.1.1.2）与重新提名
  （draft-thatcher-ice-renomination-01，NOMINATION 属性 0xC001），二者在选中后都继续检查更好的
  候选对并迁移到能用的那个；受控方遵循 USE-CANDIDATE（取最大 NOMINATION 值，否则取优先级最高的
  被提名候选对）；lite 代理选择最后一个 USE-CANDIDATE 检查的候选对。
- mDNS（`mdns`，RFC 6762）：`A` / `AAAA` 一次性查询，应答（组播、带 QU 的单播、传统单播），压缩
  指针（只能向前跳回，每个名字最多 16 次），随机 UUID 名字。
- 同意新鲜度（按组件进行）：在每个选定候选对上每 5 s ±20 % 检查一次（重传 4 次），任一组件 30 s
  无响应（lite：无有效检查）即进入 `Disconnected`，恢复后回到原状态。end-of-candidates 之后或 30 s
  后，某个尚无选定候选对的组件的所有候选对都失败则为 `Failed`。ICE 重启覆盖所有组件；每个组件在
  新一代为它提名之前保留原选定候选对。

未实现：候选收集（STUN/TURN 客户端由
调用方负责）、任何套接字（mDNS 解析器与应答器、TCP 连接都在 akio-webrtc 的 `Endpoint` 中）、远端
不支持重新提名时的改选（那要靠 ICE 重启）。不做 ICE 的对端（以普通 `c=` / 端口描述媒体的 SIP 终端）
用 `IceAgent::set_fixed_pair` 设置固定候选对（此后不做检查和 consent，ADR-072）；`mdns::MULTICAST_V6` /
`multicast_v6_on` 给出 IPv6 组，`Candidate::with_scope_id` 为链路本地候选指定接口。

## 测试

- 模拟网络（`tests/sim.rs`）：full↔full 两种角色、full↔lite 双向、host、srflx 以及经模拟端口受限
  NAT 发现的 peer-reflexive 候选、不可达候选、IPv4/IPv6 混合、24 个种子下 25 % 丢包、10 % 重复和
  300 ms 乱序、trickle、远端凭据之前到达的检查、角色冲突、链路中断约 30 s 后失去同意及恢复、
  任一方发起的 ICE 重启（保留或更换候选，以及切换到新路径）、end-of-candidates 或超时后的
  `Failed`、来自错误地址的响应、伪造的完整性校验、畸形请求（400/401）、RFC 5769 测试向量。
- 互通（`tests/pion.rs`，默认忽略）：通过回环 UDP 与 pion/ice v4.4.8 互通四种组合（pion 受控、
  pion 控制、pion lite、akio-ice lite），并在选定候选对上双向交换数据；需要 `AKIO_ICE_PION_PEER`
  指向一个小型 pion 对端程序。pion/ice 只有一个组件。
- 双组件互通（`tests/libnice.rs`，默认忽略；`tools/interop/ice/run.sh` 在 Debian 容器中编译对端并
  运行）：通过回环 UDP 与 libnice 0.1.21 的一个双组件数据流互通五种组合（libnice 控制方分别用激进
  提名与常规提名、libnice 受控、libnice lite、akio-ice lite）；双方为每个组件选定同一候选对，两个
  组件上都双向传输数据。
- 多组件（`tests/sim.rs`）：双组件数据流（RTP 与 RTCP 端口）在每种提名方式和两种角色下、丢包链路
  的 12 个种子（IPv4 与 IPv6，部分对端为 lite）、角色冲突、经 NAT 为每个组件发现的 peer-reflexive
  候选对、Frozen 顺序（无论候选以何种顺序 trickle 进来，两个 RTP 候选对都先于 RTCP 的检查）、RTCP
  不可达（RTP 已选定仍为 `Failed`）、只有 RTCP 失去同意及恢复、任一方发起的 ICE 重启。
- 提名（`tests/sim.rs`）：提名后 trickle 出的更好候选对，常规提名下被忽略，激进提名与重新提名下
  双方都会迁移（也在 10% 丢包下）；激进提名最终落在最佳候选对；受控代理遵循最大的 NOMINATION 值并
  忽略旧值。
- 模糊测试：`fuzz/` 中的 `ice_stun`（向控制方、受控方和 lite 代理输入数据报，也包括启用激进提名
  与重新提名的代理和双组件代理，以及 `Candidate::parse`）、`ice_tcp`（分帧的连接）和 `ice_mdns`（mDNS 消息、
  带名字的候选行）目标；`fuzzing::tests` 在 stable 上回放它们的语料。
