# only-ice

[English](README.md)

[`only`](https://github.com/lesismal/only) 的 sans-io ICE（RFC 8445）实现：完整（full）与精简
（lite）代理、同意新鲜度（consent freshness，RFC 7675）、Trickle（RFC 8838）和 ICE 重启，面向
UDP 上的单个组件（RTP/RTCP 复用，BUNDLE）。基于 [`only-turn`](../only-turn) 的 STUN 编解码和
[`only-crypto`](../only-crypto)，纯安全 Rust（`#![forbid(unsafe_code)]`），没有其他依赖。它是自研
WebRTC 协议栈的 ICE 层，用来替换 str0m 的实现。这是内部 crate（docs/api-stability.md）：API 跟随
该协议栈的需要，任何版本都可能变化。

## 驱动代理

`IceAgent` 不持有套接字、线程或时钟。调用方收集候选地址、完成信令，把收到的每个数据报和当前
时间传进来，再把产生的数据发出去：

```rust,ignore
use std::time::Instant;
use only_ice::{Candidate, Credentials, IceAgent, IceConfig, IceEvent};

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
- `Candidate::parse` 把 TCP、mDNS（`*.local`）和 FQDN 候选报告为不同的 `ParseError` 变体
  （`is_unsupported()`），便于跳过。

## 协议覆盖

- 候选：RFC 8445 §5.1 的优先级与 foundation；RFC 8839 §5.1 的 SDP 语法，以及 `generation`、
  `ufrag`、`network-id`、`network-cost` 扩展。
- 检查列表：按 IP 协议族配对、候选对优先级、按 base 剪除冗余、Frozen/Waiting/InProgress/
  Succeeded/Failed 状态与按 foundation 解冻，最多 100 个候选对；每个 `Ta`（50 ms）发起一个检查，
  触发检查队列；重传从 250 ms 开始翻倍，上限 1.6 s，共 7 次（首发约 8 s 后候选对失败）。
- 检查：USERNAME、PRIORITY、带随机 tie-breaker 的 ICE-CONTROLLING/ICE-CONTROLLED、USE-CANDIDATE、
  MESSAGE-INTEGRITY、FINGERPRINT；400/401 应答，双方的角色冲突处理（487）；对端反射
  （peer-reflexive）候选；只接受对称的响应；远端凭据到达之前的请求照常应答，其触发检查等待凭据。
- 提名：常规提名（没有更优候选对待检查时，或首个有效候选对出现 500 ms 后，提名最佳有效候选对；
  对端为 lite 时立即提名）；受控方遵循 USE-CANDIDATE；lite 代理选择最后一个 USE-CANDIDATE 检查的
  候选对。
- 同意新鲜度：在选定候选对上每 5 s ±20 % 检查一次（重传 4 次），30 s 无响应（lite：无有效检查）
  进入 `Disconnected`，恢复后回到原状态。end-of-candidates 之后或 30 s 后所有候选对都失败则为
  `Failed`。

未实现：多组件、TCP 候选、候选收集（STUN/TURN 客户端由调用方负责）、mDNS 解析、作为控制方的
激进提名与重新提名、在提名之后改选更好的候选对。

## 测试

- 模拟网络（`tests/sim.rs`）：full↔full 两种角色、full↔lite 双向、host、srflx 以及经模拟端口受限
  NAT 发现的 peer-reflexive 候选、不可达候选、IPv4/IPv6 混合、24 个种子下 25 % 丢包、10 % 重复和
  300 ms 乱序、trickle、远端凭据之前到达的检查、角色冲突、链路中断约 30 s 后失去同意及恢复、
  任一方发起的 ICE 重启（保留或更换候选，以及切换到新路径）、end-of-candidates 或超时后的
  `Failed`、来自错误地址的响应、伪造的完整性校验、畸形请求（400/401）、RFC 5769 测试向量。
- 互通（`tests/pion.rs`，默认忽略）：通过回环 UDP 与 pion/ice v4.4.8 互通四种组合（pion 受控、
  pion 控制、pion lite、only-ice lite），并在选定候选对上双向交换数据；需要 `ONLY_ICE_PION_PEER`
  指向一个小型 pion 对端程序。
- 模糊测试：`fuzz/` 中的 `ice_stun` 目标（向控制方、受控方和 lite 代理输入数据报，以及
  `Candidate::parse`）；`fuzzing::tests` 在 stable 上回放其语料。
