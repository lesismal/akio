# only-sctp

[English](README.md)

[`only`](https://github.com/lesismal/only) 的 sans-io SCTP over DTLS（RFC 8261）与 WebRTC 数据通道
（RFC 8831、RFC 8832），构建在 [`only-crypto`](../only-crypto) 之上，安全 Rust
（`#![forbid(unsafe_code)]`），没有其他依赖。它是 DEV-PLAN 第 D 波计划中自研 WebRTC 协议栈的数据通道层，
将替代 str0m 的 SCTP。这是内部 crate（docs/api-stability.zh-CN.md）：API 跟随该协议栈的需要，
可能在任何发布中变化。

## 驱动关联

`Association` 没有套接字、线程或时钟。调用方把每条 DTLS 应用数据记录（每条一个 SCTP 包）交给它，
并把它产生的每个包作为一条 DTLS 记录发送：

```rust,ignore
use std::time::Instant;
use only_sctp::{Association, ChannelOptions, Config, Event};

let mut sctp = Association::new(Config::new(dtls_client), Instant::now());
if dtls_client {
    sctp.connect(Instant::now()); // 任一端都可以发起；INIT 碰撞会收敛为一个关联
}
let chat = sctp.open_channel(Instant::now(), ChannelOptions::new("chat"))?;
sctp.send(Instant::now(), chat, b"hello", false)?; // 关联建立前先排队
loop {
    while let Some(packet) = sctp.poll_transmit(Instant::now()) { /* dtls.send(&packet) */ }
    while let Some(event) = sctp.poll_event() {
        match event {
            Event::Connected => {}
            Event::ChannelOpen { stream, label, .. } => {}
            Event::ChannelData { stream, data, binary } => {}
            Event::BufferedAmountLow { stream } => {}
            Event::ChannelClose { stream } => {}
            Event::Closed => return, // 总是最后一个事件
        }
    }
    // 在 sctp.poll_timeout() 之前等待记录，然后：
    // sctp.handle_packet(Instant::now(), &record) 或 sctp.handle_timeout(Instant::now())
}
```

- `Config::new(dtls_client)`：端口 5000，MTU 1200，收发两个方向的消息上限都是 256 KiB
  （`max_message_size` 即对端的 `a=max-message-size`；收到更大的消息会中止关联），1 MiB 接收窗口和
  每通道缓冲，10 次重传；RTO 初始 1 s、最小 200 ms、最大 10 s；提供 I-DATA（`message_interleaving`），
  使用加权公平排队调度器（`scheduler`）。
- 各通道通过 `Scheduler`（RFC 8260 §3）共享关联：先到先服务、轮询、按包轮询、优先级、公平容量，或按通道
  优先级的加权公平排队（默认）。优先级来自 `ChannelOptions::with_priority`、对端 DATA_CHANNEL_OPEN 中的值
  或 `set_channel_priority`，与 RFC 8832 一致，越大越重要。使用 I-DATA 时（双方都提供；由
  `message_interleaving()` 告知）调度单位是 chunk，大消息不再阻塞其他通道上的小消息（只有已开始的消息
  不超过对端窗口一半时才开始新消息）；使用 DATA 时，
  已开始的消息整条发完。
- `open_channel` 选择本端奇偶性下最小的空闲流 ID（DTLS 客户端用偶数，服务端用奇数），或使用
  `ChannelOptions::negotiated`；可以在关联建立前调用。通道已缓冲超过 `max_buffered_amount` 时
  `send` 返回 `Ok(false)`；`buffered_amount` 统计已排队和未确认的字节；它从阈值（默认 0）之上降到
  阈值或以下时触发 `BufferedAmountLow`。
- `close_channel` 在已排队数据之后重置出向流；两个方向都重置后（对端会用自己的重置回应）触发一次
  `ChannelClose`，流 ID 可以再次使用。`shutdown` 是优雅关闭，`abort` 立即关闭；关联结束时每个打开的
  通道先收到 `ChannelClose`，最后是 `Closed`。

## 协议覆盖

- 包与握手（RFC 9260）：CRC-32C 以小端存放（与 usrsctp、pion 一致），按 MTU 捆绑多个块，
  未知块和参数按类型高位处理；INIT / INIT ACK / COOKIE ECHO / COOKIE ACK，自包含的 HMAC-SHA-256
  cookie，INIT 与 COOKIE ECHO 重传（8 次），INIT 碰撞与重复 COOKIE ECHO；Supported Extensions
  声明 RE-CONFIG、FORWARD TSN、I-DATA 与 I-FORWARD-TSN。
- 数据传输：分片与重组（受接收上限约束），有序与无序投递，带间隙块和重复 TSN 的 SACK（每两个包或
  200 ms 延迟确认，出现间隙时立即确认），慢启动与拥塞避免，对端窗口，基于 SRTT / RTTVAR 的 T3-rtx
  （Karn 算法），快速重传与快速恢复，`max_retransmissions` 次超时后关联失败；应答 HEARTBEAT；
  两种角色的 SHUTDOWN；ABORT。
- 消息交错（RFC 8260 §2）：双方都提供时使用 I-DATA chunk（32 位 MID、FSN），不同流的分片交错发送，
  按流和消息重组；否则使用 DATA；收到未协商的那种数据 chunk 时发送 ABORT。流调度器与优先级
  （RFC 8260 §3）见上文。
- 部分可靠（RFC 3758）：按消息的重传次数上限和生存期，双向 FORWARD TSN（带流 / SSN 对；I-DATA 下为
  带流 / MID 条目的 I-FORWARD-TSN），仅在对端支持时使用。
- 流重置（RFC 6525）：Outgoing SSN Reset Request / Response，支持 "in progress" 与重试；
  接受对端同时在途、任意顺序到达的多个请求；接受增加流的请求。
- 数据通道（RFC 8831 / 8832）：DCEP OPEN / ACK，全部通道类型，协商通道，PPID 50、51、53、56、57
  （接收时也接受已弃用的分段 PPID 52、54），收到对端 ACK 之前消息按序发送。

未实现：多宿主，主动发送 HEARTBEAT，对端重启，AUTH，ASCONF，ECN，零校验和（RFC 9653），
Incoming SSN Reset 与 SSN/TSN Reset 请求（拒绝）。未检查与 usrsctp（Firefox）的互通。

## 测试

- 单元测试：编解码往返与校验和位置（DATA、I-DATA、I-FORWARD-TSN），带 TSN 回绕的重组，交错与乱序的
  I-DATA 重组，FORWARD TSN 与 I-FORWARD-TSN，DCEP，DATA / I-DATA 不匹配时中止。
- 模拟链路（`tests/link.rs`，模拟时间）：15 % 丢包、5 % 重复、最多 40 ms 乱序，MTU 低至 300 字节；
  有序、无序、双向，60 kB 到 256 KiB 的消息，限重传和限生存期通道与 FORWARD TSN，空消息，背压与
  `BufferedAmountLow`，任一端关闭通道与流 ID 复用，同时 INIT，关联建立前发送，协商通道，优雅关闭，
  中止，对端消失后的失败，INIT 放弃，无损链路传输 10 MB，超大的入向消息，垃圾包；各种组合下的 I-DATA
  协商，队头阻塞（两个通道上一条 200 kB 和一条 4 字节的消息），调度份额（均分、3:1 加权、严格优先级、
  FCFS 顺序、每包单一流），运行时修改优先级，可靠与部分可靠通道交错时的部分可靠性，许多通道上同时发送大量大消息。DATA 与 I-DATA
  在奇偶种子上交替运行；`SCTP_SEEDS=<n>` 运行更多种子。
- UDP 互通（`examples/udp_peer.rs`、`tools/interop/sctp/run.sh`）：对 pion/sctp v1.12.0 加
  pion/datachannel，两种角色，pion 的交错打开（I-DATA / I-FORWARD-TSN）与关闭（DATA），无丢包以及每个
  方向每 10 个包丢 1 个：有序和无序通道上的回显，pion 打开的可靠与部分可靠通道，双方各自关闭通道，
  优雅关闭（此前也测过 v1.8.33 和最多 25 % 丢包，此时 pion 可能超过 60 s 的时限）。通过 only-webrtc
  （`tools/interop/webrtc`）：pion 协商 I-DATA；Chrome 157 使用 DATA，除非以
  `--force-fieldtrials=WebRTC-DataChannelMessageInterleaving/Enabled/` 启动，此时同样通过。
- 模糊测试：`fuzz/` 中的目标 `sctp_packet`（任意包，原样以及修正校验和后，送入新建、握手中和已建立的
  关联，已建立的一对使用 I-DATA，另一对使用 DATA）；`fuzzing::tests` 在 stable 上回放其语料。
