# ADR-037：SCTP 消息交错（I-DATA）与流调度器

[English](037-sctp-idata-schedulers.md) | 简体中文

状态：已采纳（2026-11-18）

## 背景

`akio-sctp` 是自研 WebRTC 协议栈的数据通道层，此前按先到先服务的顺序用 DATA chunk 发送消息。
DATA 消息的各分片必须占用连续的 TSN，所以一条大消息一旦开始发送，其他通道都要等它的最后一个分片：
一个通道上 256 KiB 的文件传输，会让另一个通道上的聊天消息一直等到这次传输全部离开拥塞窗口为止。
DATA_CHANNEL_OPEN 中携带的通道优先级只被记录下来，从未使用。

RFC 8260 解决了这两个问题。I-DATA chunk（类型 0x40）为每个流携带 32 位消息标识（MID）和分片序号
（FSN），因此不同流上消息的分片可以交错发送；I-FORWARD-TSN（0xC2）按流和 MID 指明被放弃的消息。
第 3 节定义了流调度器。双方都必须在 Supported Extensions 中列出 I-DATA，一旦协商成功就不得再使用
DATA。已核实的对端：pion/sctp v1.12.0 实现了 RFC 8260 并默认提供（加权公平排队）；Chrome 157
（dcSCTP）实现了它，但只有在 field trial `WebRTC-DataChannelMessageInterleaving` 打开时才提供，
所以目前 Chrome 走的是 DATA。

## 决定

1. **协商。** `Config::message_interleaving`（默认 `true`）在我们的 INIT / INIT ACK 中列出 I-DATA
   和 I-FORWARD-TSN。双方都列出 I-DATA 时使用 I-DATA（由 `Association::message_interleaving`
   告知）；对端是否提供记录在 state cookie 中（与 FORWARD TSN 标志相邻的一位，旧 cookie 仍可解码）。
   否则照旧使用 DATA 和 FORWARD TSN。在 I-DATA 关联上收到 DATA chunk，或在 DATA 关联上收到 I-DATA，
   以 "protocol violation" 中止（RFC 8260 §2.2.3）；与当前方式不符的 FORWARD TSN 被忽略。
2. **发送。** 消息按流排队，在每个分片获得 TSN 时才切分（DATA 载荷大小不变；I-DATA 分片少 4 字节），
   分片是每条消息一块共享缓冲区的切片。一个流的有序与无序消息各自计数 MID，出方向流重置后从 0
   重新开始。部分可靠的消息被放弃时如果还有未发送的部分，无论 I-DATA 还是 DATA，它的最后一个分片
   仍占用一个永不发送的 TSN：否则当已发送的分片全部到达时，对端的累计 TSN 会在任何 forward chunk
   通知跳过之前越过这条消息，有序流就会卡在一条永远无法完成的消息上（由有损链路测试发现）。
   I-FORWARD-TSN 列出每个有序流被跳过的最大 MID，以及每条被跳过的无序消息。使用 I-DATA 时接收端必须完整
   保存每条已开始的消息直到它完成，所以发送端只在已开始未发完的消息加上新消息不超过对端初始窗口一半时
   才开始新消息，否则先发已开始的：否则足够多通道上足够大的消息（8 × 250 kB）会让对端窗口被一条也
   无法完成的不完整消息占满，关联停滞直至失败（评审中发现；`many_concurrent_large_messages`）。
3. **接收。** I-DATA 分片按 (stream, U, MID) 以 FSN 重组，有序消息按 MID 以 32 位序列号算术交付。
   I-FORWARD-TSN 推进累计 TSN，丢弃有序流中直到该 MID 的不完整消息并交付已在等待的消息，丢弃被指明的
   无序消息。与 FORWARD TSN 不同，它不按 TSN 丢弃分片：交错时，新累计 TSN 之下的分片可能属于仍在
   进行中的消息。内存上限、重复与窗口的处理与 DATA 相同；FSN 为 0 却没有 B 位的分片被丢弃（但会确认）；
   超大消息照旧中止关联，在分片到达时即检查。延续已开始消息的分片按两个内存上限中较大的一个接收（与
   下一个按序 TSN 相同），这样即使对端交错得比我们多，已开始的消息也能完成。不完整消息按
   (stream, U, MID) 有序保存，I-FORWARD-TSN 的每个条目只删除自己的区间，不扫描其他消息。
4. **调度器**（`Config::scheduler`、`Scheduler`，RFC 8260 §3）：先到先服务、轮询、按包轮询、优先级、
   公平容量和加权公平排队（默认）。使用 I-DATA 时调度单位是 chunk，使用 DATA 时是整条消息（已开始的
   DATA 消息总是整条发完）。重传始终优先。加权公平排队使用起始标签：流的虚拟完成时间按 字节 / 权重
   增长，空闲后重新有数据的流从当前虚拟时间开始，不会积攒额度。
5. **优先级**采用 RFC 8832 的数据通道优先级（越大越重要；WebRTC 使用 128、256、512、1024），而不是
   RFC 8260 套接字选项的取值：来自通道的 `ChannelOptions::priority`（新增 `with_priority`）、对端
   打开的通道在 DATA_CHANNEL_OPEN 中的值，或随时调用 `Association::set_channel_priority`。它们是
   加权公平排队的权重和优先级调度器的顺序。pion 在未设置优先级时发送 0，调度时按 256 处理。
6. **默认值。** 与 pion 一样，默认开启 I-DATA 并使用加权公平排队：默认优先级下各通道平分关联，
   交错时小消息在下一个包里就能越过大消息。应用可以用 `Scheduler::FirstComeFirstServed` 保留先到先服务，
   用 `message_interleaving: false` 保留 DATA。

## 影响

- 公开 API（akio-sctp，Internal 层级，仅新增）：`Config::{message_interleaving, scheduler}` 及其
  builder、`Scheduler`（`#[non_exhaustive]`）、`ChannelOptions::with_priority`、
  `Association::{set_channel_priority, message_interleaving}`。akio-webrtc 不变，沿用新的默认值。
- 队头阻塞：在 20 ms 的模拟链路上，一条 200 kB 的消息先于另一个通道上的 4 字节消息排队：使用 I-DATA
  和任一交错调度器时，小消息在第一个往返内到达，远早于大消息；先到先服务或不使用 I-DATA 时，小消息
  在大消息之后到达（`head_of_line_blocking`）。
- 性能：按流的队列、每条消息一块共享缓冲区、单 chunk 的接收路径和按序 I-DATA 分片的直接追加，使 SCTP 层
  比以前更快，尽管 I-DATA 每个 chunk 多 4 字节头部。gpu51 上与 59d41cc2 同轮 A/B（`quiet.sh`，CPU 2-9，7 轮交替，取中位数）：内存中的 SCTP（`examples/sctp_bench.rs`）1 KiB 消息 1.19 倍（DATA 回退 1.21 倍）、64 KiB 1.33 倍（1.14 倍）、16 KiB 无序 1.12 倍（1.08 倍）、四个通道 1.20 倍（1.07 倍）；两个回环 `Endpoint` 之间含 DTLS 的数据通道吞吐 0.986 倍（189.0 对 191.7 MB/s；此前一次为 1.009 倍，各轮相差 ±5%）：无回退。
- 测试：编解码往返，跨 TSN 回绕的交错与乱序重组，按 MID 的 I-FORWARD-TSN，各种组合及任一方发起的
  协商，队头阻塞，调度份额（均分、3:1 加权、严格优先级、FCFS 顺序、每包单一流），运行时修改优先级，
  在有损、乱序链路上可靠与部分可靠通道交错时的部分可靠性；链路测试套件在奇偶种子上分别运行 I-DATA
  与 DATA。模糊测试目标 `sctp_packet` 驱动一对 I-DATA 关联和一对 DATA 关联，种子中包含 I-DATA、
  I-FORWARD-TSN 和不匹配的 chunk。
- 互通：基于 UDP 与 pion/sctp v1.12.0（新增 `tools/interop/sctp/run.sh`：两种角色，pion 的交错开与关，
  有无丢包）；akio-webrtc 与 pion WebRTC（每个关联都协商了 I-DATA），以及与无头 Chrome 157 的双向
  offer（默认 DATA；强制打开 field trial 后的 I-DATA 也通过）。
- 未完成：与 usrsctp（Firefox）的互通，未检查；优先级之外的每流调度参数；在 akio-webrtc 的 API 中暴露
  优先级或调度器（那里的通道使用默认优先级）。
