# ADR-042：SCTP HEARTBEAT、对端重启、零校验和与入向重置请求

[English](042-sctp-heartbeat-restart-zero-checksum.md) | 简体中文

状态：已采纳（2026-11-19）

## 背景

`only-sctp` 是自研 WebRTC 协议栈的数据通道层。它应答 HEARTBEAT，却从不主动发送，因此空闲关联既测不到
RTT，也发现不了已经消失的对端：没有在途数据时没有任何计时器运行，关联一直“在线”，直到 DTLS 或 ICE
放弃。已建立的关联收到 INIT 时直接忽略，重启了 SCTP 协议栈的对端（RFC 9260 §5.2.2）再也无法恢复。
每个包都带 CRC-32C，尽管 DTLS 已经认证了它；RFC 9653 允许两端约定改发零校验和，dcSCTP（Chrome）和
pion/sctp 都已实现。除 Outgoing SSN Reset 与增加流之外的 RE-CONFIG 请求（Incoming SSN Reset、
SSN/TSN Reset，RFC 6525 §5.2.3-4）一律拒绝。此外从未与 Firefox 使用的 usrsctp 互通测试过。

WebRTC 在一条 DTLS 连接上只跑一个关联，不使用多宿主、AUTH（RFC 4895）、ASCONF（RFC 5061）和 ECN，
它们仍不在范围内。

## 决定

1. **HEARTBEAT**（RFC 9260 §8.3，`Config::heartbeat_interval`，默认 30 s，`None` 关闭）。关联建立后，
   没有在途 DATA 达 HB.interval + RTO 时发送 HEARTBEAT，12 字节的 Heartbeat Information 是序号加本端
   tag；有在途数据时由 T3-rtx 监视路径，计时器只是重新设定。匹配的 HEARTBEAT ACK 是一次 RTT 测量
   （与 DATA 一样更新 SRTT / RTTVAR / RTO，`Association::rtt`）并清零错误计数。RTO 内未获应答的
   HEARTBEAT 计一次错误，RTO 加倍并立即发送下一个；错误计数与 T3-rtx 超时共用，超过
   `max_retransmissions` 后关联失败（ABORT，`Closed`）。单路径时 Path.Max.Retrans 与
   Association.Max.Retrans 是同一个数：对端消失后，空闲关联在最后一次交互后 60-150 s 失败（30 s +
   RTO，再约 70 s 退避），与繁忙关联经 T3-rtx 失败的时间相当。间隔不加抖动：只有一个目的地址，不存在
   多条路径的 HEARTBEAT 同步问题。只在 ESTABLISHED 状态发送（关闭阶段有自己的 T2 计时器）。
2. **对端重启**（RFC 9260 §5.2.2、§5.2.4）。state cookie 现在还带有发出它的 INIT ACK 的 tag 和初始
   TSN，以及 Tie-Tags。已建立的关联收到 INIT 时，回复的 INIT ACK 带新的 tag 和初始 TSN（由 cookie 密钥
   和该 INIT 经 HMAC 派生，重传的 INIT 得到相同的值），以当前双方 tag 作为 Tie-Tags；此时什么都不改变。
   COOKIE ECHO 按其 cookie 中的 tag（而非当前 tag）校验，并按 §5.2.4 的表分类：情形 A（双方 tag 都是新的，
   Tie-Tags 与当前 tag 一致）是重启：每个通道收到 `ChannelClose`（对端已失去它们），丢弃已排队和未确认
   的数据，发送端、接收端和 RE-CONFIG 状态以 cookie 中的 tag 和 TSN 重新开始，发出 COOKIE ACK，随后是
   `Event::Restarted`。情形 D（重复）照旧回复 COOKIE ACK；已建立关联上的情形 B 与情形 C 丢弃（我们处理
   INIT 碰撞时每端只用一个 tag，对端的 tag 不会合法地改变）。在 SHUTDOWN-ACK-SENT 状态拒绝重启，回复
   SHUTDOWN ACK 和错误 "Cookie Received While Shutting Down"；其他关闭状态下中止关联（对端那一侧已经
   不存在）。`Event` 改为 `#[non_exhaustive]`。
3. **零校验和**（RFC 9653，`Config::zero_checksum`，默认开启）。INIT 和 INIT ACK 带 Zero Checksum
   Acceptable（0x8001），EDMID 为 1，即 "SCTP over DTLS"；开启时，校验和字段为 0 的包不计算 CRC 直接接受
   （其他值仍必须是正确的 CRC-32C）。对端也声明 EDMID 1 时（`Association::zero_checksum`），已建立关联
   上发出的每个包都使用零校验和；INIT、INIT ACK、COOKIE ECHO 以及其他验证 tag 的包始终带 CRC。该标志
   与其他标志一起放在 state cookie 中。`udp_peer`（明文 UDP）默认关闭它。
4. **Incoming SSN Reset Request**（RFC 6525 §5.2.3）：对端请求我们重置出向流（列表为空表示全部）。
   其中的通道如同调用了 `close_channel` 一样关闭；没有通道的流也一并重置。应答是我们对这些流的
   Outgoing SSN Reset Request，在它们已排队的消息都分配了 TSN 之后发出，其 Re-configuration Response
   Sequence Number 填该请求的序号；重传的请求会让它重发。重置已在途或已完成的流无需处理；完全无需处理的
   请求得到 "Success - Nothing to do"；前一个尚未完成时的第二个请求得到 "In progress"。
5. **SSN/TSN Reset Request**（RFC 6525 §5.2.4）：在我们没有在途数据、也没有分配了一半 TSN 的消息时执行
   （此前回复 "In progress"，不丢数据，对端会重试）：响应带 Sender's Next TSN（我们的，不变）和
   Receiver's Next TSN（我们的累计 TSN + 1 + 2^31），接收端从后者重新开始（相当于一个覆盖所有流的
   FORWARD TSN，延迟的入向重置随之执行），双向所有 SSN / MID 归零。重传得到相同的响应。我们从不发送此请求。
6. **与 Firefox / usrsctp 互通**（新增 `tools/interop/webrtc/firefox.sh`）：用基于 gorilla/websocket 的
   小型 Go 程序通过 WebDriver BiDi 驱动无头 Firefox（Firefox 已不再支持 DevTools Protocol）。两个 offer
   方向都测，usrsctp 因此处于 SCTP 的两种角色。

## 影响

- 公共 API（only-sctp，Internal 层级）：`Config::{heartbeat_interval, zero_checksum}` 及其 builder，
  `Association::{rtt, zero_checksum}`，`Event::Restarted`；`Event` 现为 `#[non_exhaustive]`（match
  需要通配分支；only-webrtc 本来就有）。only-webrtc 不变并获得新的默认值；其 `webrtc-interop` 示例新增
  `ONLY_INTEROP_BIND` 用于指定客户端本地地址。
- cookie 从 37 字节变为 49 字节；此前生成的 cookie 不再能通过校验（cookie 只存活一次握手）。
- 测试：空闲链路上 HEARTBEAT 测得 RTT，对端消失后空闲关联失败（60-150 s），关闭 HEARTBEAT 时不会失败，
  双向各丢 15 % 的链路上持续 30 分钟的 HEARTBEAT；有损链路上四种组合的零校验和协商（双方都提供时才用零，
  否则带 CRC）；双方都有排队数据时的对端重启：通道关闭、流 ID 复用、之后双向收发与优雅关闭，DATA 与
  I-DATA 都测；没有 COOKIE ECHO 跟随的游离 INIT 不改变任何东西；Incoming SSN Reset 由我们的 Outgoing
  请求作答（重传、两端关闭通道、无通道的流）；有在途数据时 SSN/TSN Reset 为 in progress，之后执行，
  新 TSN、SSN 0 的数据被接受，我们的 SSN 归零；关闭过程中拒绝重启；新参数与零校验和的编解码。
- 模糊测试：`sctp_packet` 的各关联接受零校验和，随机字节无需修正 CRC 即可到达解析器；新增种子覆盖
  HEARTBEAT / HEARTBEAT ACK、一次完整的对端重启以及各种 RE-CONFIG 请求和 b 的应答（共 941 个种子）。
  gpu51 上运行 11 分钟，151 万次，无崩溃。
- 互通：经 UDP 对 pion/sctp v1.12.0，双方都提供零校验和，两种角色，有无丢包
  （`tools/interop/sctp/run.sh`）；Firefox 158（usrsctp）两个 offer 方向：有序与无序/不可靠回显，70 kB 与
  200 kB 消息，空消息，空闲 150 s（only-sctp 的 HEARTBEAT 得到 usrsctp 应答：否则此前关联就已失败），
  Firefox 关闭通道（双向流重置）后在复用的 ID 上新开通道。Firefox 158 与 Chrome 157 都不提供零校验和
  （Chrome 的 dcSCTP 已实现，但处于默认关闭的实验中），因此在浏览器中仍使用 CRC-32C；无头 Chrome 157
  原样通过 `browser.sh`。在 Linux 上即使设置 `media.peerconnection.ice.loopback`，Firefox 也不收集
  回环候选，因此脚本可通过 `IP=` 指定局域网地址。
- 性能：使用零校验和后，数据路径两端都不再计算 CRC-32C。在 gpu51 上与 46f25f81 同轮 A/B（`quiet.sh`，
  CPU 2-9，7 轮交替，取中位数），内存中的 SCTP（`examples/sctp_bench.rs`，两端都是 only-sctp）：1 KiB 消息
  1.21x（DATA 1.21x），64 KiB 1.31x（1.24x），16 KiB 无序 1.27x（1.24x），四个通道 1.25x（1.20x）；两个
  回环 `Endpoint` 之间含 DTLS 的数据通道吞吐 1.003x（189.6 对 189.1 MB/s，DTLS 占主导）：无退化。空闲时
  HEARTBEAT 的开销是每 30 s 每个方向一个包。
- 未做：多宿主、AUTH、ASCONF、ECN（WebRTC 均不使用）；主动发送 Incoming 或 SSN/TSN Reset 请求；cookie
  有效期（cookie 在 DTLS 内传输，外部无法重放）。
