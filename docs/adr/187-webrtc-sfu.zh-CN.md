# ADR-187：SFU 需要 akio-webrtc 提供的能力：RTP 转发、接收码率上限与 consent 超时

[English](187-webrtc-sfu.md) | 简体中文

状态：已采纳（2026-11-27）。akit 的 A260 与 A261（以及 A259，peer 自己的配置）。

## 背景

akit 的 WHIP/WHEP 媒体服务器（I113）要做到 fit 在 pion 上所做的：对发布者每种媒体只应答一个编解码器，
对该流的观众应答同样的编解码器；发布者的 RTP 包一到就转发给每个观众（pion 的
`TrackLocalStaticRTP.WriteRTP`：使用观众轨道的 SSRC 与 payload type，头扩展按 URI 映射）；每秒以 REMB
告诉发布者 `max_bitrate`；对端静默 `ice_timeout` 后结束会话（`ICEDisconnectedTimeout` /
`ICEFailedTimeout`）。akio-webrtc 原有接收用的 RTP 模式（`on_rtp`），但发送只接受由它自己打包的样本
（`write_media`）；从不发送 REMB（只有浏览器不理会的 TMMBR）；consent 固定 30 s 失效，并在
`Disconnected` 时关闭 peer。临时方案（每帧解包、再为每个观众重新打包；超过上限就丢弃而不告知发布者）
要多等一帧、每个观众多一份工作，而从不被告知的发布者会一直发送那些被丢弃的数据。

## 决定

1. **`Peer::write_rtp(mid, &RtpPacket)`** 原样写出 RTP 模式下收到的包。它带着该媒体行自己的 SSRC、该行
   为这个包的编解码器协商的 payload type（该编解码器的第一个；用发布者的编解码器应答的观众恰好只有
   这些）、包的负载与 marker，以及 akio-rtp 认识的扩展（音量、视频方向、传输偏移、播放延迟），使用该行
   自己的扩展 id：携带的是值而不是 id，于是"按 URI 映射"自然成立。MID、RID 与发送时间扩展
   （abs-send-time、传输层序号）是本端的，在包发出时填写；它与样本的包一样经过 pacing 并计入 TWCC。
   不加 RED 或 FEC。
2. **每个发送流的重新编号**（`rtc/forward.rs` 的 `Renumber`）。同一来源（写入的同一 SSRC）内用固定偏移
   映射扩展序号与时间戳：上游丢失的包仍是观众看得到并会 NACK 的空洞；上游稍后修复的包（SFU 的接收端
   peer 向发布者发 NACK；RTP 模式以原序号交出 RTX 修复的包）迟到地填上空洞。新来源（发布者被替换、
   另一个 simulcast 层）紧接着最后发出的序号开始，时间戳按两次到达的间隔接在最后一个之后；此后旧来源的
   包被丢弃，落后最新包太远（16384）的包也被丢弃。期间流自己占用的序号（写入的样本、媒体流上的 padding
   探测）通过移动偏移跳过。序号由转发者而不是流来选：akio-rtp 新增 `SendStream::write_with_seq`，按序号
   顺序保存重传历史（迟到的包插入、重复写入的序号替换；先按偏移查找，再二分查找），因此观众的 NACK 由
   已发出的内容应答，协商了 RTX 时用 RTX；下一次普通写入接在最大序号之后，只有最新的包会移动发送报告的
   RTP / 墙钟时间对。
3. **`RtpPacket` 携带转发所需的信息**：`mid`、`rid`、`codec` 与 `extensions`（该结构体是
   `#[non_exhaustive]`，新增字段属于增加）。`Codec::kind()` 改为公开，用于为某类包选择观众的媒体段。
4. **`Peer::set_receive_bitrate_cap(Option<u64>)`** 以 REMB（draft-alvestrand-rmcat-remb）发送该上限，
   覆盖接收到的每个媒体流（尚未收到时为信令中声明的流），立即发送一次，之后随每次 RTCP 报告（每秒一次）
   发送。akio 没有接收端估计（远端根据传输层反馈自己估计路径），所以 REMB 只携带上限；libwebrtc 把它当作
   估计值的上界。`None` 停止发送；最后一个在远端继续有效（libwebrtc 正是如此），因此要用更高的值来解除
   上限。现在也会报告收到的 REMB（`Event::Other` 的 Debug 中的
   `Other::RemoteBitrateEstimate { bitrate, ssrcs }`）。
5. **`RtcConfig::set_ice_timeouts(disconnected, failed)`**：consent 静默 `disconnected`（至少 1 s）后报告
   `Disconnected`（即 agent 的 consent 超时；完整 agent 在其中至少检查三次），静默 `failed` 后报告新增的
   `IceConnectionState::Failed`。在 `failed` 之前恢复 consent 则回到 `Connected`。当 `failed` 大于
   `disconnected` 时，在失去 consent 时关闭 peer 的服务器或 endpoint（`close_on_disconnect`，默认如此）
   改为在 `Failed` 时关闭；其他情况（以及未设置时）不变：30 s 时的 `Disconnected` 关闭它们。`Failed` 的
   截止时间是一个关于时间的定时器，在报告 `Disconnected` 时设置。
6. **peer 自己的配置**（A259）：`RtcServer::accept_offer_with(config, offer, handler)` 与
   `create_offer_with`（`Endpoint` 上同样有）用 `config` 而不是服务器的闭包构建 peer；ICE 模式、候选、
   peer 上限与连接超时仍是服务器的。

## 影响

- akit 的媒体服务器让发布者运行在 RTP 模式，在发布者的 `on_rtp` 中、在收到包的 I/O 线程上把每个包写给
  其流的观众：每个观众一次头部改写、一次复制进历史、一次 SRTP 加密。观众的 `on_keyframe_request` 转交
  给发布者（`request_keyframe`），由 akit 像 fit 一样限频；`max_bitrate` 变为
  `set_receive_bitrate_cap`（akit 保留其两秒令牌桶处理仍然超出的部分）；`ice_timeout` 变为每个会话配置上的
  `set_ice_timeouts(min(8 s, ice_timeout), ice_timeout)`。
- akio-rtp 不解析的头扩展（dependency descriptor、abs-capture-time、color space、video layers
  allocation）不会被转发：接收时即被丢弃。
- 观众对 SFU 从未收到的包（上游丢失且尚未修复）的 NACK 得不到应答；修复的包到来时填上空洞。观众的 REMB
  或 TWCC 不会传往上游。
- 代价：不使用这些调用的路径没有任何代价。RTP 模式每个包构建一个 `ExtensionValues`（不分配内存）并克隆
  RID；转发的包与打包出的包代价相同，迟到的包多一次二分查找。DEV-PLAN 第 4 节列出了基准任务应测量的
  内容。
- 测试：akio-rtp `send_stream_written_with_chosen_sequence_numbers`；akio-webrtc 的模拟
  （`rtc/tests_forward.rs`：两个发布者进入 RTP 模式的 peer，一个替换另一个，转发给一个观众，两段各丢失
  十分之一的包：每帧完整且有序，SFU 的重传应答观众、发布者的重传应答 SFU，PLI 从观众经 SFU 到发布者，
  REMB 立即一次、之后每秒一次且覆盖两个流；按 URI 的扩展、空洞、迟到的包、切换与时间戳；跳过被占用的
  序号的重新编号；consent 先 `Disconnected` 再 `Failed`、在 `Failed` 前恢复、failed 超时不更长时没有
  `Failed`；REMB 立即一次、之后每秒一次，设上限之前与 `None` 之后没有），以及基于 UDP 的 `tests/sfu.rs`（`Endpoint` 发布者与观众，`RtcServer` 以选定的编解码器应答
  每一方：两个观众都收到完整的帧，发布者被替换前后都是；PLI；REMB）。
- 未完成：转发到 simulcast 行的其他编码（`write_rtp` 写第一个）；透传未知头扩展；接收端带宽估计。
