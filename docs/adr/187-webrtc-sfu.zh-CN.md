# ADR-187：SFU 需要 akio-webrtc 提供的能力：接收码率上限与 consent 超时

[English](187-webrtc-sfu.md) | 简体中文

状态：已采纳（2026-11-27）。akit 的 A261。

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

1. **`Peer::set_receive_bitrate_cap(Option<u64>)`** 以 REMB（draft-alvestrand-rmcat-remb）发送该上限，
   覆盖接收到的每个媒体流（尚未收到时为信令中声明的流），立即发送一次，之后随每次 RTCP 报告（每秒一次）
   发送。akio 没有接收端估计（远端根据传输层反馈自己估计路径），所以 REMB 只携带上限；libwebrtc 把它当作
   估计值的上界。`None` 停止发送；最后一个在远端继续有效（libwebrtc 正是如此），因此要用更高的值来解除
   上限。现在也会报告收到的 REMB（`Event::Other` 的 Debug 中的
   `Other::RemoteBitrateEstimate { bitrate, ssrcs }`）。
2. **`RtcConfig::set_ice_timeouts(disconnected, failed)`**：consent 静默 `disconnected`（至少 1 s）后报告
   `Disconnected`（即 agent 的 consent 超时；完整 agent 在其中至少检查三次），静默 `failed` 后报告新增的
   `IceConnectionState::Failed`。在 `failed` 之前恢复 consent 则回到 `Connected`。当 `failed` 大于
   `disconnected` 时，在失去 consent 时关闭 peer 的服务器或 endpoint（`close_on_disconnect`，默认如此）
   改为在 `Failed` 时关闭；其他情况（以及未设置时）不变：30 s 时的 `Disconnected` 关闭它们。`Failed` 的
   截止时间是一个关于时间的定时器，在报告 `Disconnected` 时设置。

## 影响

- akit 的媒体服务器用 `set_receive_bitrate_cap(Some(max_bitrate))` 为每个发布者设上限（仍超出的部分由其
  两秒令牌桶处理），并在每个会话的配置上设置 `set_ice_timeouts(min(8 s, ice_timeout), ice_timeout)`
  （A259 的 `accept_offer_with`）。
- 代价：不使用这些调用的路径没有任何代价：失去 consent 期间 peer 的定时器多一个截止时间，设了上限的 peer
  每秒随报告多一个 REMB，每收到一个 REMB 一个事件。
- 测试：akio-webrtc 的模拟（`rtc/tests_forward.rs`：consent 按超时先 `Disconnected` 再 `Failed`、在
  `Failed` 前恢复、failed 超时不更长时没有 `Failed`；REMB 立即一次、之后每秒一次，覆盖接收的两个流，
  设上限之前与 `None` 之后没有）。
- 未完成：接收端带宽估计。
