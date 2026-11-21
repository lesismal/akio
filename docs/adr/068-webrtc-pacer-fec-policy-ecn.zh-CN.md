# ADR-068：发送节拍器（pacer）、libwebrtc 的 FEC 掩码与保护策略、RFC 8888 中的 ECN，以及更多探测

[English](068-webrtc-pacer-fec-policy-ecn.md) | 简体中文

状态：已采纳（2026-11-21）

## 背景

ADR-036、ADR-039、ADR-048、ADR-050、ADR-053 与 ADR-058 的拥塞控制与 FEC 工作留下了这些未完成项
（DEV-PLAN 第 3 节）：

- **没有 pacer。** only-webrtc 在一帧写入的那一刻就发出其全部包，关键帧不论估计值多少都是一次突发；
  只有估计器的探测簇是按节拍发出的。
- **探测**只在开始、应用受限期间和估计值大幅下降后发起；调高最大码率不会触发探测，libwebrtc 基于
  网络状态估计（network state estimate）的探测也没有。
- **FEC 掩码与保护率。** 编码器对每个组都用交织掩码，保护因子是丢包率的三倍；libwebrtc 用按组大小
  优化的表，并用一套综合丢包、每帧比特数以及（有 NACK 时）往返时间的策略。
- **ECN。** RFC 8888 报告为每个包携带一个 ECN 码点，only-rtp 能写，但 only-webrtc 总是报告 0（不支持
  ECN），估计器也不理会。
- **simulcast 线路上的 FEC** 只有 ULPFEC；**RED** 只支持 Opus，也不接受不带 ULPFEC 的视频 RED。
- **部分重建的包**（ULPFEC 保护级别，ADR-053）从不交出；VoIP 指标块（ADR-058）的 R 因子与 MOS
  一律发送"不可用"。

## 决策

### 1. Pacer（only-webrtc，`rtc/pacing.rs`）

libwebrtc 的 `PacingController`，裁剪到 sans-io peer 所需：

- 估计器运行时（`RtcConfig::enable_bwe`）且 pacing 打开（`enable_pacing`，默认打开），视频、FEC 与
  重传经一个队列发出，排空速率为**估计值的 2.5 倍**（libwebrtc 的 pace multiplier），并允许按该速率
  **40 ms 的突发额度**：放得下的帧立即发出，更大的帧（关键帧）被摊开。重传先于新媒体。**音频从不
  排队**：立即发送并计入预算（libwebrtc 的默认，使音频时延不受视频影响）。欠额上限 500 ms；一次最多
  记入 2 s 的流逝时间；最老的包将等待超过 2 s 时队列加速排空（libwebrtc 的 `drain_large_queues`）。
- transport-wide 序号与 abs-send-time **在包离开时写入**（写入时先占位，SRTP 前在 RFC 8285 扩展块中
  原地改写），因此反馈测量的是按节拍后的发送时间；RFC 8888 的发送记录也在此时登记。
- **填充（padding）**：`set_padding_rate`（默认 0）在队列为空时、在估计值以内发送近期媒体的 RTX
  副本或纯填充包。
- **探测**保持自己的节拍（ADR-050）；探测时隙优先取队列中的媒体，再为其构造填充，与 libwebrtc 的
  探测簇携带媒体一致。
- 队列有界：8192 个包、8 MB，超出时丢弃最老的媒体（统计中计为 `paced_dropped`）；写入远超估计值的
  应用会丢帧，而不是积累数秒时延。`poll_output` 的超时包含下一次发送时间，由 endpoint 的定时器驱动。
- 没有估计器时不排队：发送路径与之前相同，只是发送时间扩展在包离开时写入。

### 2. 探测（only-rtp `BandwidthEstimator`）

- `set_bounds(now, min, max)` 运行时修改上下限；最大值调高到超过原最大值和当前估计值时，在初始探测
  结束后按新最大值探测（libwebrtc 的 `SetBitrates`）。only-webrtc：`RtcConfig::set_bwe_bounds`、
  `Peer::set_bitrate_bounds`。
- **网络状态估计**（带 `NetworkStateEstimate` 的 libwebrtc `ProbeController`）：
  `set_network_state_estimate(Some(upper))` 把每次探测限制在 `max(估计值, upper)` 以内；只有结果低于
  它的 70 % 时才继续进一步探测；估计值低于它时每 5 s、延迟控制把估计值压在它的 70 % 以下时每 3 s，
  以估计值的两倍（以它为上限）探测（libwebrtc 字段试验所用的值）。未设置时，由估计器自己的**链路
  容量估计**（libwebrtc 的 `LinkCapacityEstimator`：过载时的确认速率以 0.05 平滑、探测结果以 0.5
  平滑，加三倍归一化偏差；`link_capacity()`）驱动 3 s 探测，但不限制任何东西（否则链路变快后估计值
  找不到它）。only-webrtc 不提供外部估计（浏览器默认都不发送）。
- **ECN**：`PacketResult::ecn`（来自 RFC 8888 反馈；transport-wide 反馈为 `None`）；被标记 CE 到达
  的包在基于丢包的控制中按丢失计（经典响应，RFC 3168 §5）；`ecn_counts()` 报告 ECT 与 CE 到达数。

### 3. libwebrtc 的 FEC 掩码、分组规则与保护策略（only-rtp `fec`）

- `packet_masks(k, m, FecMaskType::{Random, Bursty})`：最多 12 个包的组用 libwebrtc 的掩码表
  （`fec_private_tables_random.cc` / `_bursty.cc`，BSD 许可，脚本转换，值不变；见 `fec/tables.rs`），
  超过 12 个用交织掩码，与 `PacketMaskTable::LookUp` 一致。`FecEncoder` 使用它们（默认 random，
  与 Chrome 相同）。
- `FecProtection { delta_rate, key_rate, max_frames, mask }` 与 `FecEncoder::{set_protection,
  push_frame}`：关键帧有自己的因子；一组最多跨 `max_frames` 帧，若其所需 FEC 包与因子相差不足
  50 / 256 且包数足够（libwebrtc 的 `UlpfecGenerator`：因子大于 80 时 4 个，平均每帧 2 个包以上时再
  加 1），在帧尾提前结束。使用 ULPFEC 级别时一组只含一帧。
- `ProtectionPolicy` / `protection_factors`：libwebrtc 的 `VCMFecMethod` 与 `VCMNackFecMethod`
  （`media_opt_util.cc`），输入同 `FecControllerDefault`：码率取自 libwebrtc 的 6450 项表，按丢包率与
  每帧比特数（按分辨率调整，未知时按 704 x 576）查得；有丢包且每帧多包时 delta 帧至少 20 %；关键帧按
  其大小提升（至少两倍）；最多 50 %；再换算为保护因子；丢包率取最近 10 s 的最大值（每秒最大值）。
  有 NACK 时（混合模式）：RTT 低于 20 ms 时 delta 帧不加 FEC；一组 `2 x 帧率 x RTT` 帧（1..=6）；
  RTT 低于 200 ms 且帧小于 400 / 700 / 1000 字节（CIF / VGA / 更大）时完全不加 FEC。策略自行测量最近
  一秒的帧数、包数与字节数。
- only-webrtc：每个发送流（每个 simulcast 编码）一个策略，喂入每个写入的帧（关键帧由 depacketizer
  判断）、接收端的丢包率（报告值或被 NACK 的比例，同以前）与 RTT；NACK 取决于编解码器是否协商了
  `nack`。`set_fec_protection(min, max)` 现在限定策略给出的因子（原来是三倍丢包规则的上下限）；
  `set_fec_mask` 选择掩码表。

### 4. RFC 8888 报告中的 ECN（only-webrtc）

endpoint 的 UDP 接收路径本来就读取码点（`IP_TOS` / `IPV6_TCLASS` 控制消息，ADR-013 / ADR-035；
`Conn::rx_ecn`）；`RtcUdp::on_data` 现在随每个数据报把它交给 peer，RFC 8888 反馈逐包报告
（`CcfbReceiver::on_received` 原本就有该参数）。无需修改 only-core。来自 ICE-TCP 与 TURN 中继的数据报
报告 0。统计计入支持 ECN 的到达、CE 到达，以及对端反馈报告的 CE 标记。发送 ECT 未做：only-webrtc
的输出不携带到套接字的码点（见下文）。

### 5. simulcast 线路上的 FlexFEC、其他编解码器的 RED、不带 FEC 的视频 RED

- **simulcast 线路上的 FlexFEC**：每个编码有自己的 FlexFEC 流与保护；这些流不在 SDP 中声明（RID
  simulcast 不声明 SSRC），携带 MID 与所修复的 RID（`repaired-rtp-stream-id`，RFC 8852）；接收端按
  MID 路由，从 flexfec-03 头中找到被保护的流，因此 SDP 中只需 `flexfec-03` 负载类型。仅用于本栈之间：
  浏览器不接收 simulcast，libwebrtc 在 simulcast 下也不发 FlexFEC。
- **其他音频编解码器的 RED**：`RtcConfig::enable_audio_red(Some(n))` 为 PCMU、PCMA 与 G.722 提供并
  接受 `red/8000`（负载类型 110、112、113，列在编解码器之前，`fmtp <red> <codec>/<codec>`），每个包带
  最多两个之前的包（复用 Opus RED 的构造，ADR-048，编解码器变化时清空历史），并拆开收到的 RED。
- **不带 FEC 的视频 RED**：`FecMechanism::Red` 提供 `red`（及其 RTX）而不提供 `ulpfec`；配置为
  `Ulpfec` 时也接受只有 `red` 的对端；媒体以 RED 发出，不带 FEC 包。

### 6. 部分包与 E-model

- `FecDecoder::take_partials(ts)` 在收到另一时间戳的媒体包后（此时前一帧的 FEC 通常已到）交出只
  部分重建的包（头部和已知的开头），截断并清除 P 位。`FrameAssembler::push_partial` 用它替代丢失
  的包；其所在帧以 `Frame::partial` 发出（若 depacketizer 接受截断的负载）。only-webrtc 在非 RTP 模式
  的视频线路上这样做；该帧的 `MediaData::contiguous` 为 false；统计计入 `fec_partial`。
- `EModel`（ITU-T G.107，默认参数，Cole 与 Rosenbluth 的时延损伤近似，按编解码器 `Ie` / `Bpl`、丢包率
  与突发比计算有效设备损伤）、`mos_from_r`、`EModelScore::apply`、
  `BurstLossModel::{loss_fraction, burst_ratio}`。only-webrtc 用本周期的丢包模型、RTT 与抖动（假设抖动
  缓冲为两倍抖动）填写 VoIP 指标块的 R 因子、MOS-LQ 与 MOS-CQ，编解码器参数取 G.711 + 丢包隐藏的值
  （E-model 没有 Opus 的值）。

### API

only-rtp（内部层）均为新增，`PacketResult::ecn` 与 `Frame::partial` 除外（结构体字面量需加
`ecn: None` / `partial: false`）：`fec::{FecMaskType, FecProtection, ProtectionPolicy, PartialPacket,
packet_masks, protection_factors}`、`FecEncoder::{set_protection, protection, push_frame}`、
`FecDecoder::take_partials`、`FrameAssembler::push_partial`、
`BandwidthEstimator::{set_bounds, bounds, set_network_state_estimate, link_capacity, ecn_counts}`、
`EModel`、`EModelScore`、`mos_from_r`、`BurstLossModel::{loss_fraction, burst_ratio}`。only-webrtc 新增：
`RtcConfig::{set_bwe_bounds, enable_pacing, set_padding_rate, set_fec_mask, enable_audio_red}`、
`Peer::set_bitrate_bounds`、`FecMask`、`FecMechanism::Red`（该枚举为 `#[non_exhaustive]`）。行为变化：
估计器打开时媒体按节拍发送；FEC 保护遵循 libwebrtc 的策略（由 `set_fec_protection` 限定）；simulcast
线路提供 FlexFEC；VoIP 指标携带 R 与 MOS。

## 后果

- 测试（模拟时间）：1 Mbps 估计值下 pacer 摊开 60 kB 关键帧（立即发出 12 个包，最后一个在 156 ms，
  计算值 150 ms，任一 10 ms 窗口不超过 5 个包），5 ms 时写入的 Opus 包立即发出；无估计器或关闭
  pacing 时不排队；队列顺序、突发计算、2 s 排空、上限与填充预算；两种扩展头形式下发送时间扩展的改写。
  最大码率从 500 kbps 调到 5 Mbps 立即探测，一秒内估计值超过 1.5 Mbps。RFC 8888 反馈把 ECT(0) 与十分之一
  的 CE 带回发送端（transport-wide 反馈不带）。10 % 丢包下 PCMU RED：300 帧收到 297-298 帧，无 RED
  263-268 帧。40 字节 level 0 的 ULPFEC、15 % 丢包、无 NACK：交出 26 个部分重建的包，送出 11 个部分帧。
  FlexFEC 在无 NACK 时修复 simulcast 编码，与 ULPFEC 一样。策略：libwebrtc 表值、混合模式的 RTT 与帧大小
  规则、10 s 丢包最大值；掩码与 C++ 表对照；分组结束规则；E-model 数值（无损伤时 R 93.2 / MOS 4.41，5 %
  丢包时的 `Ie,eff`）、突发比。估计器的模拟链路：原有爬升数据不变（0.5 / 2 / 10 Mbps 分别 0.15 / 0.25 /
  0.35 s）；调高后的最大值 0.15 s 达到；4 Mbps 的网络状态估计把探测限制在该处；2 -> 10 Mbps 恢复在设置
  估计时 1.6 s、不设置时 2.1 s；20 % 的 CE 标记与 20 % 丢包一样压低估计值。
- Chrome 157（`tools/interop/webrtc/pacing.sh`，估计值上限 300 kbps，每 500 ms 请求一次关键帧）：发往
  Chrome 的 RTP 最大突发在 pacing 下为 4 个包（没有 6 个以上的突发），不 pacing 时为 7 个（15 次 6 个以上
  的突发）；Chrome 解码 300 帧中的 299-300 帧，transport-wide 与 RFC 8888 反馈均如此。`fec.sh` 在新表与
  新策略下结果不变（5 % 丢包、无 NACK 时 ULPFEC 解码 381/400 帧、FlexFEC 391/400 帧；RED、RFC 8888、
  TMMBR、按层 ULPFEC 均通过）。
- 真实丢包（`crates/only-webrtc/tests/netem.rs`，需显式开启；Linux arm64 Docker，回环接口上
  `tc netem loss 5%`，两个 `Endpoint`，去掉 NACK）：300 帧中完整收到的帧数，无 FEC 251，ULPFEC 300，
  FlexFEC 299，打开估计器与 pacer 的 FlexFEC 300。
- 基准（gpu51，与分支点同轮 A/B，两个回环 `Endpoint` 单向 VP8）：默认配置 0.999x；FEC 固定在
  64/256 时 ULPFEC 0.993x、FlexFEC 0.994x（libwebrtc 的掩码每个 FEC 包异或的包更多）。策略每秒以及
  每次收到接收报告时重新计算，而不是每帧（每帧计算的代价为 1-2 %）。
- 按节拍发送按设计会给大帧增加时延（1 Mbps 下一个关键帧需 150 ms），libwebrtc 相同。应用必须跟随
  `EgressBitrateEstimate`：写入远超估计值时，现在会在队列上限处丢帧，而不是冲垮路径。
- 未完成：发送 ECT（only-webrtc 的输出需要把每个数据报的码点一直带到 `UdpBinding::send_to` 与监听器
  的连接，属于 endpoint 传输层的改动）；外部网络状态估计来源（浏览器不发送 libwebrtc 的
  `RemoteEstimate` RTCP）；libwebrtc 的基于丢包的 BWE v2 及其限制探测的状态；不等保护（重要包）掩码；
  RTP 模式下的部分包。
