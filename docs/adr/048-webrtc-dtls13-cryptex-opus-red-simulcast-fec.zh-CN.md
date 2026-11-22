# ADR-048：akio-webrtc 的 DTLS 1.3、cryptex、加密头部扩展、Opus RED 与 simulcast 线路上的 FEC

[English](048-webrtc-dtls13-cryptex-opus-red-simulcast-fec.md)

状态：已采纳（2026-11-19）

## 背景

各个库已经具备所需部件，但 `akio-webrtc` 的 peer 并未使用：`akio-dtls` 支持 DTLS 1.3（ADR-021、
ADR-045），peer 却只跑 DTLS 1.2；`akio-srtp` 有 cryptex（RFC 9335）、RFC 6904 头部扩展加密与 MKI
（ADR-040），但没有任何协商；`akio-rtp` 有 RED（RFC 2198）与 ULPFEC（ADR-036），只接到了普通视频
线路上（ADR-039），因此音频没有冗余，simulcast 线路没有 FEC。

对照 Chrome 157 得到的事实（`tools/interop/webrtc/browser.sh`、`fec.sh`，以及经 DevTools 抓取的
offer）：

- **DTLS 1.3** 默认开启（无需 field trial）：对方提供 DTLS 1.3 时，无论 Chrome 担任哪个 DTLS 角色都
  协商 DTLS 1.3（`RTCTransportStats.tlsVersion` 为 `FEFC`，`TLS_AES_128_GCM_SHA256`），否则用
  DTLS 1.2。SDP 不变。
- **cryptex**：页面设置 `RTCConfiguration.rtpHeaderEncryptionPolicy`（"negotiate" 或 "require"）时，
  Chrome 在会话级提供 `a=cryptex`；Chrome 157 只在 `--enable-experimental-web-platform-features` 下
  暴露该选项。"require" 时拒绝不含 cryptex 的描述。RFC 6904（`urn:ietf:params:rtp-hdrext:encrypt`）
  从不提供也不接受：libwebrtc 有代码，但 Chrome 没有开关。
- **Opus RED**：Chrome 在 Opus *之后* 提供 `a=rtpmap:63 red/48000/2` 与 `a=fmtp:63 111/111`，只要协商了
  RED 就接收 RED。只有当远端描述中 `red` 排在 Opus 之前时 Chrome 才 *发送* RED（libwebrtc 以第一个非
  RED 编解码器作为发送编解码器，只有排在它前面的 RED 负载类型才会被使用）；冗余块总是紧挨主块之前的
  那些包（遇到放不下的即停止），默认一个。
- **simulcast**（基于 RID，`a=simulcast`）与其他视频线路一样携带 `red` / `rtx` / `ulpfec`；Chrome 在每
  一层自己的 SSRC 上（带其 RID）以 RED 发送 ULPFEC。FlexFEC 需要由已声明 SSRC 组成的
  `a=ssrc-group:FEC-FR`，基于 RID 的 simulcast 没有；Chrome 在 simulcast 下不发送 FlexFEC。Chrome
  不在 `fecPacketsReceived` 中统计收到的 ULPFEC（只统计 FlexFEC）。
- **MKI**：DTLS-SRTP 只在 DTLS 的 `use_srtp` 扩展中携带 MKI（RFC 5764 §4.1.1）；SDP 中没有对应属性
  （SDES `a=crypto` 的 MKI 字段属于 SDES，而 WebRTC 禁止 SDES，RFC 8827）。libwebrtc 从不提供 MKI。

## 决定

1. **DTLS 1.3**（`RtcConfig::enable_dtls13(bool)`）：peer 提供 DTLS 1.3，以 DTLS 1.2 作为回退（在
   WebRTC 配置上 `akio_dtls::Config::with_versions([Dtls13, Dtls12])`）：客户端发送 DTLS 1.2 服务器会
   以 DTLS 1.2 应答的 DTLS 1.3 ClientHello，服务器在对方提供时选择 DTLS 1.3。SRTP 密钥照旧来自（DTLS
   1.3 的）exporter；RFC 7983 解复用本已接受 DTLS 1.3 的统一头部（首字节 32-63）。**默认开启**：在核对
   Chrome 157（两种 DTLS 角色，数据通道、音频、视频、AES-GCM SRTP）、Firefox 158 与 pion（DTLS 1.2：
   两种角色均回退）之前它是可选项；`enable_dtls13(false)` 恢复为只用 DTLS 1.2。协商出的版本记入 debug
   日志并出现在统计事件中。
2. **cryptex**（`RtcConfig::enable_cryptex(bool)`，默认关闭）：在会话级提供 `a=cryptex`（与 Chrome 相
   同），并应答 offer 中会话级或媒体级的该属性。双方都声明即为协商成功；此后每个带头部扩展或 CSRC 的
   发送包都用 cryptex 加密（`akio_srtp::Context::with_cryptex`）。只要本端提供或接受 cryptex，接收
   上下文就解密 cryptex 包，这样对方在其 answer 之后、我方应用之前发出的包不会丢失。cryptex 属于
   BUNDLE 传输（一对 SRTP 上下文），每次协商后重新应用。
3. **RFC 6904**（`RtcConfig::enable_encrypted_header_extensions(bool)`，默认关闭）：offer 额外列出最能
   透露媒体或会话信息的扩展的加密变体（`a=extmap:<id> urn:ietf:params:rtp-hdrext:encrypt <uri>`），
   依次为音频电平、MID、RID、修复 RID、视频方向、播放延迟，使用各线路都未占用的单字节 ID（默认映射下
   有 5 个；不用双字节形式，因为并非所有接收方都接受）。answer 对同时以两种形式提供的扩展选择加密变体
   （RFC 6904 §4）；未开启时忽略加密变体。协商出的 ID（BUNDLE 内取并集）交给两个 SRTP 上下文
   （`with_encrypted_header_extensions`）。若同时协商了 cryptex，线上以 cryptex 为准。
4. **不在 `akio-webrtc` 中协商 MKI**：DTLS-SRTP 的 MKI 没有 SDP 机制，没有浏览器使用，两个 `akio` peer
   之间 DTLS 本就通过新握手换钥。`akio-dtls` 保留 `with_srtp_mki` 供其他 DTLS-SRTP 用户使用。
5. **Opus RED**（`RtcConfig::enable_opus_red(Option<u8>)`，默认 `None`）：`Some(n)` 时音频线路提供或接受
   `red/48000/2`（负载类型 63，`fmtp 63 <opus>/<opus>`），排在 Opus *之前*，从而让 libwebrtc 发送 RED；
   远端的 RED 仅当其所有块都是已协商的 Opus 负载类型时才被接受。接收：RED 包的冗余块代替它之前的包
   （最后一块为序列号 - 1，再前一块为 - 2 ……，时间戳由偏移得出；顺序不对或负载类型不同的块被跳过），
   以恢复包身份进入接收流（`RecvStream::receive_recovered`：已收到的包的副本被丢弃，接收报告保留修复
   前的丢包），随后主块作为该包本身。发送（`n` 为 1 或 2；0 发送普通 Opus 但仍接收 RED）：每个 Opus
   负载与至多 `n` 个先前负载一同放入 RED，与 libwebrtc 一样取最新且连续的，只要 14 位时间戳偏移与
   MTU 允许。
6. **simulcast 线路上的 FEC**：配置 `FecMechanism::Ulpfec` 时，simulcast 线路与其他视频线路一样提供并
   接受 `red` / `rtx` / `ulpfec`，每个编码有自己的 FEC 状态（其 SSRC 上的编码器、其接收报告的平滑丢包
   率、ADR-039 的速率策略）：媒体以 RED 发送，ULPFEC 块随后在该编码的 SSRC 上发送并带其 RID。收到的
   simulcast 照旧按 SSRC 修复（每个 peer 至多 8 个解码器，原为 4 个）。由于上述原因，simulcast 线路上
   不提供也不接受 FlexFEC（收发皆然）。
7. **统计**：周期统计事件新增 DTLS 版本、以 cryptex 收到的包数与由 Opus RED 恢复的包数。

## 后果

- 公共 API 只增不改：`RtcConfig` 新增四个方法。行为变化：peer 默认提供 DTLS 1.3（SDP 不变，DTLS 1.2
  对端不受影响）。其余选项默认关闭，默认 peer 的 SDP 与以前相同。
- 互通（`tools/interop/webrtc`）：Chrome 157 两种角色的 DTLS 1.3；在 Chrome 的 "require" 策略下双向
  cryptex，同时为 DTLS 1.3 与 AEAD-AES-128-GCM SRTP；双向 10 % 丢包下的 Opus RED：Chrome 隐藏的样本
  从 20 % 降到 2-3 %，服务器从 Chrome 的 RED 中取回 300-400 个包；Chrome 的三层 simulcast 带其
  ULPFEC 经过 5 % 丢包（服务器为每一层重建包）；SFU 的 simulcast 线路带我方按编码的 ULPFEC，经过
  5 % 丢包且无 NACK：Chrome 解码 301 帧中的 300 帧，没有 FEC 时该线路完全无法解码；pion 与 Firefox
  158 回退到（或协商出）正确的版本。
- 基准（gpu51 同轮 A/B，见 CHANGELOG）：默认 peer 的握手与媒体吞吐在噪声范围内不变；DTLS 1.3 握手的
  CPU 开销比 DTLS 1.2 多几个百分点。
- 未做：与浏览器的 RFC 6904（没有浏览器提供）；MKI（见上）；simulcast 线路上的 FlexFEC；Opus 以外编解
  码器的 RED 及不带 FEC 的视频 RED；仅在远端把 RED 排在前面时才发送 RED（我方只要配置并协商就发送；
  每个接收方都必须能接收）。
