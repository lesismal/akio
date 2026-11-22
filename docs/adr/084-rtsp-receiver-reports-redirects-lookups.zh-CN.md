# ADR-084：RTSP 接收者报告、客户端重定向、重连时重新解析；HLS 请求关键帧

[English](084-rtsp-receiver-reports-redirects-lookups.md) | 简体中文

状态：已采纳（2026-11-22）

## 背景

ADR-075 之后，书中 RTSP 一章的“不支持”里仍列着：

- **向推流端发送 RTCP 接收者报告。** RECORD 会话读取推流端的发送者报告（ADR-075），却什么也不回。
  RFC 3550 6.4 要求每个接收端报告其接收情况；推流端用这些报告做统计与码率控制（GStreamer 的 `rtpbin`
  会暴露它们，一些摄像机与编码器会按丢包调整），而 NAT 之后的 UDP 推流端收不到任何回包来保持映射。
  客户端拉流只在每次保活时向每个 UDP RTCP 端口发送一个空的接收者报告（没有报告块）。
- **客户端重定向。** `3xx` 应答让客户端以 `ClientError::Status` 失败。mediamtx 对配置为
  `source: redirect` 的路径应答 `302`，负载均衡器与摄像机管理平台会用 `301` / `302` 指向有流的服务器。
- **重连时重新解析主机名。** 客户端只在调用 `pull` / `push` 时解析一次 URL 的主机，之后每次重连都拨同一地址。
  服务器以同一名字换了地址回来（容器被重新调度、DNS 故障切换）时永远找不到。

上一个媒体会话还报告：`tools/interop/media/browser.sh` 在 main 上的 AV1 多码率步骤失败：多码率播放列表应答
`503 no rendition is ready`。

## 决定

1. **由 `Recorder` 发送接收者报告。** 服务端 RECORD 会话与客户端拉流共用的入流按媒体记录 RFC 3550 附录 A
   所计的内容（`rtp::Reception`，crate 内部）：源的 SSRC；扩展最高序列号（计入回绕；跳跃 3000 及以上时忽略，
   除非下一个包紧随其后，此时重新计数，相当于 A.1 的试用期；迟到与重复的包计入接收）；上次报告时期望与收到的包数
   （用于丢包比例）；到达间隔抖动（A.8 的整数形式，到达时间折算到轨道的 RTP 时钟）；最近一次发送者报告 NTP 时间的
   中间 32 位及其到达时刻（LSR / DLSR）。新的 SSRC 重新计数。每个媒体的报告是一个复合包：RR（一个报告块）后随
   带 CNAME（`only-media-<16 个十六进制数字>`，每会话随机）的 SDES，符合 RFC 3550 6.1 对复合包的要求。
   - **服务端**：`RtspConfig::receiver_report_interval`（新公共字段，默认 5 s，即 RFC 3550 的最小间隔；
     `Duration::ZERO` 不发送）。报告按媒体到期：首份在其首包之后半个间隔，之后每个间隔一份；报告在包路径上产生
     （每会话不设定时器），在使其到期的包之后立即发出：走轨道的交织 RTCP 通道，或由服务端的 RTCP 套接字发往推流端
     的 RTCP 端口（UDP 路由现在记住它）。推流端停止发送就收不到报告，这正是 RFC 3550 对不再发声的源的要求。
   - **客户端**：`RtspClientConfig::receiver_report_interval`（新公共字段，默认值相同）。会话的定时器（至多每
     500 ms 一次）把到期的报告经轨道的 RTCP 通道、或由其 RTCP 套接字发往服务器的 RTCP 端口，使用客户端原先空报告
     所用的 SSRC。为零时，与以前一样随保活发送空报告。
   - 代价：每个 RTP 包读一次包头、更新序列号与抖动；到达时间在每次带来 RTP 的读取（TCP）或数据报（UDP）上读一次
     时钟，因为一次读取带来的内容是同时到达的（见下）；间隔为零时没有开销。
   - 否决：每个 RECORD 会话一个定时器（为包路径本已看到的事情付出一个定时器与一个弱引用）；为已停止的源发送报告
     （RFC 3550 6.4 跳过它们）；服务端的播放端发送报告（是播放端向我们报告，而不是反过来）。
2. **客户端的重定向。** 无 IO 状态机把会话进入直播之前、任何请求收到的带 `Location` 的 `300` 至 `303`、`307`
   或 `308` 转为重定向事件（`304` 与 `305 Use Proxy`（其位置是代理）仍按拒绝处理）。会话结束（仅当某个 SETUP
   已经拿到会话时才发送 TEARDOWN），客户端在该位置重新握手：`rtsp://` URL，或同一服务器上的绝对路径。连续至多
   五次重定向；第六次以其 `ClientError::Status` 失败（循环也在此结束）。URL 中的凭据只带给同一主机与端口，除非
   该位置自带凭据（与浏览器以及 ADR-010 的 HTTP 客户端跨源时的做法一致）。`RtspClientConfig::addr` 固定的是
   客户端自己的 URL，而不是重定向指向的其他服务器。`301 Moved Permanently` 会保留给客户端之后的会话（重连从那里
   开始）；`302` / `303` / `307` 每次都从客户端的 URL 重新跟随，因为发出重定向的服务器可能在做负载均衡。重定向
   产生的会话不算重连，也不经过退避。拉流的 hub 路径全程保持预占。除文档承诺的行为外没有公共 API 变化：被拒绝的
   重定向的错误仍是原来的 `Status`。
   - 否决：服务器可能在会话中发送的 `REDIRECT` 请求（RFC 2326 10.15）；我们测试的服务器都不发送它，而迁移一个
     直播中的会话需要不带退避的重连机制。它仍应答 `501`。
3. **每个会话都重新解析。** 客户端保存 URL 而不是地址，并为每个会话重新解析主机：每次重连尝试（在其短命线程上，
   该线程本就阻塞于握手）以及每次重定向。第一个会话使用 `pull` / `push` 已解析的地址（也用于 hub 的 `PeerInfo`），
   因此不会解析两次。重连时解析失败与连接被拒一样可以重试（名字可能会回来）；第一个会话的失败仍交给调用者。
   IP 字面量与 `RtspClientConfig::addr` 跳过解析。RTMP 客户端仍拨它最初的地址（`Reconnect` 的文档现在写明两者
   的区别）。
4. **HLS 请求关键帧。** 浏览器测试的失败出在 only-media：Chrome 的 WebRTC AV1 编码器只按请求（PLI）发送关键帧，
   因此在第一个关键帧之后，WHIP 流再没有可以切 HLS 分段的关键帧，没有任何 rendition 完成一个分段，多码率播放列表
   也就永远拿不到带宽。现在 HLS muxer 在正在写的分段超过 `target_duration` 仍无关键帧时向推流端请求关键帧
   （`Subscription::request_keyframe`，WebRTC 入流将其转为 PLI；hub 按流节流），每个目标时长的媒体时间至多一次。
   没有关键帧钩子的推流端（RTMP、RTSP、SRT）不受影响。脚本没有问题。

## 影响

- 公共 API（新增，`api/only-media.txt`）：`RtspConfig::receiver_report_interval`、
  `RtspClientConfig::receiver_report_interval`（以及后者的再导出）。
- 行为变化：RECORD 会话与拉流默认发送接收者报告（5 s）；带 `Location` 的 `3xx` 被跟随而不再让客户端失败；
  自动重连的 RTSP 客户端能找到换了地址的服务器，名字解析失败也不再结束自动重连的客户端；分段过长时 HLS 向
  WebRTC 推流端请求关键帧。
- 测试：`rtp::Reception`（丢包及自上一报告块以来的比例、序列号回绕、重复包、单个跳跃被忽略而第二个重新计数、
  新 SSRC、迟到包的抖动、LSR / DLSR）与复合包；经 TCP 与 UDP 的 RECORD 会话，由手写客户端读回报告（跨回绕的
  丢包、其发送者报告的 LSR、CNAME，间隔为零时没有报告）；从脚本化服务器经 TCP 与 UDP 拉流并收集其报告；状态机的
  重定向事件（`305` 与不带位置的 `3xx` 被拒绝）；重定向 URL 与凭据；拉流与推流被两次重定向到本 crate 的服务器，
  循环在五次后结束，`301` 在重连之间被记住；一个名字（测试用解析钩子）先解析失败、再移到另一个转发器：拉流与推流
  在那里重连成功；超过目标时长的 HLS 分段向关键帧钩子请求关键帧。在 macOS 以及 gpu51 的 epoll 与
  `ONLY_TEST_BACKEND=uring` 上通过；clippy 无告警。
- 互通（`tools/interop/media/rtsp-redirect.sh`，gpu51，Docker）：
  主机网络上的 mediamtx 1.15.3：拉取路径 `moved`（`source: redirect`）时，
  经 TCP 与 UDP 跟随其 `302` 到 `rsrc` 并带有两条轨道；经 UDP 的推流与拉流保持 75 s，超过 mediamtx 60 s 的会话
  超时，仅靠拉流的接收者报告维持（57 -> 4942 与 94 -> 3355 个包；ffprobe 能读出两路推流）。GStreamer 1.24.2 的
  `rtspclientsink` 经 UDP 录制：其 RTP 会话解析了每一份报告（间隔 1 s 时 7 s 内 8 份；关于其 SSRC 的报告块、丢包 0、
  回显其发送者报告的 LSR 并附 DLSR）；经 TCP 时 8 份报告都到达了它，但 rtspclientsink 在 RECORD 模式下丢弃交织数据
  （"ignoring data message"），其 RTP 会话看不到它们。在 Docker 网络中，名字 `rtspsrv` 从 mediamtx A
  （172.31.249.10，被移除）移到 mediamtx B（.20）：在该网络的容器中运行的我们自动重连的推流与拉流各重连一次，并从 B
  收到媒体，TCP 与 UDP 均如此；同一测试用 main 的客户端会超时（它一直拨 .10）。ffmpeg 9.0.2（macOS）与 6.1.1
  （gpu51）照常经 TCP 与 UDP 向服务端推流，报告随之回传（`tests/rtsp_interop.rs`）。
- `tools/interop/media/browser.sh` 重新通过（Chrome 157 无头，macOS）：hls.js 播放 AV1 码率阶梯并切换
  rendition；那一轮 Chrome 自带的播放器也播放成功（仅供参考）。
- 代价：与 main 在 gpu51 上同轮 A/B（`quiet.sh`，单个固定核心，交替多轮，取中位数，head / base）：RTSP 拉流 1.024、RTSP RECORD 入流 1.087、RTMP 拉流 0.998（`tests/client_bench.rs`，9 轮）；`bench_segmenting`（7 轮）MPEG-TS 0.981、MPEG-TS LL-HLS 0.995、fMP4 1.015、fMP4 LL-HLS 1.013、AES-128 0.998 至 1.001、SAMPLE-AES MPEG-TS 1.002、`cbcs` 1.004（分段超过目标时长后，关键帧请求是每包一次比较）。RECORD 的开销（每个 RTP 包 +18 ns）来自接收者报告所需的到达时间：每次带来 RTP 包的读取读一次时钟，而该基准每次读 255 字节，约每包一次读取；更大的读取让多个包共用一次时钟读取，`receiver_report_interval` 为零时完全跳过。最初每包读一次时钟并用 u128 除法换算的版本为 1.113（拉流）与 1.104（RECORD）。
- 未做：服务器的 `REDIRECT` 请求（见上）；RTSP 2.0、RTSPS 与 HTTP 隧道、组播与拖动仍不在范围内；扩展报告
  （RFC 3611）以及服务端播放端的报告；RTMP 客户端重连时仍拨最初的地址。

## 更新（2026-11-22）

上文的两项已在 [ADR-080](080-rtsp-server-redirect-rtmp-lookups.zh-CN.md) 中完成：服务器在会话中发送
`REDIRECT`（`RtspServer::redirect_session` / `redirect_path`），客户端跟随它而不再回答 `501`（推翻决定 2 中的
否决）；RTMP 客户端在每次重连时重新解析主机名，并与 RTSP 客户端一样依次拨该名字的各个地址，直到有一个连上。
