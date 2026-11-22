# ADR-080：RTSP 服务器的 REDIRECT 与客户端跟随；RTMP 重连时重新解析

[English](080-rtsp-server-redirect-rtmp-lookups.md) | 简体中文

状态：已采纳（2026-11-22）

## 背景

ADR-084 在 only-media 的 RTSP 与 RTMP 客户端里留下两件未做的事：

- **服务器的 `REDIRECT`。** RFC 2326 10.15 允许服务器让会话中的客户端改去别处：一个带 `Location`、可选带
  `Range`（何时生效）的 `REDIRECT` 请求。运维人员为维护而摘下一台服务器，或把负载分流到另一台时，在 RTSP 1.0
  里除了直接断开之外，没有别的办法迁移正在播放和推流的客户端。我们的服务器不能发送它，我们的客户端用 `501`
  回答它。ADR-084 当时否决了它，因为我们测试的服务器都不发送它，而迁移一个活动会话需要不带退避的重连机制。
- **RTMP 重连时重新解析。** 自 ADR-084 起 RTSP 客户端为每个会话重新解析主机名；RTMP 客户端只在
  `push` / `pull` 中解析一次，每次重连都拨同一个地址，所以服务器以同一名字出现在别处（容器被重新调度、DNS
  故障切换）时永远找不到它。两个客户端在第一个地址拒绝连接时都不会尝试该名字的其他地址。

## 决定

1. **服务器发送 `REDIRECT`。** `RtspServer` 维护其会话列表：连接在其流建立时（播放端的第一个 SETUP、推流端的
   ANNOUNCE）加入，在 TEARDOWN 或关闭时离开。新增公共 API：
   - `RtspServer::sessions() -> Vec<RtspSessionInfo>`：id（即 `Session` 头中的）、hub 路径、对端地址、
     是否在录制、是否已被重定向。
   - `RtspServer::redirect_session(id, &Redirect) -> bool` 与
     `RtspServer::redirect_path(path, &Redirect) -> usize`（该路径的所有会话：播放端及其推流端）。
   - `Redirect { location, at: Option<SystemTime>, grace }`（`Redirect::new(location)`、`.at`、
     `.grace`；默认宽限 10 s）：请求为 `REDIRECT <会话 URL> RTSP/1.0`，带服务器自己的 `CSeq`、`Session`、
     `Location`，有 `at` 时还带 `Range: clock=YYYYMMDDThhmmss.fffZ-`（RFC 2326 3.7）。
   - **干净地结束。** 发出请求后会话继续播放或录制：跟随的客户端在迁移生效时拆除会话并到新位置建立，播放端
     因此可以无缝切换。被重定向会话的 TEARDOWN 得到应答后，服务器在应答发出后关闭连接。不跟随的客户端（下面的
     第三方客户端都不跟随）在迁移生效（有 `at` 时为 `at`，否则为请求时）后 `grace` 被关闭，由一个定时任务完成；
     该任务只在会话仍在列表中、且没有更晚的重定向取代本次时才关闭连接。客户端对请求的应答被读取并忽略。
   - 开销：每个会话一次 map 插入与删除，所用的锁媒体路径从不获取。
   - 否决：请求发出后立即关闭连接（跟随的客户端在建立新会话之前还需要旧会话，RFC 2326 要求它 TEARDOWN）；
     `redirect_path` 中按会话的位置模板（需要的调用方可通过 `sessions()` 与 `redirect_session` 实现）；
     记录客户端的应答（我们试过的客户端在其中都没有说出有用的东西：`501`、`200` 或不回答，见下）。
2. **客户端跟随 `REDIRECT`。** sans-IO 状态机在活动会话中以 `200` 加会话回答服务器的 `REDIRECT` 请求（会话
   尚未活动时 `455`，没有可用的 `Location`——`rtsp://` URL 或绝对路径——时 `400`，其 `Session` 不是我们的
   时 `454`），并发出迁移事件：位置（凭据只随同一服务器带上，与 3xx 相同）与时间，由 `Range` 起点得出：
   `clock=` 为 UTC 时间，`npt=` 从 PLAY / RECORD 应答起算，没有或已过去则立即（最多一天）。会话的定时器
   （至多 500 ms）在时间到达时结束会话：TEARDOWN，关闭连接。随后客户端立即在新位置开始一个会话，在自己的线程
   上、不经退避，使用 `RtspClientConfig::reconnect` 的 engine；它计入 `reconnects()`。若该会话失败，照常
   重连，从客户端的 URL（或被记住的 `301`）开始：发出重定向的服务器可能是负载均衡器，崩溃的目标不应让客户端
   回不去。在 `REDIRECT` 之后、生效时间之前连接被关闭，也会迁移。没有 `reconnect` 时（没有可拨号的 engine，
   `pull` / `push` 只借用 `&Engine`）客户端以新增的 `ClientError::Redirected(location)` 结束，调用方可以在
   那里重新开始。
   - 否决：在会话活动之前就执行 `REDIRECT`（握手期间由 3xx 路径处理；此时的请求回答 455）；让重定向对之后的
     重连永久生效。
3. **RTMP 客户端的重新解析与地址遍历。** `push` / `pull` 解析主机的全部地址（IP 字面量与
   `RtmpClientConfig::addr` 同前）。每次重连尝试都在一个短命线程上重新解析名字（定时器线程不能阻塞）；重连时
   解析失败与连接被拒一样会重试（`ClientError::Resolve` 现在可重试；第一次解析的失败仍交给调用方）。在一次尝试
   内，连接被拒或超时会立即拨列表中的下一个地址（新的连接代次，前一个的迟到应答被忽略）；列表用尽则本次尝试失败。
   遍历需要能在 I/O 与定时器线程上拨号的 engine，即重连的那个，所以没有 `reconnect` 时与以前一样只拨第一个地址。
   `RtmpClient::addr` 现在是最近拨号的地址。RTSP 客户端对每个会话以同样方式遍历地址（那里总有调用方的
   engine），两个客户端共用一个解析函数（`reconnect::lookup`，crate 内部，`.test` 下的名字有测试解析器）。

## 后果

- 公共 API（只有新增，`api/only-media.txt`）：`rtsp::Redirect`、`rtsp::RtspSessionInfo`、
  `RtspServer::{sessions, redirect_session, redirect_path}`、`ClientError::Redirected`（RTSP；
  `ClientError` 是 `#[non_exhaustive]`）。
- 行为变化：RTSP 客户端跟随服务器的 `REDIRECT`（或以 `Redirected` 结束），不再回答 501；两个客户端在第一个
  地址连不上时会拨该名字的其他地址；RTMP 客户端能找到迁移了的服务器，名字不再能解析也不会让重连中的 RTMP
  客户端结束；`RtmpClient::addr` 在重连之间可能变化。
- 测试：`Range` 时间（`clock=` 跨闰年的双向转换、`npt=` 的各种形式、畸形值）；状态机对 `REDIRECT` 的回答
  （立即、一个未来的时钟时间、npt、已过去的时间；455、400、454）；本 crate 的服务器经 TCP 与 UDP 把重连中的
  拉流与推流迁移到第二台服务器（推流在其 `Range` 时间迁移，不会提前），第一台服务器的列表清空，没有重连的客户端
  以该位置结束；忽略请求的原始客户端在宽限后被关闭，并检查它收到的请求；RTSP 会话越过被拒的地址遍历名字的地址；
  RTMP 拉流与推流越过被拒的地址，随后名字不再能解析（重试），再迁移。
- 互通（`tools/interop/media/rtsp-server-redirect.sh`，gpu51，Docker）：ffmpeg 6.1.1（gpu51，经 TCP 与 UDP 播放和录制；macOS 上的 9.0.2 亦然，只是未试经 UDP 录制），对我们服务器的 `REDIRECT` 回答 `501` 并照常继续；GStreamer 1.24.2 的 `rtspsrc` 与 `rtspclientsink`（TCP、UDP）回答 `200` 并照常继续；从我们服务器拉流的 mediamtx 1.15.3（路径的 `source`，TCP 与 UDP）不回答，立即拆除会话并重新拉同一 URL。它们都不迁到新位置；我们的服务器在其 TEARDOWN 时或请求后 4 s（测试的宽限期）结束了每一个这样的会话。我们的客户端被我们的服务器迁到 mediamtx：拉流继续从那里带来媒体（检查中 310 至 335 个包），在 `Range` 时间迁移的推流可从 mediamtx 读回，TCP 与 UDP 均如此。RTMP：在 Docker 网络中名字 `rtmpsrv` 从 mediamtx A（172.31.248.10，已移除）迁到 mediamtx B（.20），在该网络的容器中运行、自动重连的推流与拉流都拨到了 .20（B 的路径等待推流回来期间，拉流重连了 11 次）。未试 live555（openRTSP）：Ubuntu 24.04 与 Debian 12 都不再打包它。
- 开销：BENCH
- 未做：RTSP 2.0 的 `PLAY_NOTIFY` 及其重定向、RTSPS、HTTP 隧道、组播与拖动仍不在范围内；RTMP 客户端只在设置了
  `reconnect` 时遍历地址。
