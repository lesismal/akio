# RTSP 与 WHIP/WHEP

`akio-media` 在同一个流 `Hub` 前提供 RTSP 服务和 WHIP/WHEP 信令端点，与 RTMP、HTTP-FLV、
HLS、SRT 共用：摄像头用 RTSP 推流后可以用其他任何协议播放，RTMP 编码器推的流也能在任意 RTSP
播放器里播放。每种协议都转换成 `akio_media::av` 的规范包（AVCC 视频、裸 AAC），协议之间互不感知。

## 一个 hub，一个钩子

```rust,ignore
{{#include ../../../../crates/akio-media/examples/guide-media-rtsp.rs:hub}}
```

`HubConfig::on_publish` 和 `on_subscribe` 一次性为所有推流和播放协议做鉴权；它们拿到的
`PeerInfo` 包含协议名、对端地址和 URL 的查询串（token 通常放在这里）。

## RTSP 服务端

```rust,ignore
{{#include ../../../../crates/akio-media/examples/guide-media-rtsp.rs:rtsp}}
```

- `rtsp://host:port/live/cam` 播放或录制 hub 中的流 `live/cam`。
- 播放端：`DESCRIBE`（SDP 中带 `sprop-parameter-sets` / `sprop-vps/sps/pps` 和 AAC 的
  `config`），逐轨 `SETUP`，支持 `RTP/AVP/TCP`（在 RTSP 连接上交织）和 `RTP/AVP`（UDP 单播，
  使用 `listen_udp` 绑定的端口），以及 `PLAY`、`PAUSE`、`TEARDOWN`、`GET_PARAMETER` /
  `SET_PARAMETER` 保活。播放从 hub 缓存的 GOP 开始，并收到 RTCP 发送者报告；TCP 播放端跟不上时
  退化为只发关键帧（`hub::Dropper`），超过 `RtspConfig::max_write_queue` 则断开。
- 推流端：`ANNOUNCE` 预占路径（第二个推流者立即收到 453），带 `mode=record` 的 `SETUP`，然后
  `RECORD`。参数集一旦已知（来自 SDP 或码流内；VP8、VP9、AV1 来自第一个关键帧）流即上线。RTP 只携带显示时间，因此服务端为带
  B 帧的视频推算解码时间（估计重排深度，不缓存帧）。各轨道按推流端的 RTCP 发送者报告对齐（`RtspConfig::rtcp_sync`，
  默认开启；交织 RTCP 通道、复用在 RTP 通道上的 RTCP、UDP 端口），与下文客户端拉流相同，音视频因此保持采集时的偏移。
  服务端每隔 `RtspConfig::receiver_report_interval`（5 s；为零则不发）在每条轨道的 RTCP 通道或端口上向推流端发送
  RTCP 接收者报告（RFC 3550 6.4.2）：推流端的 SSRC、丢包比例与丢包数、最高序列号、到达间隔抖动、最近一次发送者
  报告的 NTP 时间及其后经过的时间，后随带 CNAME 的 SDES。
- 编解码：H.264（单 NAL、STAP-A、FU-A）、H.265（单 NAL、AP、FU）、VP8（RFC 7741）、VP9（RFC 9628）、
  AV1（AOM 的 RTP 负载格式；这三种经 akio-rtp 处理，缺包的帧被丢弃）、AAC（`mpeg4-generic` `AAC-hbr`）、
  Opus、G.711。
- 认证：`RtspConfig::credentials` 开启 Digest（MD5）与 Basic。
- 超时：首个请求，以及任何已开始的请求，须在 `request_timeout`（10 s）内收齐。`Session: <id>;timeout=<s>`
  通告 `session_timeout`（60 s）并强制执行：客户端这么久什么都没发送（请求、交织的 RTCP，UDP 传输时来自其
  端口的数据报）的会话被拆除。
- 迁移会话：`RtspServer::sessions()` 列出会话（id、路径、对端、是否录制）；
  `redirect_session(id, &Redirect)` 与 `redirect_path(path, &Redirect)` 向其客户端发送 `REDIRECT` 请求
  （RFC 2326 10.15），用于为维护而摘下服务器或分流负载：

  ```rust,ignore
  use std::time::{Duration, SystemTime};
  use akio_media::rtsp::Redirect;

  // live/cam 的所有播放端与推流端，30 s 后迁到另一台服务器。
  let moved = srv.redirect_path("live/cam", &Redirect::new("rtsp://198.51.100.8:8554/live/cam")
      .at(SystemTime::now() + Duration::from_secs(30)));
  ```

  `at` 以 `Range: clock=<UTC>-` 发出。会话继续播放或录制，直到客户端拆除它（服务器随后关闭连接），或直到迁移生效
  后 `grace`（10 s）过去，由服务器关闭：忽略该请求的客户端同样被干净地结束。我们试过的第三方客户端都不跟随它：ffmpeg 回答 `501`、
  GStreamer 回答 `200`，两者照常继续直到宽限期把它们关闭；从服务器拉流的 mediamtx 拆除会话并重新拉同一 URL
  （`tools/interop/media/rtsp-server-redirect.sh`）；本 crate 的客户端会跟随（见下）。

已用 ffmpeg 9 测试（`crates/akio-media/tests/rtsp_interop.rs`）：

```text
ffmpeg -re -f lavfi -i testsrc=size=320x240:rate=25 -f lavfi -i sine -c:v libx264 -c:a aac \
    -f rtsp -rtsp_transport tcp rtsp://127.0.0.1:8554/live/cam      # 也可 -rtsp_transport udp
ffmpeg -re ... -c:v libx265 -c:a libopus -f rtsp -rtsp_transport udp rtsp://127.0.0.1:8554/live/cam
ffprobe -rtsp_transport tcp rtsp://127.0.0.1:8554/live/cam            # 以及 udp
ffmpeg -rtsp_transport udp -i rtsp://127.0.0.1:8554/live/cam -f null -
```

同一文件还以发送者报告录制：报告把音频放在视频之后 500 ms，而数据包同时到达（TCP、复用在 RTP 通道上的 RTCP、
UDP；报告在媒体之前与在中途）：hub 中的时间跟随报告，相差 60 s 的报告被忽略，关闭 `rtcp_sync` 时按到达计时。
另一个测试读取录制会话经 TCP 与 UDP 发回的接收者报告（跨序列号回绕的丢包、发送者报告的 LSR / DLSR）。GStreamer 的
`rtspclientsink` 经 TCP 与 UDP 向服务端录制，其 RTP 会话记录下每一份报告（`tools/interop/media/rtsp-redirect.sh`）。

## WHIP 与 WHEP

```rust,ignore
{{#include ../../../../crates/akio-media/examples/guide-media-rtsp.rs:whip}}
```

`WhipServer::routes` 向 akio-http 的 `Router` 添加：

| 请求 | 应答 |
| --- | --- |
| `POST /whip/<path>`，带 `application/sdp` offer | `201 Created`、answer SDP、`Location: /webrtc/session/<id>` |
| `POST /whep/<path>` | 同上，播放 hub 中的流 `<path>`（未上线时 404） |
| `PATCH <location>`，`application/trickle-ice-sdpfrag` | 204；引擎不支持 trickle 时 405 |
| `DELETE <location>` | 200：会话结束（WHIP 推流者下线） |
| `OPTIONS` | CORS 预检，带 `Accept-Post: application/sdp` |

WHIP 推流通过 hub 预占路径，因此 `on_publish` 同样生效；URL 没有查询串时，
`Authorization: Bearer <token>` 以 `token=<token>` 的形式传给钩子。媒体本身（ICE、DTLS-SRTP、
RTP）由 `WebRtcEngine` 负责：其 `publish` 拿到预占的 `Publisher`，`play` 自行订阅 hub。占位实现
`NoMedia` 对所有 offer 返回 `501 Not Implemented`。`WhipConfig::max_sessions`（256）限制并发会话，
超出后的 offer 得到 503；对端未经 `DELETE` 就结束的会话会释放其名额。

### WebRTC 媒体（`webrtc` feature）

开启 cargo feature `webrtc` 后，`akio_media::webrtc::RtcMedia` 即为引擎，运行在 `akio-webrtc` 的
`RtcServer` 上（单个 UDP 端口上的 ICE-lite）：

```rust,ignore
use akio_media::webrtc::{RtcMedia, RtcMediaConfig};

// 浏览器访问 UDP 监听器所用的地址，写入每个 answer。
let rtc = RtcMedia::rtc_server(vec!["203.0.113.7:8189".parse()?]);
let media = RtcMedia::new(rtc.clone(), RtcMediaConfig::default());
let whip = WhipServer::new(hub.clone(), Arc::new(media), WhipConfig::default());
// 在 Listener::udp("0.0.0.0:8189") 上服务 `rtc`，并通过 HTTP 提供 `whip.routes(router)`
```

- **WHIP 推入**：H.264 与 H.265（RTP 上的 Annex B）转为 AVCC，配置记录由带内参数集构建；VP8 与 VP9 帧以及
  AV1 temporal unit 原样透传，配置记录与尺寸取自每个关键帧；Opus、PCMU 与 PCMA 原样透传。所有媒体行就绪后
  流上线（或在 `track_timeout`，5 s 后以已就绪的行上线）；此前到达的数据保存在 `max_pending_packets` /
  `max_pending_bytes` 之内。G.722 不为 hub 所承载：只含它的 offer 得到 406。
- **WHEP 播出**：ICE 与 DTLS 建立后才为观众订阅，从下一个关键帧开始（设置 `play_gop_cache` 则从缓存的
  GOP 开始），H.264/H.265 在每个关键帧前带上参数集，VP8、VP9、AV1、Opus 与 G.711 原样发送。AAC 与 MP3 不发送（不转码）：
  面向 WebRTC 观众请推 Opus，并且视频不要 B 帧（`-bf 0`）。
- **关键帧**：观众的 PLI 或 FIR 交给 hub（`Subscription::request_keyframe`），hub 每
  `HubConfig::keyframe_request_interval`（500 ms）至多转给推流者一次；WHIP 推流者再把它变成发给其发送端的
  PLI。观众加入时若没有缓存的关键帧，会立即请求。

`crates/akio-media/examples/whip-server.rs` 可直接运行；`tools/interop/webrtc/media.sh` 用 ffmpeg 的 WHIP
封装器与 pion 验证它（WHIP 推入、WHEP 播出、PLI 往返、RTMP 推入到 WHEP 播出），
`tools/interop/media/browser.sh` 用 headless Chrome 验证（通过 WHIP 推 VP8、VP9、AV1 与 H.264 并通过 WHEP
解码，再播放一个多码率 fMP4 LL-HLS 阶梯）。

## RTSP 客户端

`akio_media::rtsp::client` 从 RTSP 服务器拉流进 hub（`pull`），或把 hub 中的流录制到服务器（`push`），
走 TCP 交织（默认）或 UDP：

```rust,ignore
use akio_media::rtsp::{RtspClientConfig, RtspTransport, client};

let cam = client::pull(&engine, "rtsp://admin:secret@192.0.2.20/stream1", &hub, "cams/door",
                       RtspClientConfig::default())?;
let mut udp = RtspClientConfig::default();
udp.transport = RtspTransport::Udp;
let out = client::push(&engine, "rtsp://198.51.100.4:8554/live/door", &hub, "cams/door", udp)?;
```

`pull` 与 `push` 在 PLAY 或 RECORD 得到应答后才返回：它们等待握手完成，因此请在 I/O 线程之外调用（主机名
也在此解析；`RtspClientConfig::addr` 可免去解析）。每个新会话（重连、重定向）都会重新解析主机名，因此服务器
换了地址而名字不变时也能找到，并且每个会话依次拨该名字的各个地址，直到有一个连上。之后会话运行在引擎上；`error()` 说明结束原因，`close()`
（或丢弃句柄）发送 TEARDOWN。URL 中的凭据用于应答 Digest 或 Basic 质询。保活（GET_PARAMETER，否则
OPTIONS）以服务器会话超时的一半为间隔。UDP 用 `Engine::bind_udp` 为每条轨道绑定一对 RTP/RTCP 端口，因此
引擎需要 `udp_client_threads` 或一个 UDP 监听器。上限：连接与每次应答 10 s，拉流 10 s 无媒体即结束，
应答受解析器的头部与 body 上限约束，TCP 推流落后时先削减到关键帧再断开。

**音视频同步**：拉流按服务器的 RTCP 发送端报告对齐各轨（`RtspClientConfig::rtcp_sync`，默认开启）。每轨时间
从其首包到达时开始；一轨一旦收到报告，其 RTP 时间戳就按服务器的 NTP 时钟映射，相对于第一个完成同步的轨，
因此同时采集的音频与视频在 hub 中带有相同的时间。修正只让时间向前移动；早发报告的服务器（ffmpeg、mediamtx）
在流进入直播之前就已对齐。拉流每隔 `RtspClientConfig::receiver_report_interval`（5 s）在每条轨道的 RTCP 通道
或端口上向服务器发送 RTCP 接收者报告（为零时与以前一样，随保活向每个 UDP RTCP 端口发一个空报告以维持 NAT 映射）。

**重定向**：PLAY 或 RECORD 得到应答之前，任何请求收到带 `Location` 的 3xx 应答（`300` 至 `303`、`307`、`308`；
`305 Use Proxy` 除外）都会结束当前连接，并在该位置（`rtsp://` URL，或同一服务器上的绝对路径）重新握手，连续最多五次；
超过则以最后一次的状态失败。URL 中的凭据只带给同一主机与端口，除非该位置自带凭据；`RtspClientConfig::addr`
只用于客户端自己的 URL。`301` 会被记住：重连从它的位置开始，其他重定向则每次从原 URL 重新跟随。

**服务器的 REDIRECT**：服务器可以用 `REDIRECT` 请求迁移活动会话（本 crate 的服务器用 `redirect_session` /
`redirect_path` 发送）。客户端回答它，并在请求的 `Range` 起点到达时（`clock=` 为 UTC 时间，`npt=` 从 PLAY 或
RECORD 起算；没有则立即）拆除会话，并立即在新位置建立会话，不经退避，使用 `reconnect` 的 engine：拉流保留其路径
并重新发布，推流重新 ANNOUNCE，`reconnects()` 计入一次。之后的重连再从客户端的 URL 开始。没有 `reconnect` 时
客户端以 `ClientError::Redirected(location)` 结束。

**自动重连**：设置 `RtspClientConfig::reconnect`（一个基于 `Arc<Engine>` 构建的 `akio_media::Reconnect`）后，
以再试一次可能好转的错误失败的会话会在有上限、逐次翻倍的退避之后由新会话接替；由于握手会阻塞，每次尝试在
自己的短命线程上运行。拉流保留其 hub 路径与订阅者，并重新发布新会话的轨道（时间线重启）；推流重新 ANNOUNCE
hub 流当前的轨道，并从缓存的 GOP 继续。第一个会话必须成功（`pull` / `push` 返回它的错误）；`reconnects()`
与 `is_live()` 反映进展。

互通：ffmpeg 的监听模式接收我们的推流（TCP 与 UDP）；mediamtx 接收我们的推流并供我们拉流，TCP 与 UDP 均测
（`tools/interop/media/rtsp-client.sh`；由于 Docker Desktop 的 NAT 会丢弃 UDP，UDP 在 mediamtx 所在网络的
容器中运行）；mediamtx 在我们自动重连的拉流与推流下被重启两次（`tests/mediamtx_reconnect.rs`，`--ignored`）。
拉取配置为 `source: redirect` 的 mediamtx 路径时跟随其 `302`（TCP 与 UDP），UDP 拉流保持 75 s，超过 mediamtx 60 s
的会话超时，靠接收者报告维持；在 Docker 网络中，我们自动重连的推流与拉流所用的名字从一个 mediamtx 移到另一个地址
上的另一个 mediamtx，两者都找到了新的（`tools/interop/media/rtsp-redirect.sh`）。
被本 crate 的服务器用 `REDIRECT` 迁移后，拉流从 mediamtx 继续，推流录制到它那里，TCP 与 UDP 均如此
（`tools/interop/media/rtsp-server-redirect.sh target`）。

## 统计

```rust,ignore
{{#include ../../../../crates/akio-media/examples/guide-media-rtsp.rs:stats}}
```

## 不支持

RTSP 2.0、RTSPS 与 HTTP 隧道、组播、拖动（流都是直播）、比连接存活更久的会话。WebRTC：simulcast、转码。
