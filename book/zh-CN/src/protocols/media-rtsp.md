# RTSP 与 WHIP/WHEP

`only-media` 在同一个流 `Hub` 前提供 RTSP 服务和 WHIP/WHEP 信令端点，与 RTMP、HTTP-FLV、
HLS、SRT 共用：摄像头用 RTSP 推流后可以用其他任何协议播放，RTMP 编码器推的流也能在任意 RTSP
播放器里播放。每种协议都转换成 `only_media::av` 的规范包（AVCC 视频、裸 AAC），协议之间互不感知。

## 一个 hub，一个钩子

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-rtsp.rs:hub}}
```

`HubConfig::on_publish` 和 `on_subscribe` 一次性为所有推流和播放协议做鉴权；它们拿到的
`PeerInfo` 包含协议名、对端地址和 URL 的查询串（token 通常放在这里）。

## RTSP 服务端

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-rtsp.rs:rtsp}}
```

- `rtsp://host:port/live/cam` 播放或录制 hub 中的流 `live/cam`。
- 播放端：`DESCRIBE`（SDP 中带 `sprop-parameter-sets` / `sprop-vps/sps/pps` 和 AAC 的
  `config`），逐轨 `SETUP`，支持 `RTP/AVP/TCP`（在 RTSP 连接上交织）和 `RTP/AVP`（UDP 单播，
  使用 `listen_udp` 绑定的端口），以及 `PLAY`、`PAUSE`、`TEARDOWN`、`GET_PARAMETER` /
  `SET_PARAMETER` 保活。播放从 hub 缓存的 GOP 开始，并收到 RTCP 发送者报告；TCP 播放端跟不上时
  退化为只发关键帧（`hub::Dropper`），超过 `RtspConfig::max_write_queue` 则断开。
- 推流端：`ANNOUNCE` 预占路径（第二个推流者立即收到 453），带 `mode=record` 的 `SETUP`，然后
  `RECORD`。参数集一旦已知（来自 SDP 或码流内；VP8、VP9、AV1 来自第一个关键帧）流即上线。RTP 只携带显示时间，因此服务端为带
  B 帧的视频推算解码时间（估计重排深度，不缓存帧）。
- 编解码：H.264（单 NAL、STAP-A、FU-A）、H.265（单 NAL、AP、FU）、VP8（RFC 7741）、VP9（RFC 9628）、
  AV1（AOM 的 RTP 负载格式；这三种经 only-rtp 处理，缺包的帧被丢弃）、AAC（`mpeg4-generic` `AAC-hbr`）、
  Opus、G.711。
- 认证：`RtspConfig::credentials` 开启 Digest（MD5）与 Basic。
- 超时：首个请求，以及任何已开始的请求，须在 `request_timeout`（10 s）内收齐。`Session: <id>;timeout=<s>`
  通告 `session_timeout`（60 s）并强制执行：客户端这么久什么都没发送（请求、交织的 RTCP，UDP 传输时来自其
  端口的数据报）的会话被拆除。

已用 ffmpeg 9 测试（`crates/only-media/tests/rtsp_interop.rs`）：

```text
ffmpeg -re -f lavfi -i testsrc=size=320x240:rate=25 -f lavfi -i sine -c:v libx264 -c:a aac \
    -f rtsp -rtsp_transport tcp rtsp://127.0.0.1:8554/live/cam      # 也可 -rtsp_transport udp
ffmpeg -re ... -c:v libx265 -c:a libopus -f rtsp -rtsp_transport udp rtsp://127.0.0.1:8554/live/cam
ffprobe -rtsp_transport tcp rtsp://127.0.0.1:8554/live/cam            # 以及 udp
ffmpeg -rtsp_transport udp -i rtsp://127.0.0.1:8554/live/cam -f null -
```

## WHIP 与 WHEP

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-rtsp.rs:whip}}
```

`WhipServer::routes` 向 only-http 的 `Router` 添加：

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

开启 cargo feature `webrtc` 后，`only_media::webrtc::RtcMedia` 即为引擎，运行在 `only-webrtc` 的
`RtcServer` 上（单个 UDP 端口上的 ICE-lite）：

```rust,ignore
use only_media::webrtc::{RtcMedia, RtcMediaConfig};

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

`crates/only-media/examples/whip-server.rs` 可直接运行；`tools/interop/webrtc/media.sh` 用 ffmpeg 的 WHIP
封装器与 pion 验证它（WHIP 推入、WHEP 播出、PLI 往返、RTMP 推入到 WHEP 播出），
`tools/interop/media/browser.sh` 用 headless Chrome 验证（通过 WHIP 推 VP8、VP9、AV1 与 H.264 并通过 WHEP
解码，再播放一个多码率 fMP4 LL-HLS 阶梯）。

## RTSP 客户端

`only_media::rtsp::client` 从 RTSP 服务器拉流进 hub（`pull`），或把 hub 中的流录制到服务器（`push`），
走 TCP 交织（默认）或 UDP：

```rust,ignore
use only_media::rtsp::{RtspClientConfig, RtspTransport, client};

let cam = client::pull(&engine, "rtsp://admin:secret@192.0.2.20/stream1", &hub, "cams/door",
                       RtspClientConfig::default())?;
let mut udp = RtspClientConfig::default();
udp.transport = RtspTransport::Udp;
let out = client::push(&engine, "rtsp://198.51.100.4:8554/live/door", &hub, "cams/door", udp)?;
```

`pull` 与 `push` 在 PLAY 或 RECORD 得到应答后才返回：它们等待握手完成，因此请在 I/O 线程之外调用（主机名
也在此解析；`RtspClientConfig::addr` 可免去解析）。之后会话运行在引擎上；`error()` 说明结束原因，`close()`
（或丢弃句柄）发送 TEARDOWN。URL 中的凭据用于应答 Digest 或 Basic 质询。保活（GET_PARAMETER，否则
OPTIONS）以服务器会话超时的一半为间隔。UDP 用 `Engine::bind_udp` 为每条轨道绑定一对 RTP/RTCP 端口，因此
引擎需要 `udp_client_threads` 或一个 UDP 监听器。上限：连接与每次应答 10 s，拉流 10 s 无媒体即结束，
应答受解析器的头部与 body 上限约束，TCP 推流落后时先削减到关键帧再断开。

互通：ffmpeg 的监听模式接收我们的推流（TCP 与 UDP）；mediamtx 接收我们的推流并供我们拉流，TCP 与 UDP 均测
（`tools/interop/media/rtsp-client.sh`；由于 Docker Desktop 的 NAT 会丢弃 UDP，UDP 在 mediamtx 所在网络的
容器中运行）。

## 统计

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-rtsp.rs:stats}}
```

## 不支持

RTSP 2.0、RTSPS 与 HTTP 隧道、组播、拖动（流都是直播）、比连接存活更久的会话；不向推流端发送
RTCP 接收者报告。客户端：重定向、重连与基于 RTCP 的音视频同步。WebRTC：simulcast、转码。
