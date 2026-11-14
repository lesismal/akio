# RTSP 与 WHIP/WHEP

`flash-media` 在同一个流 `Hub` 前提供 RTSP 服务和 WHIP/WHEP 信令端点，与 RTMP、HTTP-FLV、
HLS、SRT 共用：摄像头用 RTSP 推流后可以用其他任何协议播放，RTMP 编码器推的流也能在任意 RTSP
播放器里播放。每种协议都转换成 `flash_media::av` 的规范包（AVCC 视频、裸 AAC），协议之间互不感知。

## 一个 hub，一个钩子

```rust,ignore
{{#include ../../../../crates/flash-media/examples/guide-media-rtsp.rs:hub}}
```

`HubConfig::on_publish` 和 `on_subscribe` 一次性为所有推流和播放协议做鉴权；它们拿到的
`PeerInfo` 包含协议名、对端地址和 URL 的查询串（token 通常放在这里）。

## RTSP 服务端

```rust,ignore
{{#include ../../../../crates/flash-media/examples/guide-media-rtsp.rs:rtsp}}
```

- `rtsp://host:port/live/cam` 播放或录制 hub 中的流 `live/cam`。
- 播放端：`DESCRIBE`（SDP 中带 `sprop-parameter-sets` / `sprop-vps/sps/pps` 和 AAC 的
  `config`），逐轨 `SETUP`，支持 `RTP/AVP/TCP`（在 RTSP 连接上交织）和 `RTP/AVP`（UDP 单播，
  使用 `listen_udp` 绑定的端口），以及 `PLAY`、`PAUSE`、`TEARDOWN`、`GET_PARAMETER` /
  `SET_PARAMETER` 保活。播放从 hub 缓存的 GOP 开始，并收到 RTCP 发送者报告；TCP 播放端跟不上时
  退化为只发关键帧（`hub::Dropper`），超过 `RtspConfig::max_write_queue` 则断开。
- 推流端：`ANNOUNCE` 预占路径（第二个推流者立即收到 453），带 `mode=record` 的 `SETUP`，然后
  `RECORD`。参数集一旦已知（来自 SDP 或码流内）流即上线。RTP 只携带显示时间，因此服务端为带
  B 帧的视频推算解码时间（估计重排深度，不缓存帧）。
- 编解码：H.264（单 NAL、STAP-A、FU-A）、H.265（单 NAL、AP、FU）、AAC（`mpeg4-generic`
  `AAC-hbr`）、Opus、G.711。
- 鉴权：设置 `RtspConfig::credentials` 后启用 Digest（MD5）和 Basic。

已用 ffmpeg 9 测试（`crates/flash-media/tests/rtsp_interop.rs`）：

```text
ffmpeg -re -f lavfi -i testsrc=size=320x240:rate=25 -f lavfi -i sine -c:v libx264 -c:a aac \
    -f rtsp -rtsp_transport tcp rtsp://127.0.0.1:8554/live/cam      # 也可 -rtsp_transport udp
ffmpeg -re ... -c:v libx265 -c:a libopus -f rtsp -rtsp_transport udp rtsp://127.0.0.1:8554/live/cam
ffprobe -rtsp_transport tcp rtsp://127.0.0.1:8554/live/cam            # 以及 udp
ffmpeg -rtsp_transport udp -i rtsp://127.0.0.1:8554/live/cam -f null -
```

## WHIP 与 WHEP

```rust,ignore
{{#include ../../../../crates/flash-media/examples/guide-media-rtsp.rs:whip}}
```

`WhipServer::routes` 向 flash-http 的 `Router` 添加：

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
`NoMedia` 对所有 offer 返回 `501 Not Implemented`，直到接入 WebRTC 引擎。

## 统计

```rust,ignore
{{#include ../../../../crates/flash-media/examples/guide-media-rtsp.rs:stats}}
```

## 不支持

RTSP 2.0、RTSPS 与 HTTP 隧道、组播、拖动（流都是直播）、比连接存活更久的会话；不向推流端发送
RTCP 接收者报告。
