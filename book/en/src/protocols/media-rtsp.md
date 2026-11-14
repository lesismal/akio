# RTSP and WHIP/WHEP

`only-media` serves RTSP and the WHIP/WHEP signalling endpoints in front of the same stream
`Hub` as RTMP, HTTP-FLV, HLS and SRT: a camera that records over RTSP plays over every other
protocol, and an RTMP encoder's stream plays in any RTSP player. Every protocol converts to
the canonical packets of `only_media::av` (AVCC video, raw AAC), so no protocol knows about
another.

## One hub, one hook

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-rtsp.rs:hub}}
```

`HubConfig::on_publish` and `on_subscribe` authorize every ingest and egress at once; the
`PeerInfo` they get names the protocol, the peer address and the URL's query string (where
tokens travel).

## RTSP server

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-rtsp.rs:rtsp}}
```

- `rtsp://host:port/live/cam` plays or records the hub stream `live/cam`.
- Players: `DESCRIBE` (an SDP with `sprop-parameter-sets` / `sprop-vps/sps/pps` and the AAC
  `config`), `SETUP` per track with `RTP/AVP/TCP` (interleaved on the RTSP connection) or
  `RTP/AVP` (UDP unicast, from the ports `listen_udp` bound), `PLAY`, `PAUSE`, `TEARDOWN`,
  `GET_PARAMETER` / `SET_PARAMETER` keep-alives. A player starts from the hub's cached GOP and
  receives RTCP sender reports; a TCP player that falls behind is cut back to keyframes
  (`hub::Dropper`), and closed past `RtspConfig::max_write_queue`.
- Publishers: `ANNOUNCE` reserves the path (a second publisher gets 453 at once), `SETUP` with
  `mode=record`, `RECORD`. The stream goes live as soon as the parameter sets are known, from
  the SDP or in band. RTP carries presentation times only, so the server derives decode times
  for B-frame video (a reorder-depth estimate, no frame held back).
- Codecs: H.264 (single NAL, STAP-A, FU-A), H.265 (single, AP, FU), AAC (`mpeg4-generic`
  `AAC-hbr`), Opus, G.711.
- Authentication: `RtspConfig::credentials` turns on Digest (MD5) and Basic.

Tested with ffmpeg 9 (`crates/only-media/tests/rtsp_interop.rs`):

```text
ffmpeg -re -f lavfi -i testsrc=size=320x240:rate=25 -f lavfi -i sine -c:v libx264 -c:a aac \
    -f rtsp -rtsp_transport tcp rtsp://127.0.0.1:8554/live/cam      # also -rtsp_transport udp
ffmpeg -re ... -c:v libx265 -c:a libopus -f rtsp -rtsp_transport udp rtsp://127.0.0.1:8554/live/cam
ffprobe -rtsp_transport tcp rtsp://127.0.0.1:8554/live/cam            # and udp
ffmpeg -rtsp_transport udp -i rtsp://127.0.0.1:8554/live/cam -f null -
```

## WHIP and WHEP

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-rtsp.rs:whip}}
```

`WhipServer::routes` adds to a only-http `Router`:

| Request | Answer |
| --- | --- |
| `POST /whip/<path>` with an `application/sdp` offer | `201 Created`, the answer SDP, `Location: /webrtc/session/<id>` |
| `POST /whep/<path>` | the same, playing the hub stream `<path>` (404 when it is not live) |
| `PATCH <location>` with `application/trickle-ice-sdpfrag` | 204, or 405 when the engine does not trickle |
| `DELETE <location>` | 200: the session ends (a WHIP publisher unpublishes) |
| `OPTIONS` | CORS preflight with `Accept-Post: application/sdp` |

A WHIP publish reserves the path through the hub, so `on_publish` applies; an
`Authorization: Bearer <token>` header reaches the hook as `token=<token>` when the URL has no
query. The media itself (ICE, DTLS-SRTP, RTP) is the job of a `WebRtcEngine`: its `publish`
gets the reserved `Publisher` and its `play` subscribes to the hub. `NoMedia`, the placeholder,
answers every offer with `501 Not Implemented` until a WebRTC engine is plugged in.

## Statistics

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-rtsp.rs:stats}}
```

## Not supported

RTSP 2.0, RTSPS and HTTP tunnelling, multicast, seeking (streams are live), sessions that
outlive their connection; RTCP receiver reports to recorders.
