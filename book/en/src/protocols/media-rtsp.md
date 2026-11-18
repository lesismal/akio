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
  the SDP or in band (VP8, VP9, AV1: from the first keyframe). RTP carries presentation times only, so the server derives decode times
  for B-frame video (a reorder-depth estimate, no frame held back).
- Codecs: H.264 (single NAL, STAP-A, FU-A), H.265 (single, AP, FU), VP8 (RFC 7741), VP9
  (RFC 9628), AV1 (AOM RTP payload; the three through only-rtp, a frame missing a packet is
  dropped), AAC (`mpeg4-generic` `AAC-hbr`), Opus, G.711.
- Authentication: `RtspConfig::credentials` turns on Digest (MD5) and Basic.
- Timeouts: the first request, and any request once begun, must arrive within
  `request_timeout` (10 s). `Session: <id>;timeout=<s>` advertises `session_timeout` (60 s) and
  it is enforced: a session whose client sends nothing (requests, interleaved RTCP, or for UDP
  transports datagrams from its ports) for that long is torn down.

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
answers every offer with `501 Not Implemented`.
`WhipConfig::max_sessions` (256) bounds concurrent sessions; offers past it get 503, and a
session whose peer ended without a `DELETE` frees its slot.

### WebRTC media (`webrtc` feature)

With the cargo feature `webrtc`, `only_media::webrtc::RtcMedia` is the engine, on an
`only-webrtc` `RtcServer` (ICE-lite on one UDP port):

```rust,ignore
use only_media::webrtc::{RtcMedia, RtcMediaConfig};

// The address browsers reach the UDP listener at goes into every answer.
let rtc = RtcMedia::rtc_server(vec!["203.0.113.7:8189".parse()?]);
let media = RtcMedia::new(rtc.clone(), RtcMediaConfig::default());
let whip = WhipServer::new(hub.clone(), Arc::new(media), WhipConfig::default());
// serve `rtc` on Listener::udp("0.0.0.0:8189") and `whip.routes(router)` over HTTP
```

- **WHIP in**: H.264 and H.265 (Annex B over RTP) become AVCC with the configuration record
  built from the in-band parameter sets; VP8 and VP9 frames and AV1 temporal units pass through,
  their configuration record and size taken from each keyframe; Opus, PCMU and PCMA pass
  through. The stream goes live when every line is ready (or after `track_timeout`, 5 s, with
  those that are); what arrives before is held within `max_pending_packets` /
  `max_pending_bytes`. G.722 is not carried by the hub: an offer with nothing else gets 406.
- **WHEP out**: the viewer is subscribed once ICE and DTLS are up, from the next keyframe (set
  `play_gop_cache` to start from the cached GOP), H.264/H.265 with the parameter sets before
  each keyframe, VP8, VP9, AV1, Opus and G.711 as they are. AAC and MP3 are not sent (no transcoding): publish
  Opus for WebRTC viewers, and video without B-frames (`-bf 0`).
- **Keyframes**: a viewer's PLI or FIR goes to the hub (`Subscription::request_keyframe`), which
  passes it to the publisher at most every `HubConfig::keyframe_request_interval` (500 ms); a WHIP
  publisher turns it into a PLI to its sender. A viewer joining without a cached keyframe asks at
  once.

`crates/only-media/examples/whip-server.rs` runs it; `tools/interop/webrtc/media.sh` checks it
against ffmpeg's WHIP muxer and pion (WHIP in, WHEP out, PLI round trip, RTMP in to WHEP out),
and `tools/interop/media/browser.sh` against headless Chrome (VP8, VP9, AV1 and H.264 published
over WHIP and decoded over WHEP, then a multivariant fMP4 LL-HLS ladder played).

## RTSP client

`only_media::rtsp::client` plays from an RTSP server into the hub (`pull`) or records a hub
stream to one (`push`), over TCP interleaved (default) or UDP:

```rust,ignore
use only_media::rtsp::{RtspClientConfig, RtspTransport, client};

let cam = client::pull(&engine, "rtsp://admin:secret@192.0.2.20/stream1", &hub, "cams/door",
                       RtspClientConfig::default())?;
let mut udp = RtspClientConfig::default();
udp.transport = RtspTransport::Udp;
let out = client::push(&engine, "rtsp://198.51.100.4:8554/live/door", &hub, "cams/door", udp)?;
```

`pull` and `push` return once PLAY or RECORD is answered: they wait for the handshake, so call
them off the I/O threads (host names are resolved there too; `RtspClientConfig::addr` skips the
lookup). The session then runs on the engine; `error()` says why it ended and `close()` (or
dropping the handle) sends TEARDOWN. Credentials in the URL answer Digest or Basic challenges.
Keep-alives (GET_PARAMETER, else OPTIONS) go at half the server's session timeout. UDP binds an
RTP/RTCP port pair per track with `Engine::bind_udp`, so the engine needs
`udp_client_threads` or a UDP listener. Bounds: connect and each response 10 s, a pull without
media for 10 s ends, responses under the parser's head and body limits, and a TCP push that falls
behind is cut back to keyframes, then disconnected.

Interop: ffmpeg's listen mode receives our push (TCP and UDP); mediamtx records our push and
serves our pull, TCP and UDP (`tools/interop/media/rtsp-client.sh`; UDP runs in a container on
mediamtx's network because Docker Desktop's NAT drops it).

## Statistics

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-rtsp.rs:stats}}
```

## Not supported

RTSP 2.0, RTSPS and HTTP tunnelling, multicast, seeking (streams are live), sessions that
outlive their connection; RTCP receiver reports to recorders. Client: redirects, reconnects and
RTCP-based A/V sync. WebRTC: simulcast, transcoding.
