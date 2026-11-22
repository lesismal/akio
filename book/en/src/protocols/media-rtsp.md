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
  for B-frame video (a reorder-depth estimate, no frame held back). The tracks are lined up by
  the publisher's RTCP sender reports (`RtspConfig::rtcp_sync`, on by default; interleaved RTCP
  channels, RTCP muxed on the RTP channel, the UDP ports), as in the client's pull below, so
  audio and video keep the offset they were captured with. The server sends the publisher RTCP
  receiver reports (RFC 3550 6.4.2) on each track's RTCP channel or port, every
  `RtspConfig::receiver_report_interval` (5 s; zero for none): the publisher's SSRC, the
  fraction and number of packets lost, the highest sequence number, the interarrival jitter,
  the last sender report's NTP time and the delay since, followed by an SDES with a CNAME.
- Codecs: H.264 (single NAL, STAP-A, FU-A), H.265 (single, AP, FU), VP8 (RFC 7741), VP9
  (RFC 9628), AV1 (AOM RTP payload; the three through only-rtp, a frame missing a packet is
  dropped), AAC (`mpeg4-generic` `AAC-hbr`), Opus, G.711.
- Authentication: `RtspConfig::credentials` turns on Digest (MD5) and Basic.
- Timeouts: the first request, and any request once begun, must arrive within
  `request_timeout` (10 s). `Session: <id>;timeout=<s>` advertises `session_timeout` (60 s) and
  it is enforced: a session whose client sends nothing (requests, interleaved RTCP, or for UDP
  transports datagrams from its ports) for that long is torn down.
- Moving sessions: `RtspServer::sessions()` lists them (id, path, peer, recording or not);
  `redirect_session(id, &Redirect)` and `redirect_path(path, &Redirect)` send their clients a
  `REDIRECT` request (RFC 2326 10.15) to drain a server for maintenance or shed load:

  ```rust,ignore
  use std::time::{Duration, SystemTime};
  use only_media::rtsp::Redirect;

  // Every player and the publisher of live/cam, to the other server in 30 s.
  let moved = srv.redirect_path("live/cam", &Redirect::new("rtsp://198.51.100.8:8554/live/cam")
      .at(SystemTime::now() + Duration::from_secs(30)));
  ```

  `at` goes out as `Range: clock=<UTC>-`. The session keeps playing or recording until its
  client tears it down (the server then closes the connection) or until `grace` (10 s) after
  the move takes effect, when the server closes it: clients that ignore the request end
  cleanly as well. None of the third-party clients we tried follows it: ffmpeg answers `501`
  and GStreamer `200`, both carrying on until the grace closes them, and mediamtx pulling from
  the server tears the session down and pulls the same URL again
  (`tools/interop/media/rtsp-server-redirect.sh`); this crate's client does (below).

Tested with ffmpeg 9 (`crates/only-media/tests/rtsp_interop.rs`):

```text
ffmpeg -re -f lavfi -i testsrc=size=320x240:rate=25 -f lavfi -i sine -c:v libx264 -c:a aac \
    -f rtsp -rtsp_transport tcp rtsp://127.0.0.1:8554/live/cam      # also -rtsp_transport udp
ffmpeg -re ... -c:v libx265 -c:a libopus -f rtsp -rtsp_transport udp rtsp://127.0.0.1:8554/live/cam
ffprobe -rtsp_transport tcp rtsp://127.0.0.1:8554/live/cam            # and udp
ffmpeg -rtsp_transport udp -i rtsp://127.0.0.1:8554/live/cam -f null -
```

The same file records with sender reports that put audio 500 ms after video while the packets
arrive together (TCP, RTCP muxed on the RTP channels, UDP; reports before the media and
halfway): the hub's times follow the reports, reports 60 s apart are ignored, and with
`rtcp_sync` off the times follow the arrival. Another test reads the receiver reports a
recording sends back over TCP and UDP (losses across a sequence number wrap, the LSR / DLSR of
a sender report). GStreamer's `rtspclientsink` records to the server over TCP and UDP and its
RTP session logs every report (`tools/interop/media/rtsp-redirect.sh`).

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
lookup). Host names are looked up again for every new session (a reconnect, a redirect), so a
server that moved to another address under the same name is found, and each session dials the
name's addresses in turn until one connects. The session then runs on the engine; `error()` says why it ended and `close()` (or
dropping the handle) sends TEARDOWN. Credentials in the URL answer Digest or Basic challenges.
Keep-alives (GET_PARAMETER, else OPTIONS) go at half the server's session timeout. UDP binds an
RTP/RTCP port pair per track with `Engine::bind_udp`, so the engine needs
`udp_client_threads` or a UDP listener. Bounds: connect and each response 10 s, a pull without
media for 10 s ends, responses under the parser's head and body limits, and a TCP push that falls
behind is cut back to keyframes, then disconnected.

**A/V sync**: a pull lines its tracks up by the server's RTCP sender reports
(`RtspClientConfig::rtcp_sync`, on by default). Each track's times start at its first packet's
arrival; once a track has a report, its RTP timestamps are mapped to the server's NTP clock
relative to the first track synchronized, so audio and video captured together carry the same
time in the hub. Corrections only move times forward, and servers that send their reports
early (ffmpeg, mediamtx) have the stream aligned before it goes live. A pull sends the
server RTCP receiver reports on each track's RTCP channel or port every
`RtspClientConfig::receiver_report_interval` (5 s; with zero, an empty report goes to each UDP
RTCP port with the keep-alives, as before, for NAT bindings).

**Redirects**: a 3xx response with a `Location` (`300` to `303`, `307`, `308`; not `305 Use Proxy`) to any
request before PLAY or RECORD is answered ends that connection and starts the handshake again
at the location (an `rtsp://` URL, or an absolute path on the same server), up to five in a
row; then the client fails with the last one's status. The URL's credentials go along only to
the same host and port, unless the location carries its own; `RtspClientConfig::addr` applies
to the client's own URL only. A `301` is remembered: reconnects start at its location, other
redirects are followed again from the original URL.

**Server REDIRECT**: a server may move a live session with a `REDIRECT` request (this crate's
server does with `redirect_session` / `redirect_path`). The client answers it and, when the
request's `Range` start comes (`clock=` a UTC time, `npt=` counted from PLAY or RECORD; at once
without), tears the session down and sets up at the location at once, without the backoff, on
the `reconnect` engine: a pull keeps its path and republishes, a push announces again, and
`reconnects()` counts it. Later reconnects start from the client's URL again. Without
`reconnect` the client ends with `ClientError::Redirected(location)`.

**Reconnecting**: with `RtspClientConfig::reconnect` (an `only_media::Reconnect`, built on an
`Arc<Engine>`) a session that fails with an error another try may cure is followed by a new
one after a bounded, doubling backoff; the tries run on a short-lived thread of their own, as
the handshake blocks. A pull keeps its hub path and subscribers and republishes the new
session's tracks (a timeline restart); a push announces the hub stream's current tracks again
and continues from the cached GOP. The first session must come up (`pull` / `push` return its
error); `reconnects()` and `is_live()` tell how it goes.

Interop: ffmpeg's listen mode receives our push (TCP and UDP); mediamtx records our push and
serves our pull, TCP and UDP (`tools/interop/media/rtsp-client.sh`; UDP runs in a container on
mediamtx's network because Docker Desktop's NAT drops it); mediamtx restarted twice under our
reconnecting pulls and pushes (`tests/mediamtx_reconnect.rs`, `--ignored`). A pull of a mediamtx path
configured as `source: redirect` follows its `302`, over TCP and UDP, and a UDP pull held for
75 s past mediamtx's 60 s session timeout is kept alive by its receiver reports; on a Docker
network, the name our reconnecting push and pull use moves from one mediamtx to another at
another address, and both find the new one (`tools/interop/media/rtsp-redirect.sh`).
Moved by this crate's server with `REDIRECT`, a pull goes on from mediamtx and a push records
to it, over TCP and UDP (`tools/interop/media/rtsp-server-redirect.sh target`).

## Statistics

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media-rtsp.rs:stats}}
```

## Not supported

RTSP 2.0, RTSPS and HTTP tunnelling, multicast, seeking (streams are live), sessions that
outlive their connection. WebRTC: simulcast, transcoding.
