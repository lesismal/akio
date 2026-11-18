# only-webrtc

[中文](README.zh-CN.md)

WebRTC for [`only`](https://github.com/lesismal/only): an in-house, sans-io WebRTC stack with no
third-party dependencies, driven over `only` UDP sockets. Every layer is safe Rust
(`#![forbid(unsafe_code)]`) on `only-crypto`.

- **ICE** ([`only-ice`](../only-ice/README.md), RFC 8445): ICE-lite server (`RtcServer` on a
  `Listener::udp`, all peers on one port) and a full ICE agent (`Endpoint` on a socket bound with
  `Engine::bind_udp`); host, server-reflexive (`Endpoint::gather_srflx`) and peer-reflexive
  candidates, checklists, regular nomination, role conflicts, trickle ICE (RFC 8838), ICE
  restarts, consent freshness (RFC 7675), a connect timeout.
- **DTLS-SRTP** ([`only-dtls`](../only-dtls/README.md)): DTLS 1.2 with the roles from
  `a=setup` and certificate fingerprint verification; SRTP/SRTCP
  ([`only-srtp`](../only-srtp/README.md), RFC 3711 / RFC 7714) with AES-CM-HMAC-SHA1-80/32 and
  AEAD-AES-128/256-GCM, replay protection, ROC handling; keys from the DTLS exporter.
- **Data channels** ([`only-sctp`](../only-sctp/README.md)): SCTP over DTLS (RFC 8261) with
  congestion control, retransmission, PR-SCTP FORWARD-TSN (RFC 3758), stream reset (RFC 6525)
  for closing, CRC32C; DCEP (RFC 8832); reliable / max-retransmits / max-lifetime, ordered or
  unordered, binary / string / empty messages, buffered-amount-low events.
- **Media** ([`only-rtp`](../only-rtp/README.md)): RTP/RTCP, packetization of Opus, G.711,
  G.722, VP8, VP9, H.264, H.265 and AV1; a jitter-free frame assembler (`on_media_data`) or RTP
  mode (`on_rtp`); sender/receiver reports, generic NACK with RTX (RFC 4588), PLI/FIR, REMB,
  transport-wide congestion control (TWCC header extension + feedback) with a delay- and
  loss-based bandwidth estimator. Opt-in (`RtcConfig`, ADR-039): FEC on video (FlexFEC
  `flexfec-03` with an `a=ssrc-group:FEC-FR` stream, or ULPFEC in RED) repairing packets before
  the frame assembler and NACK and sent at a rate that follows the loss before repair; RFC 8888
  congestion control feedback instead of TWCC; RTCP XR receiver reference times (receiver-side
  RTT); TMMBR / TMMBN (`Peer::request_max_bitrate`, requests cap the estimate).
- **SDP** offer/answer (JSEP): BUNDLE, rtcp-mux, mid/msid, ssrc/FID, extmap,
  rtpmap/fmtp/rtcp-fb negotiation, setup/fingerprint, ice-ufrag/pwd/options/lite, candidates,
  sctp-port/max-message-size; renegotiation (media added, directions, ICE restart);
  simulcast sending (`a=rid`, `a=simulcast`, RID/MID header extensions) and receiving, with
  per-layer keyframe requests for layer selection (`request_layer_keyframe`).
- **Candidates** for an `Endpoint`: host, server-reflexive (`gather_srflx`), relayed through a
  TURN allocation over UDP, TCP or TLS (`gather_relay`, `gather_relay_via` with a `RelayServer`
  or a `turn:`/`turns:` URL; lost allocations are made again), passive and active ICE-TCP
  (`listen_tcp`, `dial_tcp`, RFC 6544), and a candidate policy (`candidate_filter`, as
  `iceTransportPolicy`). An `RtcServer` takes passive ICE-TCP on an engine TCP listener
  (`tcp_candidates`, `tcp`).
- **Own types**: the API is this crate's own; the `unstable` cargo feature currently adds
  nothing.

```rust,no_run
use only::{Engine, Listener};
use only_webrtc::{ChannelId, Peer, PeerHandler, RtcServer};

struct Echo;
impl PeerHandler for Echo {
    fn on_channel_data(&mut self, p: &Peer, id: ChannelId, data: &[u8], binary: bool) {
        let _ = p.send(id, data, binary);
    }
}

let server = RtcServer::new(vec!["203.0.113.7:3478".parse().unwrap()]);
let engine = Engine::builder()
    .listen(Listener::udp("0.0.0.0:3478".parse().unwrap()).serve(server.clone()))
    .build()
    .unwrap();
engine.start().unwrap();
let offer: String = todo!("the remote SDP offer");
let (_peer, answer) = server.accept_offer(&offer, Echo).unwrap(); // from WHIP/WHEP, a WebSocket ...
```

Interop: pion (data channels, Opus/VP8 echo and PLI in both offer directions, also through a
`only` TURN relay) and fib's Go WebRTC both ways: `tools/interop/webrtc/run.sh`; headless Chrome
in both offer directions (data channels, the fake camera and microphone echoed back and decoded
by Chrome): `tools/interop/webrtc/browser.sh`; FEC under loss (Chrome's and ours), RFC 8888 both
ways, XR and TMMBR with headless Chrome: `tools/interop/webrtc/fec.sh`. STUN and TURN servers are in
[`only-turn`](../only-turn/README.md).

Not implemented: TURN over DTLS, simultaneous-open ICE-TCP, FEC on simulcast lines and for audio
(Opus RED), SDES-SRTP, DTLS 1.3.

Guide: [WebRTC, STUN and TURN](https://lesismal.github.io/only/en/protocols/webrtc.html).
