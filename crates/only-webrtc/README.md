# only-webrtc

[中文](README.zh-CN.md)

WebRTC for [`only`](https://github.com/lesismal/only): an in-house, sans-io WebRTC stack with no
third-party dependencies, driven over `only` UDP sockets. Every layer is safe Rust
(`#![forbid(unsafe_code)]`) on `only-crypto`.

- **ICE** ([`only-ice`](../only-ice/README.md), RFC 8445): ICE-lite server (`RtcServer` on a
  `Listener::udp`, all peers on one port) and a full ICE agent (`Endpoint` on a socket bound with
  `Engine::bind_udp`); host, server-reflexive (`Endpoint::gather_srflx`) and peer-reflexive
  candidates, checklists, regular nomination (aggressive nomination and renomination with
  `RtcConfig::enable_ice_aggressive_nomination` / `enable_ice_renomination`), role conflicts,
  trickle ICE (RFC 8838), ICE restarts, consent freshness (RFC 7675), a connect timeout; mDNS
  (`.local`) candidates resolved and our own host addresses concealed behind mDNS names
  (`Endpoint::resolve_mdns`, `conceal_host_candidates`), as browsers do, over IPv4
  (`224.0.0.251`) and IPv6 (`ff02::fb`, joined on every interface with a link-local address;
  link-local addresses keep their interface, ADR-054).
- **DTLS-SRTP** ([`only-dtls`](../only-dtls/README.md)): DTLS 1.3 (RFC 9147, as Chrome 157
  negotiates it) falling back to DTLS 1.2 (pion; `RtcConfig::enable_dtls13(false)` for DTLS 1.2
  only), with the roles from `a=setup` and certificate fingerprint verification; SRTP/SRTCP
  ([`only-srtp`](../only-srtp/README.md), RFC 3711 / RFC 7714) with AES-CM-HMAC-SHA1-80/32 and
  AEAD-AES-128/256-GCM, replay protection, ROC handling; keys from the DTLS exporter. Opt-in
  (ADR-048): cryptex (`a=cryptex`, RFC 9335, `enable_cryptex`) and RFC 6904 encrypted header
  extensions (`enable_encrypted_header_extensions`). Opt-in for non-browser peers such as SIP
  gateways (ADR-054): SDES-SRTP (`enable_sdes_srtp`, RFC 4568 `a=crypto` keys in the SDP,
  `RTP/SAVPF`, no DTLS and so no data channels; DTLS-SRTP offers are still answered with
  DTLS-SRTP, browsers never see `a=crypto`).
- **Data channels** ([`only-sctp`](../only-sctp/README.md)): SCTP over DTLS (RFC 8261) with
  congestion control, retransmission, PR-SCTP FORWARD-TSN (RFC 3758), stream reset (RFC 6525)
  for closing, CRC32C; DCEP (RFC 8832); reliable / max-retransmits / max-lifetime, ordered or
  unordered, binary / string / empty messages, buffered-amount-low events.
- **Media** ([`only-rtp`](../only-rtp/README.md)): RTP/RTCP, packetization of Opus, G.711,
  G.722, VP8, VP9, H.264, H.265 and AV1; a jitter-free frame assembler (`on_media_data`) or RTP
  mode (`on_rtp`); sender/receiver reports, generic NACK with RTX (RFC 4588), PLI/FIR, REMB,
  transport-wide congestion control (TWCC header extension + feedback) with a delay- and
  loss-based bandwidth estimator that probes the path (ADR-050: RTX copies of recent media paced
  in short clusters at start, while application-limited, after a drop and on a new ICE pair).
  Opt-in (`RtcConfig`, ADR-039, ADR-048): FEC on video (FlexFEC
  `flexfec-03` with an `a=ssrc-group:FEC-FR` stream, or ULPFEC in RED, also per encoding of a
  simulcast line as Chrome sends it) repairing packets before the frame assembler and NACK and
  sent at a rate that follows the loss before repair; Opus RED (`red/48000/2`, listed before Opus
  so Chrome sends it; redundant copies stand in for lost packets, up to two sent); RFC 8888
  congestion control feedback instead of TWCC; RTCP XR receiver reference times (receiver-side
  RTT); TMMBR / TMMBN (`Peer::request_max_bitrate`, requests cap the estimate).
- **SDP** offer/answer (JSEP): BUNDLE, rtcp-mux, mid/msid, ssrc/FID, extmap,
  rtpmap/fmtp/rtcp-fb negotiation, setup/fingerprint, ice-ufrag/pwd/options/lite, candidates,
  sctp-port/max-message-size; renegotiation (media added, directions, ICE restart);
  simulcast sending (`a=rid`, `a=simulcast`, RID/MID header extensions) and receiving, with
  per-layer keyframe requests for layer selection (`request_layer_keyframe`).
- **Candidates** for an `Endpoint`: host, server-reflexive (`gather_srflx`), relayed through a
  TURN allocation over UDP, DTLS (RFC 7350, `RelayServer::dtls`, `turns:...?transport=udp`),
  TCP or TLS (`gather_relay`, `gather_relay_via` with a `RelayServer` or a `turn:`/`turns:`
  URL; lost allocations are made again), passive, active and
  simultaneous-open ICE-TCP (`listen_tcp`, `dial_tcp`, `listen_tcp_so`, RFC 6544), and a
  candidate policy (`candidate_filter`, as
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
by Chrome; an `Endpoint` that conceals its address with mDNS reaching Chrome with its own mDNS
concealment on, each resolving the other's name; DTLS 1.3 in both DTLS roles; cryptex both ways
with Chrome's `rtpHeaderEncryptionPolicy` "require"; our simulcast line with per-encoding ULPFEC
through loss): `tools/interop/webrtc/browser.sh`; FEC under loss (Chrome's and ours), RFC 8888
both ways, XR and TMMBR, Opus RED under loss both ways, Chrome's per-layer ULPFEC on simulcast
with headless Chrome: `tools/interop/webrtc/fec.sh`; the estimate's ramp-up with Chrome as
receiver (probing): `tools/interop/webrtc/bwe.sh`; headless Firefox in both
offer directions (data channels against usrsctp): `tools/interop/webrtc/firefox.sh`; coturn's DTLS
listener (`Endpoint`s relayed through it over `turns:...?transport=udp`):
`tools/interop/webrtc/turn-dtls.sh`. STUN and TURN servers are in
[`only-turn`](../only-turn/README.md).

Not implemented: FlexFEC on simulcast lines (RID-based simulcast signals no FEC stream; Chrome
sends none), SRTP MKIs (DTLS-SRTP has no SDP for them and no browser uses them; SDES lines with
an MKI are not taken either), SDES-SRTP without ICE or with data channels, RFC 6904 with
browsers (none offers it), several ICE components (rtcp-mux is universal). Browsers and pion have no simultaneous-open ICE-TCP
candidates: `listen_tcp_so` is tested between `Endpoint`s.

Guide: [WebRTC, STUN and TURN](https://lesismal.github.io/only/en/protocols/webrtc.html).
