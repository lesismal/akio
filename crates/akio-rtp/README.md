# akio-rtp

[中文](README.zh-CN.md)

RTP and RTCP for [`akio`](https://github.com/lesismal/akio) in safe Rust
(`#![forbid(unsafe_code)]`) with no dependencies: packets, RTCP feedback, per-stream send /
receive state with NACK and RTX, transport-wide and RFC 8888 congestion control feedback and
bandwidth estimation, RTCP extended reports, TMMBR / TMMBN, forward error correction (ULPFEC,
FlexFEC, RED), and codec payload formats. It is the media layer of the in-house WebRTC stack (below it,
[`akio-srtp`](../akio-srtp) encrypts). An internal crate (docs/api-stability.md): its API
follows that stack and may change in any release.

## Driving it

Everything is sans-io: methods take packets and `Instant`s and return packets. Randomness
(SSRCs, initial sequence numbers) comes from the caller.

```rust,ignore
use akio_rtp::*;

let map = ExtensionMap::default_video();            // or built from the SDP a=extmap lines
// Sending.
let mut send = SendStream::new(ssrc, 90_000, Some(rtx_ssrc), initial_seq);
let mut twcc_tx = TwccSender::new();
let mut bwe = BandwidthEstimator::new(1_000_000);
let ext = ExtensionValues { mid: Some(mid), transport_cc: Some(twcc_tx.next_seq()), ..Default::default() };
let pkt = send.write(now, pt, marker, timestamp, &payload, &ext, &map);
twcc_tx.on_sent(ext.transport_cc.unwrap(), now, pkt.len());
// RTCP from the peer.
for p in parse_compound(&rtcp)? {
    match p {
        Rtcp::Nack { lost, .. } => { for p in send.resend(now, &lost, Some(rtx_pt), &map) { /* send */ } }
        Rtcp::TransportCc(fb) => bwe.on_packet_results(now, &twcc_tx.on_feedback(now, &fb)),
        Rtcp::ReceiverReport { reports, .. } => { for r in &reports { send.handle_report_block(now, ntp_time(SystemTime::now()), r) } }
        Rtcp::Remb { bitrate, .. } => bwe.set_remote_estimate(bitrate),
        _ => {}
    }
}
// Receiving.
let h = RtpHeader::parse(&packet, &map).unwrap();
let ext_seq = recv.receive(now, h.sequence_number, h.timestamp);  // None: duplicate / too old
twcc_rx.on_received(h.ext.transport_cc.unwrap(), now);
if let Some(lost) = recv.poll_nack(now) { /* Rtcp::Nack { lost, .. } */ }
if let Some(fb) = twcc_rx.poll_feedback(now, local_ssrc, h.ssrc) { /* send it */ }
let rb = recv.report_block(now);                                   // for an RR / SR
```

- `RtpHeader::parse` / `write`: fixed header, CSRCs, padding (`padding_len`), and RFC 8285
  one-byte / two-byte header extensions (`write` uses the one-byte form when every id is at
  most 14 and every value 1..=16 bytes). `is_rtcp` demultiplexes RTP / RTCP (RFC 5761).
- `SendStream`: keeps the last 1024 packets / 2 s; `resend` answers NACKs with RTX
  (RFC 4588) or the original packets, each at most once per 10 ms; `sender_report` gives the
  SR sender info; `handle_report_block` computes the RTT from LSR / DLSR.
- `RecvStream`: extended sequence numbers across the 16-bit wrap, duplicates and packets more
  than 2048 behind rejected; report blocks (fraction / cumulative lost, jitter per RFC 3550
  A.8, LSR / DLSR); NACKs after a reordering wait of RTT/4 (5..20 ms), repeated every RTT
  (default 100 ms), at most 10 times or 1 s; `poll_timeout` says when to poll next.
- `TwccReceiver` builds feedback every 100 ms or 100 packets with libwebrtc's packing;
  `TwccSender` maps feedback onto sent packets as `PacketResult`s.
- `BandwidthEstimator`: GCC-like delay-gradient trendline with an adaptive threshold, AIMD
  rate control capped by the acknowledged bitrate, loss-based control (>10 % decrease,
  <2 % increase), REMB cap, bounds; and probing (ADR-050), like libwebrtc's: probe clusters at
  3 and 6 times the start rate then doubling while results keep up, every 5 s while
  application-limited, after a large drop of the estimate, and again after
  `on_network_change`. The caller sends what `poll_probe(now)` asks for (`probe_timeout()` says
  when) as RTX copies of recent media or padding (`SendStream::padding`), logs it with
  `TwccSender::on_sent_probe` / `CcfbSender::on_sent_probe` and reports it with
  `on_probe_sent`; the feedback (`PacketResult::probe`) measures the cluster's delivery rate,
  which lifts the estimate. `with_probing(false)` turns it off.
- `codec`: packetizers / depacketizers (Opus and other audio, VP8, VP9, H.264, H.265, AV1)
  and frame assembly.
- RTCP XR (RFC 3611): `RrtrResponder` answers receiver reference times with DLRR, and
  `RecvStream::handle_dlrr` / `rtt_from_dlrr` give a receiver without sender reports its RTT;
  `RecvStream::statistics_summary` builds statistics summary blocks; `ReceiptLog`
  (`RecvStream::enable_receipt_log` / `receipt_blocks`) builds loss RLE, duplicate RLE and
  packet receipt times blocks from the packets received, with thinning; `BurstLossModel` (RFC
  3611 A.2) fills the loss / burst / gap fields of VoIP metrics and, with `VoipQuality` (delays,
  levels, RERL, R / MOS when the application has them, PLC, jitter buffer), the whole block
  (`report`); `pcm_level_dbm0` measures signal and noise levels (ADR-053).
- E-model (ITU-T G.107, G.107.1 wideband, G.107.2 fullband; ADR-073, ADR-085, ADR-087):
  `EModel` rates a path's R factor, MOS-LQ and MOS-CQ from loss, burstiness and delay;
  `EModel::for_codec_rate` has G.113's planning values by codec and bitrate.
- Jitter buffer (ADR-087): `JitterBuffer<T>` plays single-packet (audio) frames out in order
  at adaptive playout instants. It handles reordering, duplicates, and late and overflow
  discards, all bounded, and gives its RFC 3611 configuration.
- SDES: `SdesItem` converts the `(type, text)` pairs of `Rtcp::SourceDescription` to typed
  items, PRIV with its prefix and value included, with constants for every registered type
  (CNAME .. MID); `random_cname` makes an RFC 7022 CNAME.
- TMMBR / TMMBN (RFC 5104): `TmmbrHandler` keeps each receiver's request for a media SSRC,
  computes the bounding set (`bounding_set`, `bounded_bitrate`) and builds the TMMBN.
- RFC 8888: `CcfbReceiver` builds congestion control feedback per media SSRC (with ECN), every
  50 ms or 100 packets; `CcfbSender` turns it into `PacketResult`s for the estimator, like TWCC.
- `fec`: `FecEncoder` / `FecDecoder` for ULPFEC (RFC 5109), FlexFEC as Chrome sends it
  (`flexfec-03`) and RFC 8627 FlexFEC: interleaved masks per frame (rate in 1/256), recovery of
  every packet that is the only one missing from some FEC packet, byte-identical; `fec::red`
  for RFC 2198 (ULPFEC in WebRTC travels in RED). ULPFEC also with several protection levels
  (RFC 5109 §7.4, ADR-053): `set_ulp_level0(Some(l0))` protects the first `l0` bytes of every
  packet with the interleaved FEC packets and the rest once per group; `encode_ulp` takes
  explicit levels; the decoder rebuilds packets range by range and returns them once complete.
  Levels are for receivers that implement them: libwebrtc reads level 0 only.

```rust,ignore
// FlexFEC: protect each frame with ~30 % FEC, recover on the other side.
let mut enc = FecEncoder::new(FecScheme::Flexfec03, media_ssrc, 77);
for payload in enc.push(&rtp_packet, marker) { /* send on the FEC SSRC */ }
let mut dec = FecDecoder::new(FecScheme::Flexfec03, media_ssrc);
for p in dec.on_media(&received) { /* a recovered RTP packet */ }
for p in dec.on_fec(fec_payload) { /* ... */ }
```

## Protocol coverage

- Header extensions: mid, rtp-stream-id, repaired-rtp-stream-id, abs-send-time,
  transport-wide-cc, ssrc-audio-level, video-orientation, toffset, playout-delay.
- RTCP: SR, RR, SDES, BYE, generic NACK, transport-wide CC feedback (run-length and both
  status-vector chunk kinds, small and large deltas), RFC 8888 congestion control feedback,
  PLI, FIR, REMB, TMMBR, TMMBN, and extended reports with every RFC 3611 block (loss and
  duplicate RLE, receipt times, RRTR, DLRR, statistics summary, VoIP metrics); other packets
  are kept as `Rtcp::Unknown` (and unknown XR blocks as `XrBlock::Unknown`). Parsing is strict
  about lengths and never panics.
- FEC: ULPFEC (any number of protection levels), FlexFEC `flexfec-03` (libwebrtc's header) and
  RFC 8627 (flexible masks, one protected SSRC), RED. ADR-036 and ADR-053 have the details.
- SDES items: every registered type (RFC 3550 §6.5, IANA), PRIV's prefix / value, texts cut at
  a character boundary.

`akio-webrtc` negotiates and uses all of these when configured to (ADR-039); for it
`RecvStream::receive_recovered` records FEC-rebuilt packets (not NACKed, still lost in reports)
and `FrameAssembler::skip` marks sequence numbers without media (ULPFEC, padding) so they are not
gaps.

Not implemented: FlexFEC retransmission and fixed L/D packets, several protected SSRCs,
libwebrtc's mask tables; handing out partially recovered packets; a jitter buffer for
multi-packet (video) frames.

## Testing

- Byte-exact checks against pion: RTP headers with one-byte and two-byte extensions and
  padding (pion/rtp v1.10.6); SR, RR, NACK, PLI, FIR, REMB, SDES, BYE and a compound packet
  (pion/rtcp v1.2.20); transport-wide feedback from pion/interceptor's TWCC recorder,
  including a wrap, gaps, reordering and large deltas, which `TwccReceiver` reproduces byte
  for byte from the same arrivals.
- Round trips of every RTCP type and of headers in both extension forms with CSRCs and
  padding; malformed headers, extensions and RTCP lengths.
- Streams: RTX format, history bounds, SR extrapolation and RTT, rollover and reordering,
  loss statistics, jitter, NACK scheduling (reordering wait, recovery, RTT-paced repeats,
  give-up, discontinuities) and a simulated lossy link with NACK / RTX recovering every
  packet.
- TWCC end to end over 70 000 packets with loss; the estimator on simulated links grows on a
  clean link, settles below a 1 Mbps bottleneck and backs off under 25 % loss.
- Probing on simulated links (an encoder following the estimate, a drop-tail bottleneck, 20 ms
  each way; start 300 kbps), with / without probing: 90 % of 0.5, 2 and 10 Mbps after 0.15 /
  0.25 / 0.35 s instead of 5.4 / 23 / 44 s, peaks at most 1.12x the capacity; a 10 -> 2 -> 10
  Mbps step recovered in 3.6 s (never within 30 s without); 5 % loss, 15 % loss, competing
  traffic, an application-limited encoder; 40 seeds; cluster pacing and measurement, padding
  packets.
- libwebrtc unit-test vectors: TMMBR, TMMBN, RRTR, DLRR and the empty XR byte for byte; the
  FlexFEC-03 masks its writer produces and its reader accepts; its ULPFEC header reader cases.
  The RFC 3611 §4.7.2 burst example (loss, discard, burst / gap density and duration); RFC 8888
  packets assembled from §3.1; round trips of every XR block; bounding sets.
- ADR-053: the RFC 5109 §10.2 two-level example byte for byte (erratum 3461), every single loss,
  level 1 before level 0, two losses, the §7.4 rules, the level-0 mode over 400 lossy frames;
  the RFC 3611 §4.1 RLE examples from received packets; loss / duplicate RLE and receipt times
  blocks byte for byte against pion/rtcp v1.2.20 (even chunk counts: pion leaves out the null
  chunk of odd ones); RLE encode / decode of 300 random traces with thinning and wraparound;
  receipt logs across the wrap; VoIP report fields and PCM levels; SDES with PRIV, MID and
  RtpStreamId byte for byte against pion/rtcp v1.2.20; RFC 7022 CNAMEs.
- RFC 8888 feedback driving the estimator on a simulated two-stream link with loss; FEC
  recovery for every scheme (bursts within a group, 5 % random loss over 5000 packets, ULPFEC
  through RED), each recovered packet compared byte for byte.
- Fuzzing: targets `rtp_rtcp` (header parse / write / parse, compound RTCP round trips,
  feeding streams, the TWCC and RFC 8888 senders, the RRTR responder and the TMMBR handler, SDES
  items, RLE re-encoding, VoIP reports, receipt logs) and `rtp_fec` (FEC headers with ULPFEC
  levels and RED parse / rewrite, decoder on arbitrary input, encoder → lossy decoder recovery,
  also in the level-0 mode and with explicit levels) in `fuzz/`; `fuzzing::tests` replays their corpora on stable.
