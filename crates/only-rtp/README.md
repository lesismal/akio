# only-rtp

[中文](README.zh-CN.md)

RTP and RTCP for [`only`](https://github.com/lesismal/only) in safe Rust
(`#![forbid(unsafe_code)]`) with no dependencies: packets, RTCP feedback, per-stream send /
receive state with NACK and RTX, transport-wide congestion control and bandwidth estimation,
and codec payload formats. It is the media layer of the in-house WebRTC stack (below it,
[`only-srtp`](../only-srtp) encrypts). An internal crate (docs/api-stability.md): its API
follows that stack and may change in any release.

## Driving it

Everything is sans-io: methods take packets and `Instant`s and return packets. Randomness
(SSRCs, initial sequence numbers) comes from the caller.

```rust,ignore
use only_rtp::*;

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
  <2 % increase), REMB cap, bounds.
- `codec`: packetizers / depacketizers (Opus and other audio, VP8, VP9, H.264, H.265, AV1)
  and frame assembly.

## Protocol coverage

- Header extensions: mid, rtp-stream-id, repaired-rtp-stream-id, abs-send-time,
  transport-wide-cc, ssrc-audio-level, video-orientation, toffset, playout-delay.
- RTCP: SR, RR, SDES, BYE, generic NACK, transport-wide CC feedback (run-length and both
  status-vector chunk kinds, small and large deltas), PLI, FIR, REMB; other packets are kept
  as `Rtcp::Unknown`. Parsing is strict about lengths and never panics.

Not implemented: RTCP XR, TMMBR / TMMBN, FEC (ULPFEC, FlexFEC), RFC 8888 feedback, probing in
the estimator, SDES items beyond type / text pairs.

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
- Fuzzing: target `rtp_rtcp` (header parse / write / parse, compound RTCP round trips,
  feeding streams and the TWCC sender) in `fuzz/`; `fuzzing::tests` replays its corpus on
  stable.
