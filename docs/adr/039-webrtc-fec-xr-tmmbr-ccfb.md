# ADR-039: FEC, RTCP XR, TMMBR and RFC 8888 feedback in akio-webrtc peers

[中文](039-webrtc-fec-xr-tmmbr-ccfb.zh-CN.md)

Status: accepted (2026-11-19)

## Context

ADR-036 gave `akio-rtp` RTCP extended reports (RFC 3611), TMMBR / TMMBN (RFC 5104), RTP
congestion control feedback (RFC 8888) and FEC (ULPFEC, FlexFEC, RED), but `akio-webrtc`'s peers
neither negotiated nor used any of it. Wiring it in means SDP (payload types, an FEC SSRC group,
feedback attributes), a FEC rate policy, a receive path that repairs packets before the frame
assembler and NACK, and RTCP scheduling. Browsers matter most: anything that changes what a
default peer offers or answers could change what Chrome sends.

What Chrome 157 does, found against it (`tools/interop/webrtc/fec.sh`):

- It offers `red` / `rtx` / `ulpfec` for video by default and `flexfec-03` only with the field
  trial `WebRTC-FlexFEC-03-Advertised` (sending FlexFEC needs `WebRTC-FlexFEC-03`). Once an answer
  accepts `red`, Chrome sends every video packet in RED; ULPFEC protects the packet with the RED
  header removed (header extensions as sent).
- It offers `a=rtcp-fb:<pt> ack ccfb` (with `WebRTC-RFC8888CongestionControlFeedback`) on every
  payload type, RTX and FEC ones included, next to `transport-cc`. It sends RFC 8888 feedback only
  when the answer carries `ack ccfb` on every payload type of the section; while the
  transport-wide header extension is negotiated it otherwise keeps sending transport-wide
  feedback.
- It answers a receiver reference time (XR RRTR) with DLRR, accepts `a=rtcp-xr:rcvr-rtt=all`, and
  honours TMMBR (its send rate follows it, TMMBN in reply) without `ccm tmmbr` in the SDP.
- Its receiver reports give the loss before FEC repair, and retransmitted packets count as
  received.

## Decision

1. **Opt-in configuration** (`RtcConfig`, all off by default, so a default peer's SDP and
   behaviour are unchanged): `enable_fec(Option<FecMechanism>)` with `FecMechanism::{FlexFec,
   Ulpfec}` (`#[non_exhaustive]`), `set_fec_protection(min, max)` (protection factor bounds in
   FEC packets per 256 media packets, default 0..=128), `enable_ccfb`, `enable_rtcp_xr`,
   `enable_tmmbr`. `Peer::request_max_bitrate(mid, Option<u64>)` sends TMMBR.
2. **SDP.** On video lines without simulcast: FlexFEC is `flexfec-03/90000` (PT 115, `fmtp
   repair-window=10000000`, `transport-cc` feedback) with `a=ssrc-group:FEC-FR <media> <fec>` and
   the FEC SSRC's `a=ssrc` lines while the line sends; ULPFEC is `red/90000` (116) with its RTX
   (117, `apt=116`) and `ulpfec/90000` (118). An answer takes the remote's payload types of the
   configured mechanism only (ULPFEC needs both `red` and `ulpfec`). `ack ccfb` is added to every
   codec's feedback (audio too), `ccm tmmbr` and libwebrtc's `rrtr` to video's, and
   `a=rtcp-xr:rcvr-rtt=all` to the section; feedback is the intersection with the remote's as
   before. When `ack ccfb` is negotiated the answer drops `transport-cc` and the transport-wide
   extension and repeats `ack ccfb` on every payload type of the section (RTX, RED, FEC), which
   is what makes Chrome switch.
3. **Sending FEC.** One `FecEncoder` per sending line, made on the first protected write. ULPFEC:
   every media packet goes out as RED (primary block only) and the encoder gets it with RED
   removed; FEC payloads go out as RED blocks with the ulpfec payload type on the media SSRC (so
   they take media sequence numbers and are retransmittable). FlexFEC: FEC payloads go out on the
   line's own FEC `SendStream`. Both carry fresh mid / transport-wide / abs-send-time extensions.
   NACKs of RED packets are answered with the RED RTX payload type.
4. **Rate policy.** The protection factor is `3 × loss` (0 below 1 %), clamped to the configured
   bounds; `loss` is smoothed (EWMA ½) over receiver reports about the protected stream and is the
   larger of the reported fraction lost and the share of packets retransmitted since the previous
   report, because NACK repairs losses before the report would show them. Reports with nothing
   sent since leave it alone. libwebrtc's tables and its NACK / FEC hybrid (no FEC below ~20 ms
   RTT) are not copied; with `min` the factor can be held up.
5. **Receiving FEC** happens before the frame assembler and NACK: a FlexFEC packet (by payload
   type; the protected SSRC from its header) or a ULPFEC block in RED goes to the decoder of the
   protected stream (at most 4 decoders per peer, about 1.5 MB each); media packets (RED removed) are recorded in it; rebuilt packets enter the
   receive stream through `RecvStream::receive_recovered` (new in akio-rtp: no longer missing, so
   not NACKed, but not counted as received, so reports keep the loss before repair as Chrome's
   do) and then the assembler. A ULPFEC packet's sequence number, and that of a padding-only
   packet, is marked with `FrameAssembler::skip` (new in akio-rtp) so it is not a gap the
   assembler has to wait out. Retransmitted packets are not fed to the decoder (their extensions
   differ from the protected originals).
6. **RFC 8888.** When negotiated on any line, received RTP (all SSRCs) goes to a `CcfbReceiver`
   polled every 50 ms instead of the transport-wide one, every sent RTP packet is logged in a
   `CcfbSender`, and RFC 8888 feedback drives the bandwidth estimator (transport-wide feedback is
   then ignored, so nothing is counted twice).
7. **XR.** Lines with XR negotiated that receive put a receiver reference time block in their
   reports; received RRTRs are always answered with one DLRR per report round; a DLRR naming one
   of our SSRCs gives the receiver-side RTT, which paces NACKs and appears in statistics.
8. **TMMBR.** Requests about our streams go to one `TmmbrHandler` per sent SSRC (at most 16), are
   answered with a TMMBN every time, and the bound (at the stream's measured packet rate) caps
   the bandwidth estimate together with REMB; changes are reported as events. Our own request is
   repeated with every report while set, and withdrawn with a TMMBR of 0.
9. **RTCP clock.** RTCP NTP times now follow the peer's `Instant`s from an anchor taken at
   creation (`Rtc::ntp`) instead of reading the wall clock at each use, so SR / RR, DLRR and RFC
   8888 arithmetic is monotonic and simulated-time tests measure real RTTs.

## Consequences

- Additive public API: `FecMechanism`, five `RtcConfig` methods, `Peer::request_max_bitrate`;
  akio-rtp gains `RecvStream::receive_recovered` and `FrameAssembler::skip` (Internal tier).
  Default configurations produce the same SDP as before; `tools/interop/webrtc/browser.sh` and
  `run.sh` pass unchanged.
- Chrome 157 (with the field trials above): FlexFEC and ULPFEC both ways (with one RTP packet in
  20 dropped each way and NACK removed, Chrome decodes 381–392 of 400 frames instead of 8, and
  the server rebuilds 50–55 packets from Chrome's FEC), RFC 8888 both ways, XR DLRR RTT, TMMBR
  (Chrome's send rate 136 kbps under a 150 kbps request).
- Default-configuration media throughput is unchanged (gpu51 same-run A/B, two loopback
  `Endpoint`s: 0.996x of main); protection costs what it sends (64/256: 80-84 MB/s of goodput
  against 92).
- Not done: FEC on simulcast lines and audio (Opus RED), libwebrtc's mask tables and RTT-aware
  hybrid, FEC overhead accounted in the estimate, ECN in RFC 8888 reports (not read from the
  socket here), XR blocks other than RRTR / DLRR on the wire, telling a lost ULPFEC packet from
  lost media in the assembler (without NACK such a gap is waited out like any other loss).
