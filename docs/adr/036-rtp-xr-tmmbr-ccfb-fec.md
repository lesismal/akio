# ADR-036: RTCP XR, TMMBR / TMMBN, RFC 8888 feedback and FEC in akio-rtp

English | [简体中文](036-rtp-xr-tmmbr-ccfb-fec.zh-CN.md)

Status: accepted (2026-11-18)

## Context

`akio-rtp` (the media layer of the in-house WebRTC stack) listed as not implemented: RTCP
extended reports (RFC 3611), TMMBR / TMMBN (RFC 5104), RTP congestion control feedback
(RFC 8888) and forward error correction (ULPFEC, FlexFEC). Each of them is a wire format plus a
piece of state; none needs I/O, so all of them fit the crate's sans-io shape. `akio-rtp` is an
Internal-tier crate (docs/api-stability.md): its API may change, but changes are recorded.

Two format questions had to be settled first:

- **FlexFEC.** Chrome negotiates FlexFEC as `flexfec-03` (behind the field trials
  `WebRTC-FlexFEC-03` / `-Advertised`). libwebrtc's `ForwardErrorCorrection::CreateFlexfec` uses
  `Flexfec03HeaderReader/Writer`, which is *not* RFC 8627: after the 8 recovery bytes it carries
  `SSRCCount` (= 1) and three reserved bytes, then the protected SSRC and the sequence number
  base, and its mask K bit is 1 on the **last** segment (masks of 15, 46 or 109 bits). RFC 8627
  §4.2.2.1 moves the protected SSRCs into the CSRC list of the FEC packet's RTP header, starts
  the mask right after the SN base, and its k bit is 1 when **another** segment follows (15, 46
  or 110 bits). libwebrtc also has an RFC 8627 reader/writer, unused for `flexfec-03`. Both
  protect everything after the 12-byte fixed header of each media packet.
- **RFC 8888 `num_reports`.** libwebrtc's `CongestionControlFeedback` writes and reads it as the
  number of 16-bit metric blocks for the stream (`begin_seq` .. `begin_seq + num_reports - 1`),
  padded to 32 bits per stream, with no media-SSRC field after the sender SSRC; the packet ends
  with the 32-bit report timestamp (middle 32 bits of NTP).

## Decision

1. **RTCP.** `Rtcp` gains `ExtendedReport { ssrc, blocks: Vec<XrBlock> }` (PT 207),
   `Tmmbr` / `Tmmbn { sender_ssrc, entries: Vec<TmmbItem> }` (205/3, 205/4; the media SSRC
   field is written 0 and ignored) and `CongestionControl(CcfbFeedback)` (205/11). `XrBlock`
   covers every RFC 3611 block: loss and duplicate RLE (raw chunks, trailing null chunk
   dropped), packet receipt times, receiver reference time, DLRR, statistics summary (flags as
   `Option`s; ToH 3 is treated as not reported) and VoIP metrics (raw fields), with
   `XrBlock::Unknown` for other types. Parsing stays strict about lengths and never panics;
   writing truncates lists that cannot fit a 16-bit length, clamps TMMB overheads to 9 bits and
   ATOs to 13, and saturates oversized TMMB exponents like REMB.
2. **XR state.** `RrtrResponder` (media sender) remembers the last RRTR of up to 32 receivers
   for a minute and answers with a DLRR block; `rtt_from_dlrr` and `RecvStream::handle_dlrr`
   give a receiver without sender reports its RTT (which also paces its NACKs).
   `RecvStream::statistics_summary` reports the interval since the previous call (lost,
   duplicate, min / max / mean / deviation of the transit time differences; TTLs are not known
   at this layer) and `RecvStream::duplicates` counts duplicates. `BurstLossModel` is the burst
   / gap model of RFC 3611 Appendix A.2 for the VoIP metrics block; the call starts in a gap
   (first loss judged as after Gmin packets), which reproduces the §4.7.2 example exactly,
   while the literal algorithm (state "burst" at the start) does not. Level, quality and jitter
   buffer fields are left "unavailable" for the application.
3. **TMMBR.** `bounding_set` computes the RFC 5104 §3.5.4.2 bounding set as the lower envelope
   of the lines `bitrate - 8 * overhead * packet_rate` over packet rates >= 0 (cut where a line
   reaches zero; zero bitrates ignored); `bounded_bitrate` evaluates it. `TmmbrHandler` keeps
   the latest request per requester for one media SSRC (0 bit/s withdraws, 25 s timeout as in
   libwebrtc, 64 requesters), says when the bounding set changed and builds the TMMBN whose
   entries name their owners.
4. **RFC 8888.** `CcfbReceiver` records arrivals per media SSRC (with ECN) and emits feedback
   every 50 ms (settable) or at 100 pending packets, at most 500 reports per packet, each packet
   once; the ATO is `now - arrival` in 1/1024 s with the over-range / unavailable values.
   `CcfbSender` logs sends per SSRC and maps reports onto `PacketResult`s (arrival =
   unwrapped report timestamp - ATO, anchored to local `Instant`s as for TWCC; results ordered
   by a send index across streams), so `BandwidthEstimator` runs on RFC 8888 as on TWCC.
   Packets reported with an over-range or unavailable ATO leave the log without a result.
5. **FEC** (module `fec`, public). `FecScheme::{Ulpfec, Flexfec03, Flexfec}` selects the header:
   ULPFEC (RFC 5109, one level, 16/48-bit mask, protection length = longest packet),
   libwebrtc's `flexfec-03`, or RFC 8627 with flexible masks (one protected SSRC; the caller
   puts it in the CSRC list). The parity covers P/X/CC, M/PT, length - 12, timestamp and every
   byte after the fixed header (CSRCs, extensions, payload, padding), so recovered packets are
   byte-identical. `FecEncoder` groups the outgoing media packets of one SSRC per frame (at
   most `MAX_FEC_GROUP` = 48, as libwebrtc) and emits `round(k * rate / 256)` (at least 1)
   interleaved FEC payloads (`interleaved_masks`: FEC i protects packets j ≡ i mod m, so bursts
   up to m are recoverable); `encode` takes explicit masks. `FecDecoder` keeps 1024 sequence
   numbers of media and 64 FEC payloads and rebuilds every packet that is the only one missing
   from some FEC packet, iterating as recoveries complete others. `FecHeader` exposes the
   parsed header. `fec::red` parses and writes RFC 2198 payloads and wraps / unwraps a packet's
   primary block, the way WebRTC carries ULPFEC (FEC protects the un-RED'd media packets). FEC
   payloads are returned bare: the caller sends them through a `SendStream` / RED on the right
   SSRC, so header extensions (mid, transport-wide sequence numbers) work as for media.
6. **Tests and fuzzing.** Byte-exact against libwebrtc's unit-test vectors (TMMBR, TMMBN, RRTR,
   DLRR, the empty XR, the FlexFEC-03 writer and reader masks, the ULPFEC header reader), the
   RFC 3611 §4.7.2 burst example, hand-assembled RFC 8888 packets, round trips of every block,
   handler tests, RFC 8888 feedback driving the bandwidth estimator on a simulated two-stream
   link with loss, and FEC recovery (bursts within a group, 5 % random loss over 5000 packets
   per scheme, ULPFEC through RED) checking recovered packets byte for byte. The `rtp_rtcp`
   fuzz target drives the new packets into the new handlers; the new target `rtp_fec` parses
   and rewrites FEC headers and RED, feeds a decoder arbitrary media / FEC, and runs an encoder
   → lossy decoder round trip asserting byte-identical recovery.

Not done: wiring into `akio-webrtc`. It needs SDP work (`a=rtcp-fb:* ack ccfb` and switching
the estimator's feedback source; `flexfec-03` with an `a=ssrc-group:FEC-FR` FEC SSRC, or `red` +
`ulpfec` payload types; `a=rtcp-xr`), a FEC protection-rate policy tied to the estimator, and
TMMBR / XR in the RTCP scheduler, so it was not small; without it Chrome cannot be checked
against FlexFEC or RFC 8888 (Chrome only sends either when negotiated). Also not done: FlexFEC
retransmission (R) and fixed L/D (F) packets, multiple protected SSRCs, ULPFEC level 1,
libwebrtc's random / bursty mask tables (masks are interleaved), generating loss / duplicate RLE
and receipt-time blocks, and VoIP quality fields (R factor, MOS).

## Consequences

- Additive except for the `Rtcp` enum, which gains four variants (it is not `#[non_exhaustive]`;
  in-tree matches already had wildcard arms). Packets that used to parse as `Rtcp::Unknown`
  (PT 207, RTPFB 3 / 4 / 11) now parse into the new variants, and malformed ones of these types
  are now errors.
- No new dependencies; everything stays `#![forbid(unsafe_code)]`.
