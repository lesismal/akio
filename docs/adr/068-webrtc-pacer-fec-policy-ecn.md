# ADR-068: A pacer, libwebrtc's FEC masks and protection policy, ECN in RFC 8888, and more probing

English | [简体中文](068-webrtc-pacer-fec-policy-ecn.zh-CN.md)

Status: accepted (2026-11-21)

## Context

The congestion control and FEC work of ADR-036, ADR-039, ADR-048, ADR-050, ADR-053 and ADR-058
left these open (DEV-PLAN, section 3):

- **No pacer.** only-webrtc sent every packet of a frame the moment it was written, so a keyframe
  left as one burst whatever the estimate; only the estimator's probe clusters were paced.
- **Probing** started over only at the start, in application-limited periods and after drops; a
  raised maximum was not probed, and libwebrtc's network-state-estimate probing was missing.
- **FEC masks and rates.** The encoder used interleaved masks for every group and a protection
  factor of three times the loss; libwebrtc uses tables optimised per group size and a policy
  that weighs the loss against the bits per frame and, with NACK, the round-trip time.
- **ECN.** RFC 8888 reports carry an ECN codepoint per packet, which only-rtp could write but
  only-webrtc always reported as 0 (not ECN-capable), and the estimator ignored.
- **FEC on simulcast lines** was ULPFEC only; **RED** was Opus only, and video RED without
  ULPFEC was not accepted.
- **Partially rebuilt packets** (ULPFEC levels, ADR-053) were never handed out, and the VoIP
  metrics block (ADR-058) sent the R factor and MOS as unavailable.

## Decision

### 1. Pacer (only-webrtc, `rtc/pacing.rs`)

libwebrtc's `PacingController`, reduced to what a sans-io peer needs:

- While the estimator runs (`RtcConfig::enable_bwe`) and pacing is on (`enable_pacing`, default
  on), video, FEC and retransmissions leave through a queue drained at **2.5 times the
  estimate** (libwebrtc's pace multiplier) with a **burst allowance of 40 ms** at that rate: a
  frame that fits leaves at once, a larger one (a keyframe) is spread out. Retransmissions go
  before new media. **Audio is never queued**: it is sent at once and counted against the budget
  (libwebrtc's default, which keeps audio latency independent of video). The debt is capped at
  500 ms; elapsed time is credited up to 2 s; a queue whose oldest packet would wait more than
  2 s drains faster (libwebrtc's `drain_large_queues`).
- The transport-wide sequence number and abs-send-time are written **when a packet leaves**
  (placeholders at write time, patched in place in the RFC 8285 extension block before SRTP), so
  feedback measures paced send times; RFC 8888 send records are taken then too.
- **Padding**: `set_padding_rate` (default 0) sends RTX copies of recent media, or padding-only
  packets, while the queue is empty, within the estimate.
- **Probes** keep their own pace (ADR-050); a probe slot takes queued media before padding is made
  for it, as libwebrtc's clusters carry media.
- The queue is bounded: 8192 packets and 8 MB, the oldest media dropped beyond that (counted in
  the statistics as `paced_dropped`); an application that writes far above the estimate loses
  frames instead of building seconds of delay. `poll_output`'s timeout includes the next send
  time, so the endpoint's timer drives it.
- Without the estimator nothing is queued: the send path is the one before, apart from the
  send-time extensions being written as the packet leaves.

### 2. Probing (only-rtp `BandwidthEstimator`)

- `set_bounds(now, min, max)` changes the bounds at run time; a maximum raised above the old one
  and the estimate probes at the new maximum once the initial probing is over (libwebrtc's
  `SetBitrates`). only-webrtc: `RtcConfig::set_bwe_bounds`, `Peer::set_bitrate_bounds`.
- **Network state estimate** (libwebrtc's `ProbeController` with a `NetworkStateEstimate`):
  `set_network_state_estimate(Some(upper))` caps every probe at `max(estimate, upper)`, lets a
  further probe follow only results below 70 % of it, and probes at twice the estimate (capped
  at it) every 5 s while the estimate is below it, and every 3 s while the delay-based rate holds
  the estimate below 70 % of it (the values libwebrtc's field trials use). Without one, the
  estimator's own **link capacity estimate** (libwebrtc's `LinkCapacityEstimator`: the
  acknowledged rate at over-use, smoothed with 0.05, and probe results with 0.5, plus three
  normalised deviations; `link_capacity()`) drives the 3 s probes, but caps nothing (it would
  stop the estimate from finding a link that got faster). only-webrtc feeds no external estimate
  (no browser sends one by default).
- **ECN**: `PacketResult::ecn` (from RFC 8888 feedback; `None` with transport-wide feedback); a
  packet that arrived marked CE counts as lost for the loss-based control (the classic response,
  RFC 3168 §5); `ecn_counts()` reports ECT and CE arrivals.

### 3. libwebrtc's FEC masks, group rules and protection policy (only-rtp `fec`)

- `packet_masks(k, m, FecMaskType::{Random, Bursty})`: libwebrtc's mask tables for groups of up to
  12 packets (`fec_private_tables_random.cc` / `_bursty.cc`, BSD-licensed, converted by a script,
  values unchanged; source in `fec/tables.rs`), interleaved masks above 12, as
  `PacketMaskTable::LookUp`. `FecEncoder` uses them (random by default, as Chrome).
- `FecProtection { delta_rate, key_rate, max_frames, mask }` and `FecEncoder::{set_protection,
  push_frame}`: key frames get their own factor; a group spans up to `max_frames` frames and
  closes earlier at a frame end once its FEC packets come within 50 / 256 of the factor and it
  has enough packets (libwebrtc's `UlpfecGenerator`: 4 when the factor is above 80, one more when
  frames average two packets or more). With ULPFEC levels groups stay one frame.
- `ProtectionPolicy` / `protection_factors`: libwebrtc's `VCMFecMethod` and `VCMNackFecMethod`
  (`media_opt_util.cc`) with `FecControllerDefault`'s inputs: the code rate from libwebrtc's
  6450-entry table for the loss and the bits per frame (resolution-adjusted, 704 x 576 when
  unknown), at least 20 % on delta frames with loss and multi-packet frames, key frames boosted
  by their size (at least twice), at most 50 %, converted to a factor; the loss is the maximum of
  the last 10 s (per-second maxima). With NACK (the hybrid): no FEC on delta frames below 20 ms of
  RTT, groups of `2 x framerate x RTT` frames (1..=6), no FEC at all for frames under 400 / 700 /
  1000 bytes (CIF / VGA / larger) below 200 ms. The policy measures frames, packets and bytes over
  the last second itself.
- only-webrtc: one policy per sent stream (per simulcast encoding), fed with every written frame
  (keyframes detected by the depacketizer), the receiver's loss (reported, or the NACKed share,
  as before) and the RTT; NACK is whether the codec negotiated `nack`. `set_fec_protection(min,
  max)` now bounds the policy's factors (it was the 3 x loss rule's bounds); `set_fec_mask`
  picks the tables.

### 4. ECN in RFC 8888 reports (only-webrtc)

The endpoint's UDP receive path already reads the codepoint (`IP_TOS` / `IPV6_TCLASS` control
messages, ADR-013 / ADR-035; `Conn::rx_ecn`); `RtcUdp::on_data` now passes it with each datagram
to the peer, and RFC 8888 feedback reports it per packet (`CcfbReceiver::on_received` had the
parameter). No only-core change. Datagrams from ICE-TCP and TURN relays report 0. The statistics
count ECN-capable and CE arrivals and the CE marks the remote's feedback reports. Sending ECT is
not done: only-webrtc's output does not carry a codepoint to the socket (see below).

### 5. FlexFEC on simulcast lines, RED for other codecs, video RED without FEC

- **FlexFEC on simulcast lines**: each encoding has its own FlexFEC stream and protection; the
  streams are unsignaled (RID simulcast signals no SSRCs) and carry the MID and the RID they
  repair (`repaired-rtp-stream-id`, RFC 8852); the receiver routes them by MID and finds the
  protected stream in the flexfec-03 header, so no SDP beyond the `flexfec-03` payload type is
  needed. Our peers only: browsers do not receive simulcast, and libwebrtc sends no FlexFEC with
  simulcast.
- **RED for other audio codecs**: `RtcConfig::enable_audio_red(Some(n))` offers and accepts
  `red/8000` for PCMU, PCMA and G.722 (payload types 110, 112, 113, listed before the codec,
  `fmtp <red> <codec>/<codec>`), sends up to two earlier packets in each (the Opus RED builder,
  ADR-048, with the history cleared when the codec changes) and takes received RED apart.
- **Video RED without FEC**: `FecMechanism::Red` offers `red` (with its RTX) and no `ulpfec`;
  received `red` without `ulpfec` is accepted with `Ulpfec` too, and media goes out in RED
  without FEC packets.

### 6. Partial packets and the E-model

- `FecDecoder::take_partials(ts)` hands out packets rebuilt only in part (their header and a
  known start), truncated, P bit cleared, once a media packet of another timestamp arrives (the
  FEC for the earlier frame has normally come by then). `FrameAssembler::push_partial` puts one
  in place of the lost packet; its frame is emitted with `Frame::partial` (if the depacketizer
  accepts the truncated payload). only-webrtc does this on video lines outside RTP mode; the
  frame's `MediaData::contiguous` is false; statistics count `fec_partial`.
- `EModel` (ITU-T G.107 with default parameters, Cole and Rosenbluth's delay impairment, the
  effective equipment impairment from the codec's `Ie` / `Bpl`, the loss and the burst ratio),
  `mos_from_r`, `EModelScore::apply`, `BurstLossModel::{loss_fraction, burst_ratio}`. only-webrtc
  fills the R factor, MOS-LQ and MOS-CQ of its VoIP metrics blocks from the interval's loss
  model, the RTT and the jitter (a jitter buffer of twice the jitter assumed), with G.711 +
  concealment codec values (the E-model has none for Opus).

### API

Additive in only-rtp (internal tier) except `PacketResult::ecn` and `Frame::partial` (struct
literals add `ecn: None` / `partial: false`): `fec::{FecMaskType, FecProtection, ProtectionPolicy,
PartialPacket, packet_masks, protection_factors}`, `FecEncoder::{set_protection, protection,
push_frame}`, `FecDecoder::take_partials`, `FrameAssembler::push_partial`,
`BandwidthEstimator::{set_bounds, bounds, set_network_state_estimate, link_capacity,
ecn_counts}`, `EModel`, `EModelScore`, `mos_from_r`, `BurstLossModel::{loss_fraction,
burst_ratio}`. only-webrtc, additive: `RtcConfig::{set_bwe_bounds, enable_pacing,
set_padding_rate, set_fec_mask, enable_audio_red}`, `Peer::set_bitrate_bounds`, `FecMask`,
`FecMechanism::Red` (the enum is `#[non_exhaustive]`). Changed behaviour: with the estimator on,
media is paced; FEC protection follows libwebrtc's policy (`set_fec_protection` bounds it);
FlexFEC is offered on simulcast lines; VoIP metrics carry R and MOS.

## Consequences

- Tests (simulated time): the pacer spreads a 60 kB keyframe at a 1 Mbps estimate (12 packets
  at once, the last after 156 ms against 150 ms computed, no 10 ms window over 5 packets) while
  an Opus packet written 5 ms in leaves at once; no queue without the estimator or with pacing
  off; queue order, burst arithmetic, the 2 s drain, the bound and padding budgets; send-time
  extensions patched in both header forms. A maximum raised from 500 kbps to 5 Mbps probes at once
  and the estimate passes 1.5 Mbps within a second. RFC 8888 feedback carries ECT(0) and one CE
  in ten to the sender (transport-wide feedback carries none). PCMU RED at 10 % loss: 297-298 of 300
  frames against 263-268 without. ULPFEC with a 40-byte level 0 at 15 % loss, no NACK: 26
  packets rebuilt in part handed out, 11 partial frames delivered.
  FlexFEC repairs simulcast encodings without NACK as ULPFEC does. Policy: libwebrtc's table
  values, the hybrid's RTT and frame-size rules, the 10 s loss maximum; masks against the C++
  tables; group closing rules; E-model values (R 93.2 / MOS 4.41 unimpaired, `Ie,eff` at 5 %
  loss), burst ratios. Estimator on simulated links: unchanged ramp-up figures (0.5 / 2 / 10 Mbps
  in 0.15 / 0.25 / 0.35 s); a raised maximum reached in 0.15 s; a 4 Mbps network state estimate
  holds probes there; 2 -> 10 Mbps recovery 1.6 s with an estimate set, 2.1 s without; 20 % CE
  marks cut the estimate as 20 % loss does.
- Chrome 157 (`tools/interop/webrtc/pacing.sh`, estimate capped at 300 kbps, a keyframe asked
  every 500 ms): the largest burst of RTP towards Chrome is 4 packets paced (no burst of 6 or
  more), 7 unpaced (15 bursts of 6+); Chrome decodes 299-300 of 300 frames, transport-wide and
  RFC 8888 feedback. `fec.sh` unchanged with the tables and the policy (ULPFEC 381/400, FlexFEC
  391/400 frames decoded at 5 % loss without NACK; RED, RFC 8888, TMMBR, per-layer ULPFEC pass).
- Real loss (`crates/only-webrtc/tests/netem.rs`, opt-in, Linux arm64 in Docker with `tc netem loss
  5%` on loopback, two `Endpoint`s, NACK removed): whole frames out of 300 without FEC 251,
  ULPFEC 300, FlexFEC 299, FlexFEC with the estimator and the pacer on 300.
- Benchmarks (gpu51, same-run A/B against the branch point, two loopback `Endpoint`s, one-way
  VP8): default configuration 0.999x; FEC held at 64/256, ULPFEC 0.993x and FlexFEC 0.994x
  (libwebrtc's masks XOR more packets per FEC packet). The policy is re-evaluated once a second
  and with each receiver report, not per frame (per frame cost 1-2 %).
- A paced sender adds latency to large frames by design (a keyframe at 1 Mbps takes 150 ms);
  libwebrtc behaves the same. An application must follow `EgressBitrateEstimate`: writing far
  above it now loses frames at the queue bound instead of flooding the path.
- Not done: sending ECT (only-webrtc's output would need a codepoint per datagram down to
  `UdpBinding::send_to` and the listener's connections, an endpoint-transport change); an
  external network state estimate source (libwebrtc's `RemoteEstimate` RTCP is not sent by
  browsers); libwebrtc's loss-based BWE v2 and its probe-limiting states; the
  unequal-protection (important packets) masks; partial packets in RTP mode.
