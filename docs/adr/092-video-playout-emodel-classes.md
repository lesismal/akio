# ADR-092: A video playout buffer, E-model delay classes and room noise, VoIP packet length and late discards

English | [简体中文](092-video-playout-emodel-classes.zh-CN.md)

Status: accepted (2026-11-23)

## Context

ADR-087 left these items in its "Not done" list:

- Video frames came from the frame assembler as soon as they were complete, with no playout
  timing.
- The delay sensitivity classes (`sT` / `mT`) were fixed at "default".
- The 03/2023 `Ro,FB` from room noise was not computed.
- Published Opus values were not used, and the monotic wideband tables were not a choice.
- The VoIP block's burst and gap durations assumed 20 ms packets.
- A packet discarded in a later report interval than the one that reported it lost was not
  matched.

The sources were read again: G.107 (06/2015), G.107.1 (06/2019 + Cor. 1), G.107.2 (06/2019
and 03/2023), G.113 (09/2024 + Erratum 1 of 01/2026). What they say:

- **Delay classes.** G.107 §7.4 Table 1 has three classes: Default (`sT` 1, `mT` 100 ms),
  Low (0.55, 120) and Very low (0.4, 150).
  - The default class "must be used" for carrier-grade and enterprise telephony, and whenever
    the users or the scenario are unknown. Any other class should be stated with the results.
  - G.107.2 (03/2023) has the same numbers under the names Default / Medium / Low, with the
    same rule.
  - G.107.1 has no classes: its `Idd` is the default one, times 1.29.
- **Room noise.** G.107.2 (03/2023) Eqs. 7-2 to 7-6 derive `Ro,FB` from noise, with `Nc` and
  `Nfo` at -96 dBm0p (Table 2). The room noise `Ps` / `Pr` has no default anywhere in that
  edition.
  - G.107's 35 dB(A) would give `Ro,FB` 121.5 in place of 148: 26.5 points lower for every
    fullband call.
  - G.107.1 lists `Ps` / `Pr` as "under study".
- **Monotic tables.** G.113 Table IV.1 gives provisional monotic (handset) `Ie,wb` for G.722
  (13 / 20 / 31 at 64 / 56 / 48 kbit/s), for G.722.2 by mode (41 at 6.6 .. 1 at 23.05, 8 at
  23.85) and for others. It gives no `Bpl,wb`; those appear only in the diotic tables.
- **Opus.** Opus appears nowhere in G.113 or P.833.2.
  - Alahmadi, Pocta and Melvin published instrumental (POLQA, P.834) `Ie` and `Bpl` values for
    narrowband and wideband Opus 1.2.1 (ISSC 2020, doi:10.1109/ISSC49989.2020.9180160), for low
    rates only: NB 6..11 kbit/s, WB 11..15 kbit/s.
  - The paper is paywalled. The values were read from the authors' open-access thesis (NUI
    Galway, 2020, Tables 5.8, 5.9, 5.13, 5.14), which reports them as published there.
- **EVS.** G.113 has EVS only in its SWB mode (Appendix V). Its NB and WB modes have no
  values.

## Decision

### 1. The video playout buffer (akio-rtp `VideoPlayout<T>`)

`VideoPlayout<T>` is sans-IO and holds the complete frames of one video stream, in decoding
order as the frame assembler gives them.

- **Input.** `push(ts, completed, flags, data, bytes)`. The flags (`VideoFrameFlags`) are:
  - `KEYFRAME`;
  - `DISCONTINUOUS` (packets missing before the frame);
  - `REPAIRED`: completed by a retransmission, or waiting behind a packet being repaired or
    given up.
- **Output.** `pop(now)` releases frames in order at their playout instants, and
  `poll_timeout()` says when the next one is due.
- **Playout.** A frame plays at `ts + offset`. The offset is the smallest transit time
  (completion minus media time, the minimum over two 5 s windows) plus the target delay.
  - A frame never plays before it is complete, or before the previous frame.
  - It never waits longer than the upper bound after it is complete.
- **Target.** The largest of:
  - the 95th percentile of each frame's delay beyond the smallest transit (2 ms buckets,
    forgetting by 0.997 per frame);
  - the delay of either of the two latest keyframes of the last 10 s.

  While frames needed repair in the last 10 s, the round-trip time is added
  (`set_round_trip`). Everything stays within `PlayoutDelay`'s bounds.
  - **Keyframes.** A keyframe is many times larger than the frames between, so it takes
    longer to arrive. Keyframes are too few to move a percentile, yet one late keyframe stalls
    every frame behind it.
  - **NACK.** Repaired frames stay out of the histogram (their delay is the repair's). The
    round trip leaves room for one retransmission, as libwebrtc's jitter estimate adds the RTT
    when NACK alone protects a stream.
- **Adapting.**
  - A longer delay applies at once.
  - A shorter one applies at once at a keyframe (the player can skip ahead where prediction
    starts over). Otherwise it shrinks by at most one frame interval per second.
  - A buffered frame that a shorter delay makes due plays at the moment of the change, not
    earlier.
- **Late frames** go out at once and are counted. They are not discarded: later frames are
  predicted from them.
- **Bounds.** At most 256 frames and 16 MiB.
  - When full, the frames before the first buffered keyframe after the oldest frame are
    dropped.
  - With no such keyframe, the oldest frame is dropped and `take_keyframe_request()` says a
    keyframe is needed.
  - The frame after a drop has `contiguous = false`.
- **Clock jumps.** If media time and completion time move more than 10 s apart between two
  frames, the buffered frames go out at once and the clock starts over (`resyncs`).
- **Statistics.** `VideoPlayoutStats`: received, played, late, repaired, dropped, resyncs,
  delay, target.
- **Shared estimator.** The audio `JitterBuffer` and `VideoPlayout` now share one delay
  estimator (`delay.rs`): the minimum windows and the forgetting histogram. The audio
  buffer's behaviour is unchanged.

akio-webrtc:

- `RtcConfig::set_video_playout_buffer(Option<PlayoutDelay>)`, off by default. It works in
  frame mode only.
- When on, the frames each video assembler completes go into the stream's buffer, and the
  peer's timer releases them.
  - `MediaData::playout_time` carries the instant.
  - A frame is flagged repaired when a packet that arrived on RTX released it, or when it came
    out with or after a frame following a gap.
  - The round-trip time is the stream's, on lines with `nack`.
  - Frames dropped without a keyframe to resume from send a PLI on lines with `nack pli`.
- A missing packet is still given up by the assembler's packet count
  (`set_reordering_size`), not by the playout deadline.
- `Peer::video_playout_stats(mid) -> Vec<(ssrc, VideoPlayoutStats)>`.

### 2. The E-model (akio-rtp)

- **`DelaySensitivity`** { `Default`, `Low`, `VeryLow` } with
  `EModel::with_delay_sensitivity` and `delay_sensitivity`.
  - `Idd` takes `sT` and `mT` (G.107 Eqs. 7-27 / 7-28; G.107.2 Eq. 7-8b, times 1.48).
  - A wideband model keeps the default class: G.107.1 has none.
  - In akio-webrtc, `RtcConfig::set_voip_delay_sensitivity` applies the class to the codec's
    model. A model the application gives keeps its own class.
- **`EModel::with_room_noise(send, receive)`** (dB(A), clamped to 0..=85). The receiver
  cannot measure room noise, so the application supplies it.
  - Narrowband: G.107's `Ps` / `Pr` feed `No`, which moves `Ro`, `Is` and the talker echo.
    35 is the default.
  - Fullband: `Ro,FB` comes from G.107.2 (03/2023) Eqs. 7-2 to 7-6. It is 121.48 at 35 dB(A),
    147.29 at 0 and 96.29 at 50.
  - Wideband: ignored.
  - Without room noise, fullband stays at 148, so ratings do not change silently.
  - `EModel::max_rating()` gives the top of the model's scale.
- **`EModel::for_codec_monotic(name, plc, bitrate)`.** G.722 and AMR-WB take Table IV.1's
  monotic `Ie,wb`, with the diotic `Bpl,wb` (the only one published). Other codecs are rated
  as by `for_codec_rate`.
- **`EModel::opus(OpusBand, bitrate)`**:
  - Narrowband: G.107 scale, VBR `Ie` 23 .. 11.7 and random-loss `Bpl` 24.6 .. 18.9 at 6..9
    kbit/s (thesis Tables 5.13 / 5.14).
  - Wideband: `Ie,wb` 28.4 .. 20 and `Bpl,wb` 23.9 .. 19.5 at 11..13 kbit/s (Tables 5.8 /
    5.9).
  - Fullband: ADR-087's values (DAGA 2021 `Ie,FB`, EVS's `Bpl,fb`).
  - Rates above the tabled ones keep the highest rate's values, which understates Opus there.
  - The RTP encoding name does not tell the band, so `for_codec_rate("opus", ..)` stays
    fullband. The application chooses the band through `Peer::set_voip_quality`'s model.
  - The CBR columns and the SWB table (on the 148 scale, `Rswb = 1.48 Rnb`) were not used:
    WebRTC Opus is VBR and fullband, and DAGA 2021 measured fullband.
- **EVS NB / WB** stay out: no values are published. This is documented in `for_codec_rate`.

### 3. VoIP metrics (akio-webrtc)

- **Packet length.** Each received audio stream measures its packet length from consecutive
  sequence numbers' timestamps (`PacketTime`). A step at most twice the current one replaces
  it, so a DTX silence is not taken for a packet.
  - The jitter buffer's frame length wins when there is one. 20 ms applies until a length is
    measured.
  - The length sets the burst and gap durations (rounded ms), the bitrate the E-model rates by,
    and the E-model's packet delay.
- **Late discards across intervals.**
  - The sequence numbers each report gave as lost are remembered: at most 1024, oldest
    dropped.
  - A discarded number outside the current interval that one of them names was reported lost
    and has since arrived late. `BurstLossModel::on_late_discard()` moves one count from loss
    to discard. The burst / gap state and the loss fraction the E-model uses do not change:
    both are losses to the model.
  - A packet reported lost that arrives later and is **played** stays counted as lost: the
    receipt log's interval has passed, and the burst model has no "not lost after all".

### API

The change is additive.

- akio-rtp:
  - `VideoPlayout`, `VideoPlayoutFrame`, `VideoPlayoutStats`, `VideoFrameFlags`.
  - `VIDEO_PLAYOUT_MAX_FRAMES`, `VIDEO_PLAYOUT_MAX_BYTES`.
  - `DelaySensitivity`, `OpusBand`.
  - `EModel::{with_delay_sensitivity, delay_sensitivity, with_room_noise, max_rating,
    for_codec_monotic, opus}`.
  - `BurstLossModel::on_late_discard`.
- akio-webrtc: `RtcConfig::{set_video_playout_buffer, set_voip_delay_sensitivity}` and
  `Peer::video_playout_stats`.

Behaviour changes without an API change:

- The XR VoIP block's durations and bitrate follow the measured packet length, not always
  20 ms.
- Late discards of packets reported lost in an earlier interval now count as discards.

## Consequences

- **Tests, akio-rtp `tests_video.rs`.** Frames from VP8 packets go through `FrameAssembler`
  and the buffer, under simulated jitter, reordering and loss:
  - 1800 frames under 0..40 ms of jitter: completions spread more than 30 ms, playout spread
    under 25 ms, at most 1 in 20 frames shown unevenly, delay 30..50 ms.
  - 1 % loss with retransmission at 60 ms RTT. Without the round trip, the target stays under
    30 ms and repaired frames are late. With it, the target is the RTT plus the jitter and late
    frames fall to a third or fewer.
  - 40-packet keyframes every 2 s: the target covers their 40 ms. A keyframe stalls the
    picture by at most the 10 ms of jitter.
  - The repair allowance expires after 10 s.
  - The delay shrinks at once at a keyframe, and at most a frame a second between keyframes.
  - Bounds: frames, bytes, keyframe-aware drops, keyframe requests.
  - Never held past the upper bound; clock jumps; timestamp wrap.
- **Tests, `tests_voip.rs`** (values computed from the equations independently of the code):
  - `Idd` per class: Low 2.253017 / 10.094228 at 200 / 300 ms; Very low 0.949825 / 6.178555
    at 200 / 300 ms.
  - Room noise: narrowband `Ro - Is` 93.3553 / 86.4917 / 70.4164 at 35 / 50 / 60 dB(A);
    fullband `Ro,FB` 121.4849 / 147.2859 / 96.2943 at 35 / 0 / 50 dB(A).
  - The monotic table rows, the Opus NB / WB rows, and NB Opus at 9 kbit/s with 2 % loss
    (`Ie,eff` 19.6713).
  - Durations scaling with the packet length, and `on_late_discard`.
- **Tests, akio-webrtc `tests_mux.rs`**:
  - Two peers with VP8 at 30 frames/s over 10..50 ms and 2 % loss, repaired by NACK / RTX.
    Every frame comes out in order at its playout instant. 91 % of frames are shown one frame
    interval apart, against 15 % of completions. The delay is about 80 ms (jitter plus a round
    trip).
  - A packet reported lost and discarded in the next interval: loss / discard rates go from
    (22, 0) without the match to (18, 3).
  - 40 ms packets give durations in 40 ms steps.
  - The three delay classes rate 250 ms in order.
- **Fuzzing.** The `rtp_rtcp` target drives a `VideoPlayout` with arbitrary steps, flags and
  sizes, checking order, bounds and never playing before completion or past the bound. It also
  rates with fuzzed classes, room noise, monotic tables and Opus bands.
- **Costs**: see BENCHMARKS, "Video playout buffer (ADR-092, same-run A/B)".
- **Not done**:
  - Giving up a missing video packet at its frame's playout deadline. The assembler still
    gives up by packet count.
  - Frame-size-aware jitter estimation (libwebrtc's Kalman filter): keyframes are covered by
    their measured delay.
  - Choosing Opus's band from SDP (`maxplaybackrate`).
  - A packet reported lost that later arrives and is played.
  - EVS NB / WB values (none published).
  - Time-stretching, which stays the decoder's job.
