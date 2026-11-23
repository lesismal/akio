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
- **Costs** (BENCHMARKS, "Video playout buffer (ADR-092, same-run A/B)", gpu51):
  - Off: no measurable change. Video CPU per frame is 8.94 against 8.92 µs, VP8 `media` 1.000.
  - On: 1.14 µs more CPU per frame (+13 %), mostly the timer wake-up for each frame handed out
    at its playout instant. The buffer alone takes 44 ns per frame. One 30 frames/s stream costs
    about 34 µs of CPU per second.
  - The shared estimator costs the audio buffer 1.5 ns per frame in isolation; end to end
    (`audio-jb`) the ratio is 1.000.
- **Not done**:
  - Giving up a missing video packet at its frame's playout deadline. The assembler still
    gives up by packet count.
  - Frame-size-aware jitter estimation (libwebrtc's Kalman filter): keyframes are covered by
    their measured delay.
  - Choosing Opus's band from SDP (`maxplaybackrate`).
  - A packet reported lost that later arrives and is played.
  - EVS NB / WB values (none published).
  - Time-stretching, which stays the decoder's job.

## Update (2026-11-23): missing packets at the playout deadline, frame sizes, Opus's band from SDP, late packets that play

### Context

Four of the items above were left. EVS NB / WB (no published values) and time-stretching (the
decoder's) stay out.

1. With the playout buffer on, the frame assembler still gave a missing packet up by count
   (`set_reordering_size`, 30 video packets). At three packets a frame that is ten frames: the
   picture stood still for about 330 ms at each loss without repair, and at high bitrates the
   count ran out before a retransmission could come.
2. The target covered keyframes only by the delay measured on the two latest ones of the last
   10 s. A keyframe after a longer gap, or the first one after start, came late and stalled the
   frames behind it.
3. `for_codec_rate("opus", ..)` always rated fullband. The band an Opus stream is coded in
   shows in its SDP, not in the encoding name.
4. A packet reported lost that arrived later and was played stayed counted as lost.

### Decision

#### 1. A missing packet is given up at the deadline of the frame behind it

akio-rtp, additive:

- `FrameAssembler::blocked()`: when `pop` returns `None` because a packet is missing and a
  later frame is buffered behind it, the extended timestamp of the frame that giving the packet
  up would release next. `None` while the head frame is still arriving.
- `FrameAssembler::give_up_hole()`: gives that packet up as the count would (the frame it
  belongs to is dropped, the next is `contiguous = false`).
- `FrameAssembler::accepts(seq)`: whether `push` would buffer a sequence number.
- `VideoPlayout::hole_deadline(ts, now)` and `hole_given_up()`, counted in
  `VideoPlayoutStats::holes_given_up`.

The deadline is the later of:

- **the playout instant of the frame waiting behind the hole** (its timestamp plus the
  offset, not before the previous frame's). The frame with the hole is not the measure: late
  frames are not discarded (above), so it may still be repaired and shown late. Once the next
  frame is due, waiting stalls the picture.
- **the start of the wait plus the longest of: the round trip, the target delay and 10 ms.**
  The round trip (lines with NACK) leaves room for one retransmission. The target delay and the
  10 ms floor keep a packet reordered behind frames that are already late (a delay spike) from
  being given up at once. The wait starts at the first `hole_deadline` call for that frame.

Before the first frame, and after the clock started over, only the second rule applies.

akio-webrtc:

- With `set_video_playout_buffer` on, each received video stream asks after every batch of
  frames. The deadline goes into the peer's timeout; when it comes, the packet is given up and
  the frames behind it go into the buffer flagged repaired.
- The assembler's video count is raised to at least 1024 packets (`VIDEO_HOLE_PACKETS`). It
  only bounds the wait and the memory; the deadline normally comes first.
- A retransmission that comes after the packet was given up is ignored, as with the count.
- A given-up packet does not send a PLI. The frame after it is `contiguous = false`, and the
  application decides (as before for count give-ups).

#### 2. Frame-size-aware delay estimation

The target's percentile part now adds the share of the frame size, from a Kalman filter in the
manner of libwebrtc's jitter estimator (`modules/video_coding/timing/jitter_estimator.cc`):

- State: the delay per byte (the bottleneck's serialisation) and an offset. Each unrepaired
  frame after an unrepaired, contiguous one gives a measurement: its delay variation (completion
  interval minus media interval) against its size change.
- libwebrtc's constants: start at 512 kbit/s, covariance `diag(1e4, 1e2)`, process noise
  `diag(2.5e-10, 1e-10)`, measurement noise `(300 e^(-|Δsize| / max size) + 1) σ`, outliers
  beyond 15 σ (taken anyway when the frame is 3 σ above the average size), size decreases below
  a quarter of the largest left out, the slope at least that of 1 Gbit/s. Average size by 0.97
  per frame, only from frames not 2 σ above it (keyframes do not move it); the largest size
  decays by 0.9999 per frame.
- **Size delay** = slope × (largest recent size − average size), 0 for the first 5 frames.
  The target is `max(percentile + size delay, latest keyframes' delay)`, plus the round trip
  while repairs happen, within the bounds.
- Differences from libwebrtc:
  - The delay sample is not clamped to 3.5 σ. On a steady stream the keyframes' samples are
    the ones that tell the slope, and they lie far above the noise.
  - The noise estimate is used only to weigh samples. The noise part of the target stays the
    95th percentile (libwebrtc's is 2.33 σ − 30 ms).
  - The noise filter is not scaled by the frame rate.
- `VideoPlayoutStats::size_delay` reports it.
- The latest keyframes' measured delay stays: it covers what the slope cannot, such as a
  sender that paces keyframes more slowly.

#### 3. Opus's band from the SDP

- Each media line takes the band of the Opus stream it receives from the remote's
  `sprop-maxcapturerate` (RFC 7587 §6.1, the rate it captures at; 48000 when absent):
  - up to 12000 (narrowband, and mediumband, which the E-model has no scale for) →
    `OpusBand::Narrowband`;
  - up to 24000 (wideband, and super-wideband, rated on the wideband scale since no Opus SWB
    values are used) → `Wideband`;
  - above → `Fullband`.
- The VoIP metrics then rate the received Opus with `EModel::opus(band, measured bitrate)`
  (the highest rate's values when no packet came in the interval). A model the application
  gives (`Peer::set_voip_quality`) still wins.
- **`maxplaybackrate`** is what a receiver asks of the remote's encoder. The remote's concerns
  the stream akio sends, so it does not rate what akio receives. akio declares none of its own
  (the application has no way to set Opus parameters).
- **Answers no longer echo `sprop-maxcapturerate` / `maxplaybackrate`.** akio's answer carried
  the offer's format parameters back. For these two that told the offerer that akio captured,
  or could play, only what the offerer had declared, and it would have made an offerer rate
  akio's audio by its own capture rate. Other parameters are still echoed.

#### 4. A packet reported lost that arrives later and plays

- Each received audio stream remembers the sequence numbers its VoIP metrics reported lost
  (ADR-092, at most 1024). One of them arriving later, behind the highest one, is noted with
  whether it plays:
  - with the jitter buffer, when the buffer takes it (`JitterPush::Buffered`);
  - without it, when the frame assembler still would (`FrameAssembler::accepts`).
- The next report takes each back with `BurstLossModel::on_late_arrival()`. It lowers the loss
  count, so the loss rate and the loss fraction the E-model uses drop. The burst and gap
  densities keep it: the model cannot take a packet back out of the run it was counted in.
- One that does not play becomes a discard (`on_late_discard`, as above). That now includes a
  packet the frame assembler had already moved past (no jitter buffer), which used to stay lost.
- In RTP mode the application plays the packets, so a late one stays lost.

### API

Additive:

- akio-rtp:
  - `FrameAssembler::{blocked, give_up_hole, accepts}`;
  - `VideoPlayout::{hole_deadline, hole_given_up}`;
  - `VideoPlayoutStats::{size_delay, holes_given_up}` (the struct is `#[non_exhaustive]`);
  - `BurstLossModel::on_late_arrival`.
- akio-webrtc: none.

Behaviour changes in akio-webrtc:

- With the video playout buffer, packets are given up at the deadline, and the video
  reordering count is at least 1024.
- Received Opus is rated in its SDP band.
- Answers drop the two Opus band parameters.
- Late reported-lost packets count as played or discarded.

### Consequences

- **Tests, akio-rtp.**
  - `tests_video_holes.rs`:
    - The assembler's `blocked` / `give_up_hole` / `accepts` on a frame with a hole, a whole
      frame lost and a frame still arriving.
    - 1800 frames at 1 % loss without repair, count of 30 against the deadline (count 1000).
      A loss pauses the picture for about 360 ms by count (423 ms at most) and for its frame
      and a little jitter by deadline (103 ms at most, where two frames were lost; under 80 ms
      for one). Late frames go from 459 to 37, and the deadline keeps more frames (1742 against
      1733: by count a second loss before the count ran out cost the frames between).
    - At 1 % loss with 60 ms RTT and NACK: at most 2 packets given up, every other loss
      repaired in time.
    - A packet reordered by 5 ms behind frames 200 ms late is waited for.
    - 40-packet keyframes every 15 s (past the 10 s keyframe memory): the size delay stays
      25..50 ms between keyframes, and each keyframe after the first two pauses the picture by
      at most the jitter.
  - `size.rs`: a 2 Mbit/s channel's slope (4 µs/byte) learnt within 15 % under ±3 ms noise;
    equal frames add nothing.
- **Tests, akio-webrtc `tests_mux.rs`:**
  - Two peers with VP8 at 2 % loss and no NACK (removed from the offer): 40 packets given up at
    the deadline. Longest pause 106 ms and 99th percentile 73 ms, against 422 / 389 ms with
    the old count on the same network.
  - A reported-lost packet arriving 100 ms later, inside a 400 ms buffer: the next report has
    loss 0 and discard 0. At 600 ms it is a discard. Without the buffer it plays 5 packets late
    and is a discard 30 packets late.
  - `sprop-maxcapturerate=16000` in the offer: the answerer rates wideband, the answer does not
    echo it, and the offerer stays fullband. The band mapping at 8000 / 12000 / 16000 / 24000 /
    48000 / junk, and the three bands rate differently.
- **Fuzzing.**
  - `rtp_codec` gives holes up as a deadline would on every other packet (one bit of the
    selector).
  - `rtp_rtcp` asks hole deadlines: stable while a frame waits, at least 10 ms on after a
    give-up.
- **Interop.** The pion suite (`tools/interop/webrtc/run.sh`) passes plain, which covers the
  answer without the echoed Opus parameters. It also passes with `AKIO_INTEROP_PLAYOUT=1`,
  akio's peers receiving through both playout buffers.
- **Costs** (BENCHMARKS, "Video playout buffer, second pass (ADR-092 update, same-run A/B)",
  gpu51): no measurable change end to end, buffers off or on (VP8 `media` 0.999; `video-jb` CPU
  per frame 10.01 against 10.03 µs; `audio-jb` 9.74 against 9.76 µs). The buffer alone takes
  60.3 against 43.9 ns per frame: 16 ns for the Kalman update, half a microsecond a second for
  a 30 frames/s stream.
- **Not done**:
  - EVS NB / WB values (none published).
  - Time-stretching (the decoder's).
  - Opus super-wideband values (rated as wideband).
  - A PLI when a packet is given up (the application sees `contiguous = false`).
