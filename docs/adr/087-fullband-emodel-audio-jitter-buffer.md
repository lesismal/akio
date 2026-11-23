# ADR-087: Fullband and per-bitrate E-model, and an audio jitter buffer in akio-webrtc

English | [简体中文](087-fullband-emodel-audio-jitter-buffer.zh-CN.md)

Status: accepted (2026-11-22)

## Context

ADR-085 rates received audio with the E-model for the RTCP XR VoIP metrics. It left four
things out: G.107.2 (fullband), codec values that follow the bitrate, G.722's `Bpl,wb` with its
appendix concealment, and a jitter buffer in akio-webrtc, which hands audio frames to the
application as they arrive.

Reading the in-force texts again showed that ADR-085's wideband model was not G.107.1 (06/2019,
with Corrigendum 1 of 01/2020):

- Eq. 7-15 is `Ie,eff,WB = Ie,WB + (95 - Ie,WB) Ppl / (Ppl + Bpl)`. ADR-085 used 129 where 95
  stands.
- `Id,WB` has its own talker echo: `Roe = -1.5 (-69 - RLR)` (Corrigendum 1), `Re,WB = 80 + 3
  (TERV,WB - 14)`, and a `K` term in `TERV,WB`. Its `Idd` is G.107's times 1.29. ADR-085 used
  the narrowband `Id` with `Ro` 129.

The numbers come from the ITU-T PDFs: G.107 (06/2015), G.107.1 (06/2019 + Cor. 1), G.107.2
(06/2019 and 03/2023), and G.113 (09/2024, with Erratum 1 of 01/2026).

## Decision

### 1. The E-model (akio-rtp)

- **Wideband, corrected** to G.107.1 with Corrigendum 1: `R = 129 - Id,WB - Ie,eff,WB`, its
  talker echo, `1.29 Idd`, and 95 in Eq. 7-15. G.107.1 has no burst ratio. G.107's
  `Ppl / BurstR` is kept, which is Eq. 7-15 exactly for random loss.
- **Fullband (G.107.2)**: `EModel::fullband(ie_fb, bpl_fb)`, `with_burst_robustness(brf)`,
  `is_fullband`.
  - `R = 148 - 1.48 Idd - Ie,eff,FB`, with `Is,FB = 0`, `A = 0`, and delay class "default".
  - `Ie,eff,FB = Ie,FB + (132 - Ie,FB) (Ppl - (1 - BurstR) / Brf) / (Ppl + Bpl)` (Eq. 7-10 of
    03/2023, the share clamped to 0..=1).
  - `Ro,FB` is the scale's top, 148, as in the 06/2019 edition. The 03/2023 edition derives it
    from noise levels but gives no defaults for the room noise `Ps` / `Pr`. Without room noise
    its formula gives 147.5.
  - The R field and the MOS take `R / 1.48` (Annex A), as wideband takes `R / 1.29`.
  - `EModel::scaled_delay_impairment(d)` gives the delay impairment on the model's own scale.
- **Codec values by bitrate**: `EModel::for_codec_rate(name, plc, bitrate)`.
  `for_codec(name, plc)` is the same without a rate. Between two tabled rates, the lower one's
  values apply, and below the lowest, the lowest's.

  | encoding | scale | Ie | Bpl | source |
  |---|---|---|---|---|
  | PCMU, PCMA | narrow | 0 | 25.1 (4.3 without PLC) | G.113 Table I.4 |
  | G729 | narrow | 11 | 19 | Table I.4 (G.729A + VAD) |
  | G723 | narrow | 15 (19 below 5.8 kbit/s) | 16.1 | Tables I.1, I.4 |
  | G722 64 kbit/s | wide | 5 | 7.1 App. III PLC (`Enhanced`), 5.1 App. IV (`Standard`), else 4.3 | Tables IV.3, IV.4 |
  | G722 56 / 48 kbit/s | wide | 10 / 41 | 4.3 | Table IV.3 |
  | AMR-WB | wide | 56 (6.6) .. 8 (23.05), 10 (23.85); 12.65 without a rate | 4.3 / 4.6 / 4.9 at 12.65 / 23.05 / 23.85, else 4.3 | Tables IV.3, IV.4 |
  | EVS | full | 22.7 (9.6) .. 7.2 (24.4) .. 10.2 (48); 13.2 without a rate | 13 .. 9.3; `Brf` 3.28 at 13.2 | Table V.3 (SWB mode) |
  | opus, with a rate | full | 37.85 (13 kbit/s) .. 0 (48), interpolated | EVS's at that rate | P.863-derived, DAGA 2021 (not ITU-T) |
  | opus, without | wide | 0 | 25.1 | assumed (ADR-085) |

  - The wideband values are G.113's diotic ones (headset or loudspeaker). Those tables come
    with `Bpl,wb`, and loss is what the metrics are about. The monotic (handset) Table IV.1 rates
    G.722 at 13 / 20 / 31; it can be given with `EModel::wideband`. This changes G.722's
    `Ie,wb` from ADR-085's 13 to 5.
  - G.729 without VAD is `EModel::codec(10.0, 19.0)`: Table I.1's `Ie`, with the only `Bpl`
    published, the one for G.729A + VAD.
  - ITU-T has published no planning values for Opus. With a bitrate, Opus takes the `Ie,FB` that
    Michael, Mittag and Möller derived for Opus 1.3 from P.863 (DAGA 2021, Table 2). Its `Bpl,fb`
    is assumed equal to EVS's at the same rate, since no Opus `Bpl` is published.
  - `Plc::of_codec` adds EVS (`Enhanced`) and AMR / AMR-WB (`Standard`).
- **The akio-webrtc bitrate**: payload bits per packet over the packet length. The length is the
  jitter buffer's measured frame length, else 20 ms. Packets of 2 bytes or less (Opus DTX) are
  left out. The count covers each report interval, so Opus is rated fullband at its real rate.

### 2. The jitter buffer (akio-rtp)

`JitterBuffer<T>` is sans-IO and holds one stream of single-packet frames. Frames go in with
`push(ext_seq, ts, marker, arrival, data, bytes)`. They come out with `pop(now)` in sequence
order at their playout instants, and `poll_timeout()` says when the next one is due.

- **Playout**: `ts + offset`. The offset is the smallest transit time seen lately plus the
  target delay. The smallest transit is the minimum over two 5 s windows, so drift and route
  changes move it.
- **Target**: the 95th percentile of each packet's delay beyond that minimum, from a 2 ms
  bucket histogram that forgets by 0.997 per packet (about 7 s at 50 packets/s), within
  `PlayoutDelay`'s bounds. It is recomputed every 8 packets, and at once for a packet later
  than it.
  - `PlayoutDelay::adaptive(min, max)` (default 0..500 ms) or `fixed(d)`, at most 2 s.
- **Adapting**:
  - A longer delay applies at once; the application conceals the pause.
  - A shorter one applies at a talkspurt start while nothing is buffered. A talkspurt starts
    at the marker bit, or when the timestamp jumps further than the sequence numbers do (DTX).
  - A stream that never pauses shortens by at most one frame per second. The application
    absorbs that much (time-stretching is the decoder's job, not done here).
- **Losses**: a missing frame is given up when a later frame is due, and that later frame goes
  out with `contiguous = false`.
  - A packet arriving after that is late: discarded.
  - So is one arriving when the buffer is full (more than 1024 slots or 256 KiB): overflow.
    A sequence jump of more than two windows starts the buffer over.
  - A frame that arrives after its own playout instant still plays, at once, if no later frame
    went out yet.
  - Duplicates are dropped, and `skip(seq)` marks a FEC or padding number as no gap.
- **Accounting**: `JitterBufferStats` (received, played, lost, late, overflow, duplicates,
  reordered, delay, target).
  - `drain_discarded()` gives the late and overflow sequence numbers, at most 4096 between
    calls.
  - `xr_config()` gives RFC 3611's view. An adaptive buffer reports rate 1 (a longer delay
    applies at once), the current delay as nominal, and the upper bound as maximum and absolute
    maximum. A fixed buffer reports its delay three times.
  - `frame_duration()` and `drain()` are also provided.
- **Bounds** (docs/rules.md): the slots, at most 1002 histogram buckets, and 4096 discarded
  numbers. Each packet costs O(1), plus a histogram scan up to the percentile every 8 packets.

### 3. akio-webrtc

- `RtcConfig::set_audio_jitter_buffer(Option<PlayoutDelay>)`, off by default.
  - When on, in frame mode, each received audio stream goes through a `JitterBuffer` in place of
    the frame assembler and its reordering wait.
  - Frames still arrive through `on_media_data`, in order, at their playout instants: the
    peer's timer wakes for the next one.
  - `MediaData::playout_time` carries the instant (`None` without the buffer). A frame after a
    gap has `contiguous = false`.
  - RTP mode and video are unchanged.
- **Into the VoIP metrics**:
  - The buffer's discards are the burst model's discarded packets: received, then discarded.
  - Its `xr_config()` fills the jitter buffer fields (RX config adaptive, rate, nominal /
    maximum / abs max).
  - Its nominal delay plus a packet is the end system delay the E-model uses.
  - What the application gives with `set_voip_quality` still wins.
- `Peer::jitter_buffer_stats(mid) -> Vec<(ssrc, JitterBufferStats)>`.

### API

The change is additive.

- akio-rtp:
  - `EModel::{fullband, with_burst_robustness, is_fullband, for_codec_rate, scaled_delay_impairment}`.
  - `JitterBuffer`, `JitterBufferStats`, `JitterFrame`, `JitterPush`, `PlayoutDelay`.
  - `MAX_PLAYOUT_DELAY`, `JITTER_BUFFER_MAX_FRAMES`, `JITTER_BUFFER_MAX_BYTES`.
- akio-webrtc: `RtcConfig::set_audio_jitter_buffer`, `Peer::jitter_buffer_stats`, and
  `MediaData::playout_time` (a new field of a `#[non_exhaustive]` struct).

Some values change without an API change:

- Wideband ratings follow G.107.1. Under loss they are higher than ADR-085's (95 in place of
  129), and with delay the wideband echo terms apply.
- G.722 takes the diotic `Ie,wb` 5. With an application-declared concealment it also takes
  Table IV.4's `Bpl,wb`.
- akio-webrtc measures the Opus bitrate, so Opus rates fullband by it.

## Consequences

- **Tests, akio-rtp `tests_voip.rs`**:
  - G.107.1 defaults: `Idle,WB` 0.1537, R 128.846, MOS 4.4992.
  - G.722 with Appendix III PLC at 2 %: `Ie,eff,WB` 24.78, R 104.07, MOS 4.0491. With
    Appendix IV PLC: 30.35.
  - `Idd,WB` at 200 / 300 ms: 3.9273 / 19.0413.
  - G.107.2: R 148 → 100 / MOS 4.5; R 129 on the FB scale → MOS 4.2634; `Id,FB` at 200 / 300
    ms: 4.5057 / 21.8458.
  - EVS 13.2 at 2 %: `Ie,eff,FB` 33.874, R 114.126, MOS 3.9103. With BurstR 2, `Brf` 3.28:
    36.431. EVS 48 at 1 %: 21.691.
  - The table lookups by rate, and Opus monotone in its bitrate.
  - The published documents have no worked examples beyond the defaults. These values were
    computed from the equations, independently of the code.
- **Tests, akio-rtp `tests_jitter.rs`**, at 20 ms frames:
  - 3000 frames under 0..60 ms uniform jitter with 3 % loss: delay 58 ms, 708 reordered, every
    packet accounted for once.
  - Duplicates and late packets.
  - FEC numbers skipped.
  - A talkspurt after 1.2 s of +600 ms delay restarts at the target (< 15 ms). A stream without
    pauses shrinks by at most one frame at a time (5 to 20 shrinks over 19 s).
  - The bounds: bytes, slots, a jump, the delay bounds, timestamp wrap.
- **Tests, akio-webrtc `tests_mux.rs`** (simulated network):
  - 10..70 ms one way with 3 % loss: 489 frames out in order, all within 5 ms of their playout
    instant; the delay is 60 ms. The sender's metrics carry nominal 60 / abs max 500, RX config
    adaptive, and R 79 for 32 kbit/s Opus.
  - A fixed 0 ms buffer under the same jitter: late frames become the discard rate, not the
    loss rate.
- **Fuzzing**: the `rtp_rtcp` fuzz target rates EVS, AMR-WB and Opus at a fuzzed bitrate.
- **Costs** (BENCHMARKS, "Audio jitter buffer (ADR-087, same-run A/B)", gpu51):
  - Off, the receive path gains a flag check per packet and two counter adds per audio packet.
    No measurable change: VP8 `media` 0.999; Opus `audio` CPU per frame 8.47 against 8.48 µs.
  - On, 1.3 µs more CPU per frame (+16 %), mostly the timer wake-up for each frame handed out
    at its playout instant. The buffer alone takes 47 ns per frame (`jitter-bench`). One Opus
    call (50 frames/s) costs about 65 µs of CPU per second.
- **Not done**:
  - Video: frames still come from the assembler as soon as they are complete, with no playout
    timing.
  - Time-stretching (accelerate / expand) belongs to the decoder.
  - Delay sensitivity classes (G.107 / G.107.2 `sT` / `mT`) are fixed at "default".
  - The 03/2023 `Ro,FB` from room noise, whose `Ps` / `Pr` defaults are missing.
  - ITU-T values for Opus: the published narrowband / wideband Opus values of Al-Ahmadi et al.
    were not used. Also missing: EVS's NB / WB modes (not published), and the monotic wideband
    tables as a choice.
  - The VoIP block's burst and gap durations still assume 20 ms packets.
  - A packet discarded in a later report interval than the one that reported it lost is not
    matched.

## Update (2026-11-23): leftovers closed by ADR-092

[ADR-092](092-video-playout-emodel-classes.md) takes up the "Not done" list above:

- a video playout buffer (`VideoPlayout`, `RtcConfig::set_video_playout_buffer`);
- delay sensitivity classes (`DelaySensitivity`, `RtcConfig::set_voip_delay_sensitivity`);
- the 03/2023 `Ro,FB` from room noise the application gives (`EModel::with_room_noise`);
  without it, 148 stays;
- the monotic tables as a choice (`EModel::for_codec_monotic`);
- the published narrowband / wideband Opus values (`EModel::opus`);
- burst and gap durations from the measured packet length;
- late discards matched across report intervals.

EVS NB / WB modes still have no published values. Time-stretching stays the decoder's job.
