# ADR-085: The codec-side fields of RTCP XR VoIP metrics: G.107 / G.107.1 per codec, the application's values

English | [简体中文](085-rtcp-xr-voip-quality-fields.zh-CN.md)

Status: accepted (2026-11-22)

## Context

ADR-058 sends RTCP XR VoIP metrics (RFC 3611 §4.7) about received audio, and ADR-073 added an
E-model to fill the R factor, MOS-LQ and MOS-CQ. Its "not done" line kept "codec-side VoIP
quality fields", and what was there had three weak points:

- **One codec for all.** Every stream was rated as G.711 with concealment (`Ie = 0`,
  `Bpl = 25.1`), so an Opus call and a G.722 call scored the same as G.711, and the receiver
  configuration byte said nothing about concealment.
- **An approximation of the delay impairment.** Cole and Rosenbluth's fit
  (`Id = 0.024 d + 0.11 (d - 177.3) H`) matches G.107's default curve to about 300 ms and
  drifts beyond it (34.1 against 31.1 at 400 ms, 47.5 against 38.6 at 500 ms).
- **No way in for the application.** only-webrtc hands audio to the application undecoded: it
  has no jitter buffer and never sees samples, so the signal and noise levels, the residual
  echo return loss, the jitter buffer fields and the end system delay can only come from the
  application, and there was no API to give them.

## Decision

### 1. The E-model (only-rtp)

- `EModel` computes G.107 §7 with every parameter the receiver cannot measure at its Table 3
  default: `No`, `Ro` (94.77) and `Is = Iolr + Ist + Iq` (1.41) from their formulas, and the
  full delay impairment `Id = Idte + Idle + Idd` with `Ta = T`, `Tr = 2T` (talker echo with
  TELR 65 dB, listener echo with WEPL 110 dB, absolute delay above `mT` = 100 ms). Unimpaired,
  R = 93.21. `EModel::delay_impairment` keeps its signature and now gives this `Id`.
- **Wideband codecs** follow G.107.1: `R_wb = 129 - Id - Ie,wb,eff`, 129 in place of 95 in
  `Ie,wb,eff = Ie,wb + (129 - Ie,wb) Ppl / (Ppl / BurstR + Bpl)`, and the rating divided by
  1.29 onto the narrowband scale the VoIP block's R field and the MOS formula use. A clean
  wideband call rates 100 (MOS 4.5); a clean G.711 one 93.2 (MOS 4.41).
  `EModel::wideband(ie_wb, bpl_wb)`, `EModel::is_wideband`.
- **Codec table**: `EModel::for_codec(name, plc)` by SDP encoding name:

  | encoding | scale | Ie | Bpl | source |
  |---|---|---|---|---|
  | PCMU, PCMA | narrow | 0 | 25.1, 4.3 with `Plc::Disabled` | G.113 App. I (G.711 Appendix I PLC) |
  | G729 | narrow | 11 | 19 | G.113 App. I (G.729A + VAD) |
  | G723 | narrow | 15 | 16.1 | G.113 App. I (G.723.1 6.3 kbit/s + VAD) |
  | G722 | wide | 13 | 4.3 | G.113 App. IV `Ie,wb` at 64 kbit/s; G.107.1's default `Bpl` |
  | opus | wide | 0 | 25.1 | no ITU-T value: assumed |

  G.722's concealment is optional (Appendices III and IV), so it gets no robustness credit.
  ITU-T has no planning values for Opus (instrumental derivations exist in the literature, not
  in G.113): it is taken as transparent at the bitrates WebRTC uses, the wideband reference
  `Ie,wb = 0`, with concealment as robust as G.711 Appendix I's. Both are stated in the
  documentation; `EModel::codec` / `EModel::wideband` take measured values.
- `Plc::of_codec(name)`: the concealment a decoder always does: Opus (RFC 6716 §4.4)
  `Enhanced`, G.729 and G.723.1 `Standard`, others `Unspecified`.
- `EModel::estimate_report(&BurstLossModel, &VoipQuality, jitter, packet)`: the estimate from
  the loss so far, its burst ratio (G.107's BurstR from the burst / gap runs), the round trip,
  and the end system delay: the application's if given, else a known jitter buffer's nominal
  delay plus a packet, else twice the interarrival jitter plus a packet.
  `EModelScore::fill` fills only the score fields still `None`.
- `VoipMetrics::quality()`: the inverse of `BurstLossModel::report` for the delay, level,
  score and receiver configuration fields (127, out-of-range scores, zero delays and an
  unknown or reserved jitter buffer kind become `None`), so received blocks read as typed
  values.

### 2. only-webrtc

- Each received audio stream's report uses the received codec's table entry and concealment
  (G.711 with concealment for a codec without one); RX config carries `Plc::of_codec` unless
  the application said otherwise; Gmin stays 16.
- `Peer::set_voip_quality(mid, VoipQuality, Option<EModel>)`: what the application knows of
  the audio it decodes and plays: signal and noise levels (`pcm_level_dbm0`), RERL, the jitter
  buffer (nominal / maximum / absolute maximum, adaptive, rate), the end system delay, its
  concealment, an external segment's R factor, and its own R / MOS which then replace the
  estimate. A given jitter buffer or end system delay also improves the estimate. The model
  replaces the codec table's. Anything left `None` is sent unavailable (127 for levels and
  scores, 0 for delays, unknown for the jitter buffer kind), as before.
- Received VoIP metrics stay a `VoipMetrics` event (now documented with
  `VoipMetrics::quality`); `PeerStats` is unchanged.

### API

Additive. only-rtp: `EModel::{wideband, is_wideband, for_codec, estimate_report}`,
`EModelScore::fill`, `Plc::of_codec`, `VoipMetrics::quality`. only-webrtc:
`Peer::set_voip_quality`. Changed behaviour without a signature change:
`EModel::delay_impairment` and `EModel::score` use G.107's full `Id` and computed `Ro - Is`
(93.21 where the constant 93.2 was), and only-webrtc's reports rate by codec.

## Consequences

- Tests (only-rtp `tests_voip.rs`, `emodel.rs`): G.107's defaults (`No` -61.18, `Ro` 94.77,
  `Is` 1.41, R 93.2, MOS 4.41); the ITU-T SG12 G.107.1 calculator's defaults (R 128.8,
  MOS 4.50); G.109 Table 1's R / MOS pairs; `Id` by hand from §7.4 at 150 ms (3.82) and 300 ms
  (20.69), within a point of Cole and Rosenbluth's fit up to 300 ms, monotone; G.113's
  `Ie,eff` cases (G.729A at 2 % random and bursty loss, G.711 with and without concealment,
  G.722 on the wideband scale); the codec ordering under loss; `estimate_report`'s end system
  delay choices and `fill`; the VoIP block through the wire and back to the same
  `VoipQuality` (fixed and adaptive buffers, reserved kind, out-of-range scores). The
  `rtp_rtcp` fuzz target checks that decoding is stable through another report and that
  every codec's estimate stays in range. only-webrtc (`tests_mux.rs`, simulated network):
  Opus at 10 % loss rates as wideband with enhanced concealment and unavailable levels; the
  application's levels, RERL, external R, concealment and jitter buffer arrive at the sender
  as given, its codec model lowers R against the peer's Opus default, and its own scores
  replace the estimate.
- Costs: one estimate (a few dozen `pow` / `log`) per received audio stream per second when
  VoIP metrics are negotiated; nothing otherwise. No hot path changed, so no A/B was run.
- Not done: G.107.2 fullband for Opus at fullband bitrates; codec values that follow the
  negotiated bitrate (Opus, G.722 at 48 / 56 kbit/s, G.729 without VAD); `Bpl,wb` for G.722
  with its appendix concealment; measuring the jitter buffer inside only-webrtc (it has none).

## Update (2026-11-22): ADR-087

ADR-087 does this ADR's "not done" items: G.107.2 fullband, codec values by bitrate
(`EModel::for_codec_rate`), G.722's `Bpl,wb` with its Appendix III / IV concealment, and a
jitter buffer in only-webrtc (`RtcConfig::set_audio_jitter_buffer`) that feeds the jitter
buffer and discard fields.

It also corrects the wideband model above to G.107.1 (06/2019) with Corrigendum 1:

- `Ie,eff,WB` has 95 where this ADR put 129.
- `Id,WB` has its own talker echo and `1.29 Idd`.

G.722 now takes G.113's diotic `Ie,wb` (5) in place of the monotic 13. The codec table above
is replaced by ADR-087's.
