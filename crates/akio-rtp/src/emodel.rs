//! Call quality estimation with the E-model (ITU-T G.107; wideband codecs with G.107.1,
//! fullband ones with G.107.2): the transmission rating R and the mean opinion scores the VoIP
//! metrics block of RTCP XR carries (RFC 3611 §4.7.5).
//!
//! Every parameter the RTP receiver cannot know (loudness ratings, room noise, sidetone,
//! talker echo) has its G.107 Table 3 default; what it measures goes in: the loss of packets
//! (lost or discarded), how bursty it is, and the mouth-to-ear delay.

use std::time::Duration;

use crate::xr::{BurstLossModel, Plc, VoipQuality};

// G.107 Table 3 defaults.
const SLR: f64 = 8.0;
const RLR: f64 = 2.0;
const STMR: f64 = 15.0;
const LSTR: f64 = 18.0;
const DS: f64 = 3.0;
const TELR: f64 = 65.0;
const WEPL: f64 = 110.0;
const NC: f64 = -70.0;
const NFOR: f64 = -64.0;
const PS: f64 = 35.0;
const PR: f64 = 35.0;
const QDU: f64 = 1.0;
/// G.107.2 (03/2023) Table 2: the circuit noise `Nc` and noise floor `Nfo` of the fullband
/// path (dBm0p).
const NC_FB: f64 = -96.0;
const NFO_FB: f64 = -96.0;

/// The delay sensitivity class of a conversation (ITU-T G.107 (06/2015) §7.4 Table 1;
/// G.107.2 (03/2023) §7.4 Table 1 has the same values): the parameters `sT` and `mT` of the
/// absolute delay impairment
/// `Idd = 25 {(1 + X^(6 sT))^(1/(6 sT)) - 3 (1 + (X/3)^(6 sT))^(1/(6 sT)) + 2}`,
/// `X = log2(Ta / mT)`, 0 up to `mT`.
///
/// Both Recommendations require the default class for carrier-grade and enterprise
/// telephony and whenever the users or the scenario are not known, and ask that any other
/// class be stated with the results. G.107.1 (wideband) has no classes: its `Idd` is the
/// default one, so a wideband model ignores this.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum DelaySensitivity {
    /// `sT` 1, `mT` 100 ms: every kind of telephone conversation.
    #[default]
    Default,
    /// `sT` 0.55, `mT` 120 ms: users known to be little sensitive to delay (G.107: "Low",
    /// non time-sensitive conversation; G.107.2: "Medium", conversations like random number
    /// verification).
    Low,
    /// `sT` 0.4, `mT` 150 ms: users known to be hardly sensitive to delay (G.107: "Very low",
    /// mainly listening, as to a lecture; G.107.2: "Low", short conversation tests).
    VeryLow,
}

impl DelaySensitivity {
    /// `(sT, mT ms)`.
    fn params(self) -> (f64, f64) {
        match self {
            DelaySensitivity::Default => (1.0, 100.0),
            DelaySensitivity::Low => (0.55, 120.0),
            DelaySensitivity::VeryLow => (0.4, 150.0),
        }
    }
}

/// The room noise at the send and receive sides (dB(A)).
#[derive(Debug, Clone, Copy, PartialEq)]
struct Room {
    ps: f64,
    pr: f64,
}

/// G.107 Table 3's room noise.
const ROOM: Room = Room { ps: PS, pr: PR };

/// The highest rating of G.107.1's wideband scale (`Ro,WB`, Eq. 7-2; `Is,WB` is 0).
const RO_WB: f64 = 129.0;
/// G.107.1 Annex A: the wideband rating over this is the narrowband-scale `Rx` of the MOS.
const WB_SCALE: f64 = 1.29;
/// The highest rating of G.107.2's fullband scale (`Ro,FB`; `Is,FB` is 0).
const RO_FB: f64 = 148.0;
/// G.107.2 Annex A: the fullband rating over this is the `Rx` of the MOS.
const FB_SCALE: f64 = 1.48;
/// The top of the loss term of `Ie,eff,FB` (G.107.2 Eq. 7-10).
const FB_LOSS_TOP: f64 = 132.0;
/// The top of the loss term of `Ie,eff` and `Ie,eff,WB` (G.107 Eq. 7-29, G.107.1 Eq. 7-15).
const LOSS_TOP: f64 = 95.0;

/// The circuit noise `No` (dBm0p) of the default parameters and room noise `room` (-61.18
/// with G.107's 35 dB(A)).
fn noise_no(room: Room) -> f64 {
    let olr = SLR + RLR;
    let nfo = NFOR + RLR;
    let pre = room.pr + 10.0 * (1.0 + 10f64.powf((10.0 - LSTR) / 10.0)).log10();
    let nor = RLR - 121.0 + pre + 0.008 * (pre - 35.0).powi(2);
    let nos = room.ps - SLR - DS - 100.0 + 0.004 * (room.ps - olr - DS - 14.0).powi(2);
    10.0 * [NC, nos, nor, nfo]
        .iter()
        .map(|n| 10f64.powf(n / 10.0))
        .sum::<f64>()
        .log10()
}

/// The basic signal-to-noise ratio `Ro` (94.77 with G.107's room noise).
fn ro(room: Room) -> f64 {
    15.0 - 1.5 * (SLR + noise_no(room))
}

/// G.107.2 (03/2023) Eqs. 7-2 to 7-6: the fullband `Ro,FB` from the room noise `room`, with
/// Table 2's defaults (`Nc` = `Nfo` = -96 dBm0p).
fn ro_fb(room: Room) -> f64 {
    let olr = SLR + RLR;
    let pre = room.pr + 10.0 * (1.0 + 10f64.powf((10.0 - LSTR) / 10.0)).log10();
    let nor = RLR - 147.0 + 1.12 * pre + 0.009 * (pre - 25.0).powi(2);
    let nos = room.ps - SLR - DS - 100.0 + 0.004 * (room.ps - olr - DS - 14.0).powi(2);
    let no = 10.0
        * [NC_FB, nos, nor, NFO_FB]
            .iter()
            .map(|n| 10f64.powf(n / 10.0))
            .sum::<f64>()
            .log10();
    20.0 - 1.5 * (SLR + no)
}

/// The simultaneous impairment `Is = Iolr + Ist + Iq` with one-way delay `t` ms (1.41).
fn is(t: f64, room: Room) -> f64 {
    let no = noise_no(room);
    let xolr = SLR + RLR + 0.2 * (64.0 + no - RLR);
    let iolr = 20.0 * ((1.0 + (xolr / 8.0).powi(8)).powf(1.0 / 8.0) - xolr / 8.0);
    let stmro =
        -10.0 * (10f64.powf(-STMR / 10.0) + (-t / 4.0).exp() * 10f64.powf(-TELR / 10.0)).log10();
    let ist = 12.0 * (1.0 + ((stmro - 13.0) / 6.0).powi(8)).powf(1.0 / 8.0)
        - 28.0 * (1.0 + ((stmro + 1.0) / 19.4).powi(35)).powf(1.0 / 35.0)
        - 13.0 * (1.0 + ((stmro - 3.0) / 33.0).powi(13)).powf(1.0 / 13.0)
        + 29.0;
    let q = 37.0 - 15.0 * QDU.log10();
    let g = 1.07 + 0.258 * q + 0.0602 * q * q;
    let z = 46.0 / 30.0 - g / 40.0;
    let y = (ro(room) - 100.0) / 15.0 + 46.0 / 8.4 - g / 9.0;
    let iq = 15.0 * (1.0 + 10f64.powf(y) + 10f64.powf(z)).log10();
    iolr + ist + iq
}

/// G.107's absolute-delay impairment `Idd` (Eqs. 7-27, 7-28) of absolute delay `t` ms in
/// delay sensitivity class `class`; G.107.1 (Eq. 7-13, default class only) and G.107.2
/// (03/2023 Eq. 7-8b) scale it by 1.29 and 1.48.
fn idd(t: f64, class: DelaySensitivity) -> f64 {
    let (st, mt) = class.params();
    if t <= mt {
        return 0.0;
    }
    let x = (t / mt).log2();
    let e = 6.0 * st;
    25.0 * ((1.0 + x.powf(e)).powf(1.0 / e) - 3.0 * (1.0 + (x / 3.0).powf(e)).powf(1.0 / e) + 2.0)
}

/// The listener echo impairment `Idle` (G.107 Eq. 7-23, G.107.1 Eq. 7-11) with round trip
/// `Tr = 2T`, on a scale of highest rating `ro`.
fn idle(t: f64, ro: f64) -> f64 {
    let rle = 10.5 * (WEPL + 7.0) * (2.0 * t + 1.0).powf(-0.25);
    (ro - rle) / 2.0 + ((ro - rle).powi(2) / 4.0 + 169.0).sqrt()
}

/// The talker echo impairment `Idte` from `Roe` and `Re`.
fn idte(t: f64, roe: f64, re: f64) -> f64 {
    ((roe - re) / 2.0 + ((roe - re).powi(2) / 4.0 + 100.0).sqrt() - 1.0) * (1.0 - (-t).exp())
}

/// The delay impairment `Id = Idte + Idle + Idd` of G.107 §7.4 for mean one-way delay `t`
/// ms, absolute delay `Ta = T` and round trip `Tr = 2T`.
fn id(t: f64, room: Room, class: DelaySensitivity) -> f64 {
    let ro = ro(room);
    let t = t.max(0.0);
    let terv =
        TELR - 40.0 * ((1.0 + t / 10.0) / (1.0 + t / 150.0)).log10() + 6.0 * (-0.3 * t * t).exp();
    let re = 80.0 + 2.5 * (terv - 14.0);
    let roe = -1.5 * (noise_no(room) - RLR);
    idte(t, roe, re) + idle(t, ro) + idd(t, class)
}

/// The wideband delay impairment `Id,WB = Idte,WB + Idle,WB + Idd` of G.107.1 §7.4 (with its
/// Corrigendum 1: `Roe = -1.5 (-69 - RLR)`), `Ta = T`, `Tr = 2T`.
fn id_wb(t: f64) -> f64 {
    let t = t.max(0.0);
    let k = if t < 100.0 { 0.08 * t + 10.0 } else { 18.0 };
    let terv = TELR + k - 40.0 * ((1.0 + t / 10.0) / (1.0 + t / 150.0)).log10()
        + 6.0 * (-0.3 * t * t).exp();
    let re = 80.0 + 3.0 * (terv - 14.0);
    let roe = -1.5 * (-69.0 - RLR);
    idte(t, roe, re) + idle(t, RO_WB) + WB_SCALE * idd(t, DelaySensitivity::Default)
}

/// The fullband delay impairment `Id,FB = Idd` of G.107.2 §7.4 (absolute delay only).
fn id_fb(t: f64, class: DelaySensitivity) -> f64 {
    FB_SCALE * idd(t.max(0.0), class)
}

fn millis(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// The rating scale of a codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scale {
    /// G.107: 300-3400 Hz, R up to 93.2 with the defaults.
    Narrow,
    /// G.107.1: 50-7000 Hz, up to 129.
    Wide,
    /// G.107.2: 20-20000 Hz, up to 148.
    Full,
}

/// The E-model of a speech path (ITU-T G.107 §7) with every parameter the receiver cannot
/// measure at its Table 3 default (no echo beyond TELR 65 dB / WEPL 110 dB, default noise and
/// loudness: R = 93.2 unimpaired), the full delay impairment (`Id = Idte + Idle + Idd` with
/// `Ta = T`, `Tr = 2T`), and the effective equipment impairment of §7.5 from the codec's `Ie`
/// / `Bpl`, the packet loss and the burst ratio:
///
/// `R = Ro - Is - Id - Ie,eff`, `Ie,eff = Ie + (95 - Ie) Ppl / (Ppl / BurstR + Bpl)`.
///
/// A wideband codec ([`EModel::wideband`]) is rated with G.107.1 (2019, Corrigendum 1):
/// `R = 129 - Id,WB - Ie,eff,WB` with its own talker echo and `Idd` scaled by 1.29, and
/// `Ie,eff,WB = Ie,WB + (95 - Ie,WB) Ppl / (Ppl / BurstR + Bpl)` (Eq. 7-15 for random loss;
/// G.107.1 has no burst ratio, G.107's is kept). A fullband codec ([`EModel::fullband`]) is
/// rated with G.107.2: `R = 148 - 1.48 Idd - Ie,eff,FB`,
/// `Ie,eff,FB = Ie,FB + (132 - Ie,FB) (Ppl - (1 - BurstR) / Brf) / (Ppl + Bpl)` (Eq. 7-10,
/// `Brf` the codec's burstiness robustness, 1 when unknown). `Ro,FB` is the scale's top, 148
/// (G.107.2 06/2019): the 03/2023 edition derives it from noise levels but gives no defaults
/// for the room noise, which [`with_room_noise`](Self::with_room_noise) supplies. The delay
/// sensitivity class is the default one unless
/// [`with_delay_sensitivity`](Self::with_delay_sensitivity) says otherwise. The VoIP metrics block and the MOS
/// take the rating divided by 1.29 or 1.48 (G.107.1 / G.107.2 Annex A), so a clean wideband
/// or fullband call rates 100 and a clean G.711 one 93.2.
///
/// The default codec is G.711 with packet loss concealment (G.113 Appendix I: `Ie = 0`,
/// `Bpl = 25.1`); [`EModel::for_codec_rate`] has the planning values of the usual RTP codecs
/// by bitrate and [`EModel::codec`] / [`EModel::wideband`] / [`EModel::fullband`] take any
/// others.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EModel {
    ie: f64,
    bpl: f64,
    brf: f64,
    scale: Scale,
    class: DelaySensitivity,
    /// The room noise given ([`EModel::with_room_noise`]).
    room: Option<Room>,
}

impl Default for EModel {
    fn default() -> EModel {
        EModel::codec(0.0, 25.1)
    }
}

/// What [`EModel::estimate`] gives.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EModelScore {
    /// The conversational rating R (0..=100), delay included.
    pub r_factor: f64,
    /// The listening-quality rating (delay left out).
    pub r_lq: f64,
    /// MOS-CQ (conversational quality, 1..=4.5), from [`r_factor`](Self::r_factor).
    pub mos_cq: f64,
    /// MOS-LQ (listening quality, 1..=4.5), from [`r_lq`](Self::r_lq).
    pub mos_lq: f64,
}

impl EModelScore {
    /// Fills the R factor and the MOS fields of `q` (MOS × 10, rounded).
    pub fn apply(&self, q: &mut VoipQuality) {
        q.r_factor = Some(self.r_factor.round().clamp(0.0, 100.0) as u8);
        q.mos_lq = Some((self.mos_lq * 10.0).round().clamp(10.0, 50.0) as u8);
        q.mos_cq = Some((self.mos_cq * 10.0).round().clamp(10.0, 50.0) as u8);
    }

    /// [`apply`](Self::apply) to the fields of `q` that are still `None`: values the
    /// application measured itself win.
    pub fn fill(&self, q: &mut VoipQuality) {
        let mut s = VoipQuality::default();
        self.apply(&mut s);
        q.r_factor = q.r_factor.or(s.r_factor);
        q.mos_lq = q.mos_lq.or(s.mos_lq);
        q.mos_cq = q.mos_cq.or(s.mos_cq);
    }
}

/// The MOS of a rating `r` (G.107 Annex B): 1 below 0, 4.5 above 100, else
/// `1 + 0.035 R + R (R - 60) (100 - R) 7e-6`.
#[must_use]
pub fn mos_from_r(r: f64) -> f64 {
    if r <= 0.0 {
        1.0
    } else if r >= 100.0 {
        4.5
    } else {
        (1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7e-6).max(1.0)
    }
}

/// G.711 Appendix I concealment's packet-loss robustness (G.113 Appendix I).
const BPL_G711_PLC: f64 = 25.1;
/// G.107's default packet-loss robustness: no concealment credit.
const BPL_NONE: f64 = 4.3;

/// G.113 Table IV.3 (diotic `Ie,wb`) and Table IV.4 (`Bpl,wb`, diotic, uniform loss) for
/// AMR-WB (G.722.2) by mode (bit/s): `(rate, Ie,wb, Bpl,wb)`; 4.3 (G.107.1's default) where
/// Table IV.4 has none.
const AMR_WB: [(u32, f64, f64); 6] = [
    (6_600, 56.0, BPL_NONE),
    (8_850, 41.0, BPL_NONE),
    (12_650, 20.0, 4.3),
    (15_850, 17.0, BPL_NONE),
    (23_050, 8.0, 4.6),
    (23_850, 10.0, 4.9),
];

/// G.113 Table IV.1 (monotic, handset listening: provisional `Ie,wb`) for AMR-WB (G.722.2)
/// by mode (bit/s).
const AMR_WB_MONOTIC: [(u32, f64); 9] = [
    (6_600, 41.0),
    (8_850, 26.0),
    (12_650, 13.0),
    (14_250, 10.0),
    (15_850, 7.0),
    (18_250, 5.0),
    (19_850, 3.0),
    (23_050, 1.0),
    (23_850, 8.0),
];

/// G.113 Table IV.1 (monotic) for G.722 at 64, 56, 48 kbit/s.
const G722_MONOTIC: [(u32, f64); 3] = [(48_000, 31.0), (56_000, 20.0), (64_000, 13.0)];

/// Narrowband Opus 1.2.1 in VBR mode, from POLQA (ITU-T P.834 method): `(rate, Ie, Bpl)`,
/// `Bpl` under random loss. M. Alahmadi, P. Pocta, H. Melvin, "Derivation of E-model
/// Equipment Impairment Factors for Narrowband and Wideband Opus Codec Using the
/// Instrumental Method", ISSC 2020 (doi:10.1109/ISSC49989.2020.9180160), as printed in
/// M. Alahmadi's thesis (NUI Galway, 2020), Tables 5.13 and 5.14. Not ITU-T values.
const OPUS_NB: [(u32, f64, f64); 4] = [
    (6_000, 23.0, 24.6),
    (7_000, 21.3, 22.5),
    (8_000, 16.0, 20.2),
    (9_000, 11.7, 18.9),
];

/// Wideband Opus 1.2.1 in VBR mode, the same source (thesis Tables 5.8 and 5.9):
/// `(rate, Ie,wb, Bpl,wb)`.
const OPUS_WB: [(u32, f64, f64); 3] = [
    (11_000, 28.4, 23.9),
    (12_000, 23.3, 22.2),
    (13_000, 20.0, 19.5),
];

/// The audio bandwidth an Opus stream is coded in (its decoder's output: SDP
/// `maxplaybackrate` 8000 is narrowband, 16000 wideband), for [`EModel::opus`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum OpusBand {
    /// 4 kHz audio (G.107 scale).
    Narrowband,
    /// 8 kHz audio (G.107.1 scale).
    Wideband,
    /// 20 kHz audio (G.107.2 scale): what WebRTC sends unless told otherwise.
    #[default]
    Fullband,
}

/// G.113 Table V.3 (EVS in SWB mode, diotic): `(rate, Ie,fb, Bpl,fb, Brf)`, `Brf` 1 where
/// it is for further study.
const EVS: [(u32, f64, f64, f64); 6] = [
    (9_600, 22.7, 13.0, 1.0),
    (13_200, 17.1, 11.7, 3.28),
    (16_400, 10.8, 10.3, 1.0),
    (24_400, 7.2, 11.4, 1.0),
    (32_000, 8.7, 9.3, 1.0),
    (48_000, 10.2, 9.6, 1.0),
];

/// `Ie,FB` of Opus 1.3 derived from ITU-T P.863 (Michael, Mittag, Möller, DAGA 2021,
/// Table 2): `(rate, Ie,FB)`; not ITU-T planning values.
const OPUS_FB: [(u32, f64); 5] = [
    (13_000, 37.85),
    (16_000, 21.96),
    (24_000, 9.82),
    (32_000, 2.58),
    (48_000, 0.0),
];

/// The row of `table` for `rate`: the highest rate not above it, else the lowest.
fn step<T: Copy>(table: &[T], rate: u32, key: impl Fn(&T) -> u32) -> T {
    table
        .iter()
        .rev()
        .find(|r| key(r) <= rate)
        .copied()
        .unwrap_or(table[0])
}

/// Opus's `Ie,FB` at `rate`: linear between [`OPUS_FB`]'s rates, held beyond them.
fn opus_ie_fb(rate: u32) -> f64 {
    let (lo, hi) = (OPUS_FB[0], OPUS_FB[OPUS_FB.len() - 1]);
    if rate <= lo.0 {
        return lo.1;
    }
    if rate >= hi.0 {
        return hi.1;
    }
    let i = OPUS_FB.iter().position(|r| r.0 > rate).unwrap_or(1);
    let ((r0, v0), (r1, v1)) = (OPUS_FB[i - 1], OPUS_FB[i]);
    v0 + (v1 - v0) * f64::from(rate - r0) / f64::from(r1 - r0)
}

impl EModel {
    /// The narrowband model for a codec of equipment impairment `ie` and packet-loss
    /// robustness `bpl`.
    #[must_use]
    pub fn codec(ie: f64, bpl: f64) -> EModel {
        EModel {
            ie: ie.clamp(0.0, 95.0),
            bpl: bpl.max(1.0),
            brf: 1.0,
            scale: Scale::Narrow,
            class: DelaySensitivity::Default,
            room: None,
        }
    }

    /// The wideband model (G.107.1) for a codec of wideband equipment impairment `ie_wb`
    /// (0..=129) and packet-loss robustness `bpl_wb`.
    #[must_use]
    pub fn wideband(ie_wb: f64, bpl_wb: f64) -> EModel {
        EModel {
            ie: ie_wb.clamp(0.0, RO_WB),
            bpl: bpl_wb.max(1.0),
            brf: 1.0,
            scale: Scale::Wide,
            class: DelaySensitivity::Default,
            room: None,
        }
    }

    /// The fullband model (G.107.2) for a codec of fullband equipment impairment `ie_fb`
    /// (0..=148) and packet-loss robustness `bpl_fb`; burstiness robustness 1 (see
    /// [`with_burst_robustness`](Self::with_burst_robustness)).
    #[must_use]
    pub fn fullband(ie_fb: f64, bpl_fb: f64) -> EModel {
        EModel {
            ie: ie_fb.clamp(0.0, RO_FB),
            bpl: bpl_fb.max(1.0),
            brf: 1.0,
            scale: Scale::Full,
            class: DelaySensitivity::Default,
            room: None,
        }
    }

    /// The codec's burstiness robustness factor `Brf` (G.107.2 Eq. 7-10, at least 1; only
    /// the fullband model uses it).
    #[must_use]
    pub fn with_burst_robustness(mut self, brf: f64) -> EModel {
        self.brf = if brf.is_finite() { brf.max(1.0) } else { 1.0 };
        self
    }

    /// The model in delay sensitivity class `class` (narrowband and fullband models;
    /// G.107.1 has no classes, so a wideband model keeps the default one).
    #[must_use]
    pub fn with_delay_sensitivity(mut self, class: DelaySensitivity) -> EModel {
        self.class = class;
        self
    }

    /// The delay sensitivity class the model rates with.
    #[must_use]
    pub fn delay_sensitivity(&self) -> DelaySensitivity {
        if self.scale == Scale::Wide {
            DelaySensitivity::Default
        } else {
            self.class
        }
    }

    /// The model with the room noise at the send side `send` and the receive side `receive`
    /// (dB(A), each clamped to 0..=85), which the receiver cannot measure.
    ///
    /// - Narrowband: G.107's `Ps` / `Pr` (Table 3: default 35, range 35..=85), which move the
    ///   noise `No`, so `Ro`, `Is` and the talker echo.
    /// - Fullband: G.107.2 (03/2023) Eqs. 7-2 to 7-6 then give `Ro,FB` in place of 148,
    ///   with Table 2's other defaults. That edition gives no default room noise: 35 dB(A)
    ///   at both ends (G.107's) gives `Ro,FB` 121.5, 0 dB(A) 147.3.
    /// - Wideband: G.107.1 lists `Ps` / `Pr` as under study and does not use them; ignored.
    #[must_use]
    pub fn with_room_noise(mut self, send: f64, receive: f64) -> EModel {
        let level = |v: f64| {
            if v.is_finite() {
                v.clamp(0.0, 85.0)
            } else {
                PS
            }
        };
        self.room = Some(Room {
            ps: level(send),
            pr: level(receive),
        });
        self
    }

    /// The highest rating on the model's own scale: `Ro - Is` (93.2 with the defaults)
    /// narrowband, 129 wideband, `Ro,FB` (148 unless the room noise is given) fullband.
    #[must_use]
    pub fn max_rating(&self) -> f64 {
        match self.scale {
            Scale::Narrow => {
                let room = self.room.unwrap_or(ROOM);
                ro(room) - is(0.0, room)
            }
            Scale::Wide => RO_WB,
            Scale::Full => self.ro_fb(),
        }
    }

    fn ro_fb(&self) -> f64 {
        self.room.map_or(RO_FB, ro_fb)
    }

    /// Whether the codec is rated on the wideband scale (G.107.1).
    #[must_use]
    pub fn is_wideband(&self) -> bool {
        self.scale == Scale::Wide
    }

    /// Whether the codec is rated on the fullband scale (G.107.2).
    #[must_use]
    pub fn is_fullband(&self) -> bool {
        self.scale == Scale::Full
    }

    /// The model for the RTP encoding `name` (SDP `a=rtpmap` name, any case) whose receiver
    /// conceals losses as `plc` says; `None` for a codec without planning values here. The
    /// same as [`for_codec_rate`](Self::for_codec_rate) without a bitrate.
    #[must_use]
    pub fn for_codec(name: &str, plc: Plc) -> Option<EModel> {
        EModel::for_codec_rate(name, plc, None)
    }

    /// The model for the RTP encoding `name` (SDP `a=rtpmap` name, any case) at `bitrate`
    /// (the codec's bits per second, if known) whose receiver conceals losses as `plc` says;
    /// `None` for a codec without planning values here. A rate between two of a table's
    /// takes the lower one's values (Opus: interpolated), one below its lowest the lowest's.
    ///
    /// | encoding | scale | Ie | Bpl | source |
    /// |---|---|---|---|---|
    /// | PCMU, PCMA | narrow | 0 | 25.1 (4.3 with [`Plc::Disabled`]) | G.113 Table I.4 |
    /// | G729 | narrow | 11 | 19 | G.113 Table I.4 (G.729A + VAD) |
    /// | G723 | narrow | 15 (19 below 5.8 kbit/s) | 16.1 | G.113 Tables I.1, I.4 (6.3 kbit/s + VAD) |
    /// | G722 64 kbit/s | wide | 5 | 7.1 [`Plc::Enhanced`], 5.1 [`Plc::Standard`], else 4.3 | G.113 Tables IV.3, IV.4 (G.722 App. III / IV PLC) |
    /// | G722 56 / 48 kbit/s | wide | 10 / 41 | 4.3 | G.113 Table IV.3 |
    /// | AMR-WB | wide | 56 .. 8 by mode (12.65 kbit/s without a rate) | 4.3, 4.6, 4.9 at 12.65, 23.05, 23.85 | G.113 Tables IV.3, IV.4 |
    /// | EVS | full | 22.7 .. 7.2 by rate (13.2 kbit/s without one) | 13 .. 9.3, `Brf` 3.28 at 13.2 | G.113 Table V.3 (SWB mode) |
    /// | opus, with a rate | full | 37.85 at 13 kbit/s .. 0 at 48 | EVS's at that rate | not ITU-T: P.863-derived (DAGA 2021) |
    /// | opus, without | wide | 0 | 25.1 | none: assumed |
    ///
    /// The wideband values are G.113's diotic ones (headset or loudspeaker listening, the
    /// tables that come with `Bpl,wb`); its monotic (handset) Table IV.1 is
    /// [`for_codec_monotic`](Self::for_codec_monotic). G.722 rated with concealment takes
    /// Appendix III's (high quality) for [`Plc::Enhanced`] and Appendix IV's (low complexity)
    /// for [`Plc::Standard`]; on RTP G.722 runs at 64 kbit/s (RFC 3551), so the 48 and 56
    /// kbit/s rows only apply when the application knows its mode. G.729 without VAD is
    /// `EModel::codec(10.0, 19.0)` (Table I.1's `Ie`; no `Bpl` is published). ITU-T has no
    /// planning values for Opus: with its bitrate it is rated fullband with the `Ie,FB` that
    /// Michael, Mittag and Möller derived for Opus 1.3 from P.863 (interpolated, 0 at
    /// 48 kbit/s and above, 37.85 at 13 kbit/s and below) and EVS's `Bpl,fb` at the same
    /// rate (an assumption: no `Bpl` is published); without, it is taken as transparent on
    /// the wideband scale with concealment as robust as G.711 Appendix I's (ADR-085).
    /// Narrowband and wideband Opus, which the RTP encoding name does not tell, are
    /// [`EModel::opus`]. EVS is rated in its SWB mode only: G.113 publishes no values for
    /// its narrowband and wideband modes.
    #[must_use]
    pub fn for_codec_rate(name: &str, plc: Plc, bitrate: Option<u32>) -> Option<EModel> {
        let n = name.to_ascii_lowercase();
        Some(match n.as_str() {
            "pcmu" | "pcma" => EModel::codec(
                0.0,
                if plc == Plc::Disabled {
                    BPL_NONE
                } else {
                    BPL_G711_PLC
                },
            ),
            "g729" => EModel::codec(11.0, 19.0),
            "g723" => EModel::codec(
                if bitrate.is_some_and(|r| r < 5_800) {
                    19.0
                } else {
                    15.0
                },
                16.1,
            ),
            "g722" => match bitrate.unwrap_or(64_000) {
                r if r >= 60_000 => EModel::wideband(
                    5.0,
                    match plc {
                        Plc::Enhanced => 7.1,
                        Plc::Standard => 5.1,
                        _ => BPL_NONE,
                    },
                ),
                r if r >= 52_000 => EModel::wideband(10.0, BPL_NONE),
                _ => EModel::wideband(41.0, BPL_NONE),
            },
            "amr-wb" => {
                let (_, ie, bpl) = step(&AMR_WB, bitrate.unwrap_or(12_650), |r| r.0);
                EModel::wideband(ie, bpl)
            }
            "evs" => {
                let (_, ie, bpl, brf) = step(&EVS, bitrate.unwrap_or(13_200), |r| r.0);
                EModel::fullband(ie, bpl).with_burst_robustness(brf)
            }
            "opus" => match bitrate {
                Some(r) => EModel::opus(OpusBand::Fullband, r),
                None => EModel::wideband(0.0, BPL_G711_PLC),
            },
            _ => return None,
        })
    }

    /// The model of an Opus stream coded in `band` at `bitrate` (bit/s). ITU-T has published
    /// no Opus planning values; these are instrumental (POLQA / P.863) estimates for VBR
    /// Opus, not ITU-T values. A rate between two tabled ones takes the lower one's values
    /// (fullband: interpolated), one below the lowest the lowest's, one above the highest
    /// the highest's.
    ///
    /// | band | Ie | Bpl | rates | source |
    /// |---|---|---|---|---|
    /// | narrow | 23 .. 11.7 | 24.6 .. 18.9 | 6..=9 kbit/s | Alahmadi, Pocta, Melvin, ISSC 2020 (thesis Tables 5.13, 5.14) |
    /// | wide | 28.4 .. 20 | 23.9 .. 19.5 | 11..=13 kbit/s | the same (Tables 5.8, 5.9) |
    /// | full | 37.85 .. 0 | EVS's at that rate (assumed) | 13..=48 kbit/s | Michael, Mittag, Möller, DAGA 2021, Table 2 |
    ///
    /// The narrowband and wideband values were measured for those low rates only: Opus above
    /// them in those bands is rated at the highest tabled rate's values, which understates
    /// it. Their `Bpl` is the random-loss one (the burst ratio covers burstiness), as G.113's.
    #[must_use]
    pub fn opus(band: OpusBand, bitrate: u32) -> EModel {
        match band {
            OpusBand::Narrowband => {
                let (_, ie, bpl) = step(&OPUS_NB, bitrate, |r| r.0);
                EModel::codec(ie, bpl)
            }
            OpusBand::Wideband => {
                let (_, ie, bpl) = step(&OPUS_WB, bitrate, |r| r.0);
                EModel::wideband(ie, bpl)
            }
            OpusBand::Fullband => {
                let (_, _, bpl, _) = step(&EVS, bitrate, |r| r.0);
                EModel::fullband(opus_ie_fb(bitrate), bpl)
            }
        }
    }

    /// [`for_codec_rate`](Self::for_codec_rate) for monotic (handset) listening: G.722 and
    /// AMR-WB take G.113 Table IV.1's provisional `Ie,wb` (G.722 13 / 20 / 31 at 64 / 56 /
    /// 48 kbit/s; AMR-WB 41 at 6.6 .. 1 at 23.05, 8 at 23.85 kbit/s) with the same `Bpl,wb`
    /// as diotic listening (G.113 publishes `Bpl,wb` only with the diotic tables). Other
    /// codecs have no monotic values and are rated as by `for_codec_rate`.
    #[must_use]
    pub fn for_codec_monotic(name: &str, plc: Plc, bitrate: Option<u32>) -> Option<EModel> {
        let mut m = EModel::for_codec_rate(name, plc, bitrate)?;
        match name.to_ascii_lowercase().as_str() {
            "g722" => m.ie = step(&G722_MONOTIC, bitrate.unwrap_or(64_000), |r| r.0).1,
            "amr-wb" => m.ie = step(&AMR_WB_MONOTIC, bitrate.unwrap_or(12_650), |r| r.0).1,
            _ => {}
        }
        Some(m)
    }

    /// The narrowband delay impairment `Id` (G.107 §7.4) of one-way mouth-to-ear delay `d`,
    /// with the default echo parameters, `Ta = d` and `Tr = 2d`: talker echo, listener echo
    /// and absolute delay (0.15 at 0 ms, about 3.8 at 150 ms, 20.7 at 300 ms).
    #[must_use]
    pub fn delay_impairment(d: Duration) -> f64 {
        id(millis(d), ROOM, DelaySensitivity::Default)
    }

    /// The delay impairment on this model's scale: [`delay_impairment`](Self::delay_impairment)
    /// for a narrowband codec, G.107.1's `Id,WB` (Corrigendum 1) for a wideband one, G.107.2's
    /// `Id,FB = 1.48 Idd` for a fullband one.
    #[must_use]
    pub fn scaled_delay_impairment(&self, d: Duration) -> f64 {
        let t = millis(d);
        match self.scale {
            Scale::Narrow => id(t, self.room.unwrap_or(ROOM), self.class),
            Scale::Wide => id_wb(t),
            Scale::Full => id_fb(t, self.class),
        }
    }

    /// The effective equipment impairment `Ie,eff` (`Ie,eff,WB` / `Ie,eff,FB` on the scale
    /// of a wideband / fullband model) with `loss` (0..=1) of the packets lost or discarded
    /// and burst ratio `burst_ratio` (1 for random loss).
    #[must_use]
    pub fn equipment_impairment(&self, loss: f64, burst_ratio: f64) -> f64 {
        let ppl = (loss * 100.0).clamp(0.0, 100.0);
        let burst = if burst_ratio.is_finite() && burst_ratio > 0.0 {
            burst_ratio
        } else {
            1.0
        };
        if self.scale == Scale::Full {
            if ppl == 0.0 {
                return self.ie;
            }
            let share = ((ppl - (1.0 - burst) / self.brf) / (ppl + self.bpl)).clamp(0.0, 1.0);
            return self.ie + (FB_LOSS_TOP - self.ie).max(0.0) * share;
        }
        self.ie + (LOSS_TOP - self.ie).max(0.0) * ppl / (ppl / burst + self.bpl)
    }

    /// The ratings and scores of a path losing `loss` (0..=1, lost and discarded packets) with
    /// burst ratio `burst_ratio` and one-way mouth-to-ear delay `one_way`.
    #[must_use]
    pub fn score(&self, loss: f64, burst_ratio: f64, one_way: Duration) -> EModelScore {
        let t = millis(one_way);
        let ie = self.equipment_impairment(loss, burst_ratio);
        let (r_lq, r) = match self.scale {
            Scale::Narrow => {
                let room = self.room.unwrap_or(ROOM);
                let ro = ro(room);
                (
                    ro - is(0.0, room) - id(0.0, room, self.class) - ie,
                    ro - is(t, room) - id(t, room, self.class) - ie,
                )
            }
            Scale::Wide => (
                (RO_WB - id_wb(0.0) - ie) / WB_SCALE,
                (RO_WB - id_wb(t) - ie) / WB_SCALE,
            ),
            Scale::Full => {
                let ro = self.ro_fb();
                (
                    (ro - id_fb(0.0, self.class) - ie) / FB_SCALE,
                    (ro - id_fb(t, self.class) - ie) / FB_SCALE,
                )
            }
        };
        let (r, r_lq) = (r.clamp(0.0, 100.0), r_lq.clamp(0.0, 100.0));
        EModelScore {
            r_factor: r,
            r_lq,
            mos_cq: mos_from_r(r),
            mos_lq: mos_from_r(r_lq),
        }
    }

    /// [`score`](Self::score) from what a receiver measures: the one-way delay is half the
    /// round-trip time (0 if unknown) plus the end system delay, which when not given is a
    /// jitter buffer of twice the interarrival `jitter` (at least `packet` of media) plus one
    /// packet of media for the encoder.
    #[must_use]
    pub fn estimate(
        &self,
        loss: f64,
        burst_ratio: f64,
        round_trip: Option<Duration>,
        jitter: Duration,
        packet: Duration,
        end_system_delay: Option<Duration>,
    ) -> EModelScore {
        let end = end_system_delay.unwrap_or_else(|| (jitter * 2).max(packet) + packet);
        let one_way = round_trip.map_or(Duration::ZERO, |r| r / 2) + end;
        self.score(loss, burst_ratio, one_way)
    }

    /// [`estimate`](Self::estimate) for the loss so far of `model` and the round trip and
    /// end system delay of `quality`; without an end system delay, a known jitter buffer's
    /// nominal delay plus one `packet` stands for it, else twice the `jitter`.
    #[must_use]
    pub fn estimate_report(
        &self,
        model: &BurstLossModel,
        quality: &VoipQuality,
        jitter: Duration,
        packet: Duration,
    ) -> EModelScore {
        let end = quality.end_system_delay.or_else(|| {
            quality
                .jitter_buffer
                .filter(|j| !j.nominal.is_zero())
                .map(|j| j.nominal + packet)
        });
        self.estimate(
            model.loss_fraction(),
            model.burst_ratio(),
            quality.round_trip,
            jitter,
            packet,
            end,
        )
    }
}

impl Plc {
    /// The concealment an RTP encoding's decoder always does (SDP name, any case): Opus
    /// (RFC 6716 §4.4) and EVS (3GPP TS 26.447) are [`Plc::Enhanced`], G.729 (§4.4), G.723.1
    /// (frame erasure concealment) and AMR / AMR-WB (TS 26.091 / 26.191) [`Plc::Standard`];
    /// others (G.711's Appendix I and G.722's Appendices III /
    /// IV are optional) [`Plc::Unspecified`].
    #[must_use]
    pub fn of_codec(name: &str) -> Plc {
        match name.to_ascii_lowercase().as_str() {
            "opus" | "evs" => Plc::Enhanced,
            "g729" | "g723" | "amr-wb" | "amr" => Plc::Standard,
            _ => Plc::Unspecified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g107_default_intermediates() {
        // G.107 §7 with the Table 3 defaults: No = -61.18 dBm0p, Ro = 94.77, Is = 1.41.
        assert!((noise_no(ROOM) + 61.18).abs() < 0.005, "{}", noise_no(ROOM));
        assert!((ro(ROOM) - 94.77).abs() < 0.005, "{}", ro(ROOM));
        assert!((is(0.0, ROOM) - 1.41).abs() < 0.01, "{}", is(0.0, ROOM));
        // No absolute-delay impairment up to 100 ms; talker echo none at 0 ms.
        let d = DelaySensitivity::Default;
        let idle0 = id(0.0, ROOM, d);
        assert!((id(100.0, ROOM, d) - idle0) > 0.0);
        let x: f64 = 1.0;
        let idd200 = 25.0
            * ((1.0 + x.powi(6)).powf(1.0 / 6.0) - 3.0 * (1.0 + (x / 3.0).powi(6)).powf(1.0 / 6.0)
                + 2.0);
        assert!((idd200 - 3.044).abs() < 0.001);
    }
}
