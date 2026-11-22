//! Call quality estimation with the E-model (ITU-T G.107, wideband codecs with G.107.1): the
//! transmission rating R and the mean opinion scores the VoIP metrics block of RTCP XR carries
//! (RFC 3611 §4.7.5).
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
/// The absolute delay below which there is no delay impairment (`mT`, ms).
const MT: f64 = 100.0;

/// The highest rating of G.107.1's wideband scale (`Ro,wb`; its `Is,wb` is 0).
const RO_WB: f64 = 129.0;
/// The wideband scale over the narrowband one (G.107.1: `R_wb = 1.29 R_nb`).
const WB_SCALE: f64 = 1.29;

/// The circuit noise `No` (dBm0p) of the default parameters (-61.18).
fn noise_no() -> f64 {
    let olr = SLR + RLR;
    let nfo = NFOR + RLR;
    let pre = PR + 10.0 * (1.0 + 10f64.powf((10.0 - LSTR) / 10.0)).log10();
    let nor = RLR - 121.0 + pre + 0.008 * (pre - 35.0).powi(2);
    let nos = PS - SLR - DS - 100.0 + 0.004 * (PS - olr - DS - 14.0).powi(2);
    10.0 * [NC, nos, nor, nfo]
        .iter()
        .map(|n| 10f64.powf(n / 10.0))
        .sum::<f64>()
        .log10()
}

/// The basic signal-to-noise ratio `Ro` (94.77).
fn ro() -> f64 {
    15.0 - 1.5 * (SLR + noise_no())
}

/// The simultaneous impairment `Is = Iolr + Ist + Iq` with one-way delay `t` ms (1.41).
fn is(t: f64) -> f64 {
    let no = noise_no();
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
    let y = (ro() - 100.0) / 15.0 + 46.0 / 8.4 - g / 9.0;
    let iq = 15.0 * (1.0 + 10f64.powf(y) + 10f64.powf(z)).log10();
    iolr + ist + iq
}

/// The delay impairment `Id = Idte + Idle + Idd` of G.107 §7.4 for mean one-way delay `t`
/// ms, absolute delay `Ta = T` and round trip `Tr = 2T`, on a scale of highest rating `ro`.
fn id(t: f64, ro: f64) -> f64 {
    let t = t.max(0.0);
    // Talker echo.
    let terv =
        TELR - 40.0 * ((1.0 + t / 10.0) / (1.0 + t / 150.0)).log10() + 6.0 * (-0.3 * t * t).exp();
    let re = 80.0 + 2.5 * (terv - 14.0);
    let roe = -1.5 * (noise_no() - RLR);
    let idte =
        ((roe - re) / 2.0 + ((roe - re).powi(2) / 4.0 + 100.0).sqrt() - 1.0) * (1.0 - (-t).exp());
    // Listener echo.
    let rle = 10.5 * (WEPL + 7.0) * (2.0 * t + 1.0).powf(-0.25);
    let idle = (ro - rle) / 2.0 + ((ro - rle).powi(2) / 4.0 + 169.0).sqrt();
    // Too long an absolute delay.
    let idd = if t <= MT {
        0.0
    } else {
        let x = (t / MT).log2();
        25.0 * ((1.0 + x.powi(6)).powf(1.0 / 6.0) - 3.0 * (1.0 + (x / 3.0).powi(6)).powf(1.0 / 6.0)
            + 2.0)
    };
    idte + idle + idd
}

fn millis(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// The E-model of a speech path (ITU-T G.107 §7) with every parameter the receiver cannot
/// measure at its Table 3 default (no echo beyond TELR 65 dB / WEPL 110 dB, default noise and
/// loudness: R = 93.2 unimpaired), the full delay impairment (`Id = Idte + Idle + Idd` with
/// `Ta = T`, `Tr = 2T`), and the effective equipment impairment of §7.5 from the codec's `Ie`
/// / `Bpl`, the packet loss and the burst ratio:
///
/// `R = Ro - Is - Id - Ie,eff`, `Ie,eff = Ie + (95 - Ie) Ppl / (Ppl / BurstR + Bpl)`.
///
/// A wideband codec ([`EModel::wideband`]) is rated on G.107.1's scale (`R_wb = 129 - Id -
/// Ie,wb,eff`, 129 in place of 95 in `Ie,wb,eff`) and the rating divided by 1.29 onto the
/// narrowband scale the VoIP metrics block and the MOS formula use (G.107.1), so a clean
/// wideband call rates 100 and a clean G.711 one 93.2.
///
/// The default codec is G.711 with packet loss concealment (G.113 Appendix I: `Ie = 0`,
/// `Bpl = 25.1`); [`EModel::for_codec`] has the planning values of the usual RTP codecs and
/// [`EModel::codec`] / [`EModel::wideband`] take any others.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EModel {
    ie: f64,
    bpl: f64,
    wideband: bool,
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

impl EModel {
    /// The narrowband model for a codec of equipment impairment `ie` and packet-loss
    /// robustness `bpl`.
    #[must_use]
    pub fn codec(ie: f64, bpl: f64) -> EModel {
        EModel {
            ie: ie.clamp(0.0, 95.0),
            bpl: bpl.max(1.0),
            wideband: false,
        }
    }

    /// The wideband model (G.107.1) for a codec of wideband equipment impairment `ie_wb`
    /// (0..=129) and packet-loss robustness `bpl_wb`.
    #[must_use]
    pub fn wideband(ie_wb: f64, bpl_wb: f64) -> EModel {
        EModel {
            ie: ie_wb.clamp(0.0, RO_WB),
            bpl: bpl_wb.max(1.0),
            wideband: true,
        }
    }

    /// Whether the codec is rated on the wideband scale.
    #[must_use]
    pub fn is_wideband(&self) -> bool {
        self.wideband
    }

    /// The model for the RTP encoding `name` (SDP `a=rtpmap` name, any case) whose receiver
    /// conceals losses as `plc` says; `None` for a codec without planning values here.
    ///
    /// | encoding | scale | Ie | Bpl | source |
    /// |---|---|---|---|---|
    /// | PCMU, PCMA | narrow | 0 | 25.1 (4.3 with [`Plc::Disabled`]) | G.113 App. I (G.711 App. I PLC) |
    /// | G729 | narrow | 11 | 19 | G.113 App. I (G.729A + VAD) |
    /// | G723 | narrow | 15 | 16.1 | G.113 App. I (G.723.1 6.3 kbit/s + VAD) |
    /// | G722 | wide | 13 | 4.3 | G.113 App. IV `Ie,wb` (64 kbit/s); G.107.1's default `Bpl` |
    /// | opus | wide | 0 | 25.1 | none in G.113: assumed (see below) |
    ///
    /// G.722's concealment is optional (G.722 Appendices III, IV), so it gets no robustness
    /// credit. ITU-T has no planning values for Opus: it is taken as transparent at the
    /// bitrates WebRTC uses (the wideband reference, `Ie,wb = 0`) with concealment as robust
    /// as G.711 Appendix I's. Measured values go in with [`EModel::wideband`].
    #[must_use]
    pub fn for_codec(name: &str, plc: Plc) -> Option<EModel> {
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
            "g723" => EModel::codec(15.0, 16.1),
            "g722" => EModel::wideband(13.0, BPL_NONE),
            "opus" => EModel::wideband(0.0, BPL_G711_PLC),
            _ => return None,
        })
    }

    /// The narrowband delay impairment `Id` (G.107 §7.4) of one-way mouth-to-ear delay `d`,
    /// with the default echo parameters, `Ta = d` and `Tr = 2d`: talker echo, listener echo
    /// and absolute delay (0.15 at 0 ms, about 3.8 at 150 ms, 20.7 at 300 ms).
    #[must_use]
    pub fn delay_impairment(d: Duration) -> f64 {
        id(millis(d), ro())
    }

    /// The effective equipment impairment `Ie,eff` (`Ie,wb,eff` on the wideband scale of a
    /// wideband model) with `loss` (0..=1) of the packets lost or discarded and burst ratio
    /// `burst_ratio` (1 for random loss).
    #[must_use]
    pub fn equipment_impairment(&self, loss: f64, burst_ratio: f64) -> f64 {
        let ppl = (loss * 100.0).clamp(0.0, 100.0);
        let burst = if burst_ratio.is_finite() && burst_ratio > 0.0 {
            burst_ratio
        } else {
            1.0
        };
        let top = if self.wideband { RO_WB } else { 95.0 };
        self.ie + (top - self.ie) * ppl / (ppl / burst + self.bpl)
    }

    /// The ratings and scores of a path losing `loss` (0..=1, lost and discarded packets) with
    /// burst ratio `burst_ratio` and one-way mouth-to-ear delay `one_way`.
    #[must_use]
    pub fn score(&self, loss: f64, burst_ratio: f64, one_way: Duration) -> EModelScore {
        let t = millis(one_way);
        let ie = self.equipment_impairment(loss, burst_ratio);
        let (r_lq, r) = if self.wideband {
            (
                (RO_WB - id(0.0, RO_WB) - ie) / WB_SCALE,
                (RO_WB - id(t, RO_WB) - ie) / WB_SCALE,
            )
        } else {
            let ro = ro();
            (ro - is(0.0) - id(0.0, ro) - ie, ro - is(t) - id(t, ro) - ie)
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
    /// (RFC 6716 §4.4) is [`Plc::Enhanced`], G.729 (§4.4) and G.723.1 (frame erasure
    /// concealment) [`Plc::Standard`]; others (G.711's Appendix I and G.722's Appendices III /
    /// IV are optional) [`Plc::Unspecified`].
    #[must_use]
    pub fn of_codec(name: &str) -> Plc {
        match name.to_ascii_lowercase().as_str() {
            "opus" => Plc::Enhanced,
            "g729" | "g723" => Plc::Standard,
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
        assert!((noise_no() + 61.18).abs() < 0.005, "{}", noise_no());
        assert!((ro() - 94.77).abs() < 0.005, "{}", ro());
        assert!((is(0.0) - 1.41).abs() < 0.01, "{}", is(0.0));
        // No absolute-delay impairment up to 100 ms; talker echo none at 0 ms.
        let idle0 = id(0.0, ro());
        assert!((id(100.0, ro()) - idle0) > 0.0);
        let x: f64 = 1.0;
        let idd200 = 25.0
            * ((1.0 + x.powi(6)).powf(1.0 / 6.0) - 3.0 * (1.0 + (x / 3.0).powi(6)).powf(1.0 / 6.0)
                + 2.0);
        assert!((idd200 - 3.044).abs() < 0.001);
    }
}
