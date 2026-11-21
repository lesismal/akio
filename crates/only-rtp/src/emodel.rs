//! Call quality estimation with the E-model (ITU-T G.107): the transmission rating R and the
//! mean opinion scores the VoIP metrics block of RTCP XR carries (RFC 3611 §4.7.5).

use std::time::Duration;

use crate::xr::VoipQuality;

/// `Ro - Is` of G.107 with every default parameter (basic signal-to-noise ratio less the
/// simultaneous impairments).
const R_DEFAULT: f64 = 93.2;

/// The E-model of a narrowband speech path with default parameters (G.107 §7, Table 3: no
/// echo, default noise and loudness), the delay impairment in Cole and Rosenbluth's
/// approximation (`Id = 0.024 d + 0.11 (d - 177.3)` above 177.3 ms of one-way delay `d`),
/// and the effective equipment impairment of G.107 §7.4 from the codec's `ie` / `bpl`, the
/// packet loss and the burst ratio:
///
/// `R = 93.2 - Id - Ie,eff`, `Ie,eff = Ie + (95 - Ie) Ppl / (Ppl / BurstR + Bpl)`.
///
/// The default codec is G.711 with packet loss concealment (G.113 Appendix I: `Ie = 0`,
/// `Bpl = 25.1`); pass a codec's own values with [`EModel::codec`] (for example
/// `Ie = 0, Bpl = 4.3` for G.711 without concealment, `Ie = 11, Bpl = 19` for G.729A + VAD).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EModel {
    ie: f64,
    bpl: f64,
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

impl EModel {
    /// The model for a codec of equipment impairment `ie` and packet-loss robustness `bpl`.
    #[must_use]
    pub fn codec(ie: f64, bpl: f64) -> EModel {
        EModel {
            ie: ie.clamp(0.0, 95.0),
            bpl: bpl.max(1.0),
        }
    }

    /// The delay impairment `Id` of one-way mouth-to-ear delay `d`.
    #[must_use]
    pub fn delay_impairment(d: Duration) -> f64 {
        let d = d.as_secs_f64() * 1000.0;
        let mut id = 0.024 * d;
        if d > 177.3 {
            id += 0.11 * (d - 177.3);
        }
        id
    }

    /// The effective equipment impairment `Ie,eff` with `loss` (0..=1) of the packets lost or
    /// discarded and burst ratio `burst_ratio` (1 for random loss).
    #[must_use]
    pub fn equipment_impairment(&self, loss: f64, burst_ratio: f64) -> f64 {
        let ppl = (loss * 100.0).clamp(0.0, 100.0);
        let burst = if burst_ratio.is_finite() && burst_ratio > 0.0 {
            burst_ratio
        } else {
            1.0
        };
        self.ie + (95.0 - self.ie) * ppl / (ppl / burst + self.bpl)
    }

    /// The ratings and scores of a path losing `loss` (0..=1, lost and discarded packets) with
    /// burst ratio `burst_ratio` and one-way mouth-to-ear delay `one_way`.
    #[must_use]
    pub fn score(&self, loss: f64, burst_ratio: f64, one_way: Duration) -> EModelScore {
        let r_lq = (R_DEFAULT - self.equipment_impairment(loss, burst_ratio)).clamp(0.0, 100.0);
        let r = (r_lq - EModel::delay_impairment(one_way)).clamp(0.0, 100.0);
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
}
