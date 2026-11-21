//! libwebrtc's FEC protection policy (`media_opt_util.cc`, `fec_controller_default.cc`): the
//! protection factors of delta and key frames from the loss, the bitrate per frame and the
//! resolution (`VCMFecMethod`), and with NACK the RTT-aware hybrid (`VCMNackFecMethod`): no
//! FEC on delta frames below 20 ms of RTT, groups spanning more frames as the RTT grows, no
//! FEC at all for small frames below 200 ms.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::{FecMaskType, FecProtection, tables};

/// Loss values (x 255) of the rate table; higher losses use the last column.
const LOSS_MAX: usize = 129;
/// The RTT below which the hybrid sends no FEC on delta frames (`kLowRttNackMs`).
const LOW_RTT_NACK: Duration = Duration::from_millis(20);
/// The RTT below which the hybrid turns FEC off for small frames (`kMaxRttTurnOffFec`).
const MAX_RTT_TURN_OFF_FEC: Duration = Duration::from_millis(200);
/// Frames per group at most (`kUpperLimitFramesFec`).
const UPPER_LIMIT_FRAMES_FEC: f64 = 6.0;
/// Bytes per frame below which the hybrid turns FEC off (`kMaxBytesPerFrameForFec*`): CIF
/// and smaller, up to VGA, larger.
const MAX_BYTES_FOR_FEC_LOW: f64 = 400.0;
const MAX_BYTES_FOR_FEC: f64 = 700.0;
const MAX_BYTES_FOR_FEC_HIGH: f64 = 1000.0;
/// Payload bytes per packet the rate table assumes (`_maxPayloadSize`).
const MAX_PAYLOAD: f64 = 1460.0;
/// The reference resolution of the rate table (4CIF), and the one assumed when unknown.
const REF_PIXELS: f64 = 704.0 * 576.0;
/// Key frames get at least twice the delta factor (`_scaleProtKey`).
const SCALE_KEY: f64 = 2.0;
/// The loss history: per-second maxima over 10 seconds (`kLossPrHistorySize`,
/// `kLossPrShortFilterWinMs`).
const LOSS_HISTORY: usize = 10;
const LOSS_WINDOW: Duration = Duration::from_secs(1);
/// Frame statistics are measured over this window.
const FRAME_WINDOW: Duration = Duration::from_secs(1);
/// Frames kept for that window at most (120 fps).
const MAX_FRAMES: usize = 128;

/// What the protection depends on, for [`protection_factors`].
#[derive(Debug, Clone, Copy, PartialEq)]
struct Params {
    /// Loss x 255 (filtered).
    loss: u8,
    /// Media bitrate of the stream (bits per second).
    bitrate: f64,
    framerate: f64,
    packets_per_frame: f64,
    packets_per_key_frame: f64,
    pixels: f64,
    rtt: Duration,
}

/// The FEC protection factors (delta, key; FEC packets per 256 media packets) and frames per
/// group that libwebrtc chooses for a stream: `loss` is the packet loss fraction (libwebrtc
/// takes the maximum of the last 10 s, which [`ProtectionPolicy`] keeps), `bitrate` the media
/// bitrate in bits per second, `framerate` in frames per second, `packets_per_frame` /
/// `packets_per_key_frame` the media packets of delta / key frames, `pixels` the frame size
/// (`None`: 704 x 576), and `nack`: the receiver NACKs, so the RTT-aware hybrid applies
/// (`rtt`).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn protection_factors(
    loss: f64,
    bitrate: u64,
    framerate: f64,
    packets_per_frame: f64,
    packets_per_key_frame: f64,
    pixels: Option<u32>,
    nack: bool,
    rtt: Duration,
) -> FecProtection {
    let p = Params {
        loss: sat_u8(255.0 * loss),
        bitrate: bitrate as f64,
        framerate,
        packets_per_frame,
        packets_per_key_frame,
        pixels: pixels.map_or(REF_PIXELS, f64::from),
        rtt,
    };
    compute(&p, nack)
}

fn sat_u8(v: f64) -> u8 {
    v.clamp(0.0, 255.0) as u8
}

/// Kilobits per frame (`BitsPerFrame`, one temporal layer).
fn kbits_per_frame(p: &Params) -> f64 {
    let fr = p.framerate.max(1.0);
    p.bitrate / 1000.0 / fr
}

/// `VCMFecMethod::ProtectionFactor`: the code rates (FEC / all packets x 255) of delta and key
/// frames.
fn code_rates(p: &Params) -> (u8, u8) {
    let mut loss = usize::from(p.loss);
    if loss == 0 {
        return (0, 0);
    }
    let first_partition_prot = sat_u8(255.0 * 0.20);
    let (rate_par1, rate_par2) = (5i64, 49i64);
    let resoln_fac = 1.0 / (p.pixels / REF_PIXELS).max(1e-6).powf(0.3);
    let bits_per_frame = kbits_per_frame(p) as i64;
    let avg_tot_packets = sat_u8(1.5 + bits_per_frame as f64 * 1000.0 / (8.0 * MAX_PAYLOAD));
    let eff_rate = (resoln_fac * bits_per_frame as f64).clamp(0.0, 65535.0) as i64;
    let rate_index = ((eff_rate - rate_par1) / rate_par1).clamp(0, rate_par2) as usize;
    if loss >= LOSS_MAX {
        loss = LOSS_MAX - 1;
    }
    let mut delta = tables::FEC_RATE[rate_index * LOSS_MAX + loss];
    if loss > 0 && avg_tot_packets > 1 && delta < first_partition_prot {
        delta = first_partition_prot;
    }
    if usize::from(delta) >= LOSS_MAX {
        delta = (LOSS_MAX - 1) as u8;
    }
    // Key frames: boosted by their size relative to delta frames.
    let pf_delta = sat_u8(0.5 + p.packets_per_frame);
    let pf_key = sat_u8(0.5 + p.packets_per_key_frame);
    let ratio = if pf_delta > 0 { pf_key / pf_delta } else { 1 };
    let boost = i64::from(ratio.max(2));
    let key_index = (1 + (boost * eff_rate - rate_par1) / rate_par1).clamp(0, rate_par2) as usize;
    let key_idx = (key_index * LOSS_MAX + loss).min(tables::FEC_RATE.len() - 1);
    let code_key = tables::FEC_RATE[key_idx];
    let boost_key = ((SCALE_KEY * f64::from(delta)) as usize).min(LOSS_MAX - 1);
    let mut key = (loss.max(boost_key).max(usize::from(code_key))).min(255) as u8;
    if usize::from(key) >= LOSS_MAX {
        key = (LOSS_MAX - 1) as u8;
    }
    (delta, key)
}

/// `ConvertFECRate`: a code rate (FEC / all packets) to a protection factor (FEC / media
/// packets), both x 255.
fn convert(code_rate: u8) -> u8 {
    let c = f64::from(code_rate);
    sat_u8((0.5 + 255.0 * c / (255.0 - c)).min(255.0))
}

fn compute(p: &Params, nack: bool) -> FecProtection {
    let (mut delta, mut key) = code_rates(p);
    let mut max_frames = 1.0f64;
    if nack {
        if p.rtt < LOW_RTT_NACK {
            delta = 0;
        }
        max_frames = (2.0 * p.framerate * p.rtt.as_secs_f64() + 0.5)
            .floor()
            .clamp(1.0, UPPER_LIMIT_FRAMES_FEC);
        // `BitRateTooLowForFec`.
        let bytes_per_frame = 1000.0 * kbits_per_frame(p).floor() / 8.0;
        let max_bytes = if p.pixels <= 352.0 * 288.0 {
            MAX_BYTES_FOR_FEC_LOW
        } else if p.pixels > 640.0 * 480.0 {
            MAX_BYTES_FOR_FEC_HIGH
        } else {
            MAX_BYTES_FOR_FEC
        };
        if bytes_per_frame < max_bytes && p.rtt < MAX_RTT_TURN_OFF_FEC {
            delta = 0;
            key = 0;
        }
    }
    FecProtection {
        delta_rate: convert(delta),
        key_rate: convert(key),
        max_frames: max_frames as u8,
        mask: FecMaskType::Random,
    }
}

/// libwebrtc's FEC controller for one sent stream: it measures the stream (frames, packets and
/// bytes over the last second), keeps the loss maxima of the last 10 seconds and the RTT, and
/// gives the [`FecProtection`] for [`FecEncoder::set_protection`](super::FecEncoder::set_protection)
/// as libwebrtc's `FecControllerDefault` with the `NackFec` method (when the receiver NACKs)
/// or the `Fec` method: the code rate from libwebrtc's table for the loss and bits per frame
/// (adjusted for the resolution), at least 20 % on delta frames with loss and multi-packet
/// frames, key frames boosted by their size (at least twice), at most 50 %; with NACK no FEC
/// on delta frames below 20 ms of RTT, groups of `2 x framerate x rtt` frames (1..=6), and no
/// FEC for frames under 400 / 700 / 1000 bytes (CIF / VGA / larger) below 200 ms.
#[derive(Debug)]
pub struct ProtectionPolicy {
    nack: bool,
    mask: FecMaskType,
    pixels: Option<u32>,
    rtt: Duration,
    /// Per-second loss maxima, newest first: (start of the second, maximum x 255).
    history: VecDeque<(Instant, u8)>,
    /// Sent frames: (when, packets, bytes, keyframe).
    frames: VecDeque<(Instant, usize, usize, bool)>,
    /// Packets of the last keyframe.
    key_packets: Option<usize>,
}

impl ProtectionPolicy {
    /// A policy for a stream whose receiver NACKs (`nack`: the hybrid) or does not.
    #[must_use]
    pub fn new(nack: bool) -> ProtectionPolicy {
        ProtectionPolicy {
            nack,
            mask: FecMaskType::Random,
            pixels: None,
            rtt: Duration::ZERO,
            history: VecDeque::new(),
            frames: VecDeque::new(),
            key_packets: None,
        }
    }

    /// Whether the receiver NACKs.
    pub fn set_nack(&mut self, nack: bool) {
        self.nack = nack;
    }

    /// The masks of the protection (libwebrtc always uses [`FecMaskType::Random`], the
    /// default).
    pub fn set_mask(&mut self, mask: FecMaskType) {
        self.mask = mask;
    }

    /// The frame size in pixels (unknown: the table's 704 x 576).
    pub fn set_pixels(&mut self, pixels: Option<u32>) {
        self.pixels = pixels.filter(|p| *p > 0);
    }

    /// The round-trip time to the receiver.
    pub fn set_rtt(&mut self, rtt: Duration) {
        self.rtt = rtt;
    }

    /// A loss fraction (0..=1) the receiver reported at `now`.
    pub fn on_loss(&mut self, now: Instant, loss: f64) {
        let l = sat_u8(255.0 * loss);
        match self.history.front_mut() {
            Some((at, m)) if now.saturating_duration_since(*at) < LOSS_WINDOW => {
                *m = (*m).max(l);
            }
            _ => {
                self.history.push_front((now, l));
                self.history.truncate(LOSS_HISTORY);
            }
        }
    }

    /// The loss the protection uses (libwebrtc's maximum filter): the largest of the last
    /// 10 seconds, x 255.
    fn filtered_loss(&self, now: Instant) -> u8 {
        let span = LOSS_WINDOW * LOSS_HISTORY as u32;
        self.history
            .iter()
            .take_while(|(at, _)| now.saturating_duration_since(*at) <= span)
            .map(|&(_, l)| l)
            .max()
            .unwrap_or(0)
    }

    /// A frame of `packets` media packets and `bytes` bytes sent at `now`.
    pub fn on_frame(&mut self, now: Instant, packets: usize, bytes: usize, keyframe: bool) {
        if keyframe {
            self.key_packets = Some(packets);
        }
        self.frames.push_back((now, packets, bytes, keyframe));
        while self.frames.len() > MAX_FRAMES
            || self
                .frames
                .front()
                .is_some_and(|f| now.saturating_duration_since(f.0) > FRAME_WINDOW)
        {
            self.frames.pop_front();
        }
    }

    /// The protection at `now`.
    #[must_use]
    pub fn protection(&self, now: Instant) -> FecProtection {
        let recent: Vec<_> = self
            .frames
            .iter()
            .filter(|f| now.saturating_duration_since(f.0) <= FRAME_WINDOW)
            .collect();
        let n = recent.len();
        let span = match (recent.first(), recent.last()) {
            (Some(a), Some(b)) if n > 1 => b.0.saturating_duration_since(a.0),
            _ => Duration::ZERO,
        };
        // Frames per second over what was seen (one frame: one per second at least).
        let secs = span.as_secs_f64().max(FRAME_WINDOW.as_secs_f64() / 30.0);
        let framerate = if n > 1 {
            (n - 1) as f64 / secs
        } else {
            n as f64
        };
        let bytes: usize = recent.iter().map(|f| f.2).sum();
        let bitrate = if n > 1 {
            // The bytes of the frames after the first, over the span.
            (bytes - recent[0].2) as f64 * 8.0 / secs
        } else {
            bytes as f64 * 8.0
        };
        let deltas: Vec<usize> = recent.iter().filter(|f| !f.3).map(|f| f.1).collect();
        let ppf = if deltas.is_empty() {
            recent.iter().map(|f| f.1).max().unwrap_or(1) as f64
        } else {
            deltas.iter().sum::<usize>() as f64 / deltas.len() as f64
        };
        let p = Params {
            loss: self.filtered_loss(now),
            bitrate,
            framerate,
            packets_per_frame: ppf,
            packets_per_key_frame: self.key_packets.map_or(ppf, |k| k as f64),
            pixels: self.pixels.map_or(REF_PIXELS, f64::from),
            rtt: self.rtt,
        };
        FecProtection {
            mask: self.mask,
            ..compute(&p, self.nack)
        }
    }
}
