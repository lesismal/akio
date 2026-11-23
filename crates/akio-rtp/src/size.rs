//! Frame-size-aware delay estimation for the video playout buffer (ADR-092 update): the
//! extra delay a frame as large as the largest recent one takes to arrive, beyond an average
//! frame, from a Kalman filter of each frame's delay variation against its size change, as
//! libwebrtc's jitter estimator (`modules/video_coding/timing/jitter_estimator.cc`) does.
//!
//! Units are milliseconds and bytes inside (the filter's constants are libwebrtc's).

/// Forgetting factor of the average frame size and its variance.
const PHI: f64 = 0.97;
/// Decay of the largest frame size per frame.
const PSI: f64 = 0.9999;
/// Frames averaged before the filtered average starts.
const STARTUP_FRAMES: u32 = 5;
/// The noise estimate's averaging window grows to this many frames.
const ALPHA_COUNT_MAX: f64 = 400.0;
/// A delay sample further than this many noise deviations from the line is an outlier.
const DELAY_OUTLIER_SD: f64 = 15.0;
/// A frame larger than the average by this many deviations is taken even as an outlier.
const SIZE_OUTLIER_SD: f64 = 3.0;
/// The smallest slope (ms per byte): a channel of at most 1 Gbit/s.
const THETA_LOW: f64 = 8.0 / 1e9 * 1e3;
/// Process noise of the slope and the offset.
const Q: [f64; 2] = [2.5e-10, 1e-10];

/// The Kalman filter of `delay variation = slope x size change + offset`.
#[derive(Debug, Clone)]
pub(crate) struct FrameSizeEstimator {
    /// ms per byte, ms.
    theta: [f64; 2],
    p: [[f64; 2]; 2],
    avg_noise: f64,
    var_noise: f64,
    alpha_count: f64,
    avg_size: f64,
    var_size: f64,
    max_size: f64,
    startup_sum: f64,
    startup_count: u32,
    prev_size: Option<f64>,
}

impl Default for FrameSizeEstimator {
    fn default() -> FrameSizeEstimator {
        FrameSizeEstimator {
            // 512 kbit/s.
            theta: [1.0 / (512e3 / 8.0), 0.0],
            p: [[1e4, 0.0], [0.0, 1e2]],
            avg_noise: 0.0,
            var_noise: 4.0,
            alpha_count: 1.0,
            avg_size: 0.0,
            var_size: 100.0,
            max_size: 0.0,
            startup_sum: 0.0,
            startup_count: 0,
            prev_size: None,
        }
    }
}

impl FrameSizeEstimator {
    /// Forgets the previous frame (a repaired or missing frame broke the chain): the next
    /// frame starts a new pair.
    pub(crate) fn break_chain(&mut self) {
        self.prev_size = None;
    }

    /// A frame of `bytes` whose delay changed by `delay_us` from the previous frame of the
    /// chain (its completion interval minus its media interval).
    pub(crate) fn update(&mut self, delay_us: i64, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let size = bytes as f64;
        if self.startup_count < STARTUP_FRAMES {
            self.startup_sum += size;
            self.startup_count += 1;
            if self.startup_count == STARTUP_FRAMES {
                self.avg_size = self.startup_sum / f64::from(STARTUP_FRAMES);
            }
        } else {
            // Only frames that are not much larger than the average (keyframes) move it.
            let avg = PHI * self.avg_size + (1.0 - PHI) * size;
            if size < self.avg_size + 2.0 * self.var_size.sqrt() {
                self.avg_size = avg;
            }
            let d = size - avg;
            self.var_size = (PHI * self.var_size + (1.0 - PHI) * d * d).max(1.0);
        }
        self.max_size = (PSI * self.max_size).max(size);
        let Some(prev) = self.prev_size.replace(size) else {
            return;
        };
        let delta = size - prev;
        // Not clamped to a few noise deviations: the samples that tell the slope are the
        // keyframes', far above the noise of a steady stream.
        let delay = delay_us as f64 / 1e3;
        let deviation = delay - (self.theta[0] * delta + self.theta[1]);
        let sd = self.var_noise.sqrt();
        if deviation.abs() < DELAY_OUTLIER_SD * sd
            || size > self.avg_size + SIZE_OUTLIER_SD * self.var_size.sqrt()
        {
            self.noise(deviation);
            if delta > -0.25 * self.max_size {
                self.kalman(delay, delta);
            }
        } else {
            self.noise(deviation.signum() * DELAY_OUTLIER_SD * sd);
        }
    }

    fn noise(&mut self, d: f64) {
        let alpha = (self.alpha_count - 1.0) / self.alpha_count;
        self.alpha_count = (self.alpha_count + 1.0).min(ALPHA_COUNT_MAX);
        self.avg_noise = alpha * self.avg_noise + (1.0 - alpha) * d;
        let e = d - self.avg_noise;
        self.var_noise = (alpha * self.var_noise + (1.0 - alpha) * e * e).max(1.0);
    }

    fn kalman(&mut self, delay: f64, delta: f64) {
        let p = &mut self.p;
        p[0][0] += Q[0];
        p[1][1] += Q[1];
        let mh = [p[0][0] * delta + p[0][1], p[1][0] * delta + p[1][1]];
        let sigma = ((300.0 * (-delta.abs() / self.max_size.max(1.0)).exp() + 1.0)
            * self.var_noise.sqrt())
        .max(1.0);
        let s = delta * mh[0] + mh[1] + sigma;
        if s.abs() < 1e-9 || !s.is_finite() {
            return;
        }
        let k = [mh[0] / s, mh[1] / s];
        let res = delay - (delta * self.theta[0] + self.theta[1]);
        self.theta[0] = (self.theta[0] + k[0] * res).max(THETA_LOW);
        self.theta[1] += k[1] * res;
        let (t00, t01) = (p[0][0], p[0][1]);
        p[0][0] = (1.0 - k[0] * delta) * t00 - k[0] * p[1][0];
        p[0][1] = (1.0 - k[0] * delta) * t01 - k[0] * p[1][1];
        p[1][0] = p[1][0] * (1.0 - k[1]) - k[1] * delta * t00;
        p[1][1] = p[1][1] * (1.0 - k[1]) - k[1] * delta * t01;
    }

    /// The extra delay (µs) of a frame of the largest recent size over an average one:
    /// `slope x (largest - average)`, 0 until the average is known.
    pub(crate) fn size_delay_us(&self) -> i64 {
        if self.startup_count < STARTUP_FRAMES {
            return 0;
        }
        let d = self.theta[0] * (self.max_size - self.avg_size).max(0.0) * 1e3;
        if d.is_finite() { d.min(1e10) as i64 } else { 0 }
    }

    /// The slope (µs per byte), for tests.
    #[cfg(test)]
    pub(crate) fn slope_us_per_byte(&self) -> f64 {
        self.theta[0] * 1e3
    }
}

#[cfg(test)]
mod tests {
    use super::FrameSizeEstimator;

    /// xorshift64*: deterministic noise in -1..1.
    fn noise(s: &mut u64) -> f64 {
        *s ^= *s >> 12;
        *s ^= *s << 25;
        *s ^= *s >> 27;
        (s.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 11) as f64 / (1u64 << 52) as f64 - 1.0
    }

    #[test]
    fn learns_the_channel_slope() {
        // A 2 Mbit/s bottleneck: 4 µs per byte. Frames of 4000..6000 bytes with a 40 kB
        // keyframe every 60; ±3 ms of noise on each frame's delay variation.
        let mut e = FrameSizeEstimator::default();
        let mut s = 9u64;
        let mut prev = 5000.0;
        for i in 0..3000 {
            let size: f64 = if i % 60 == 0 {
                40_000.0
            } else {
                5000.0 + 1000.0 * noise(&mut s)
            };
            let dv = 4.0 * (size - prev) + 3000.0 * noise(&mut s);
            prev = size;
            e.update(dv as i64, size as usize);
        }
        let slope = e.slope_us_per_byte();
        assert!((slope - 4.0).abs() < 0.6, "{slope}");
        // A keyframe's 35 kB over the average take about 140 ms.
        let d = e.size_delay_us();
        assert!((120_000..=165_000).contains(&d), "{d}");
    }

    #[test]
    fn equal_frames_add_nothing_and_breaks_restart() {
        let mut e = FrameSizeEstimator::default();
        let mut s = 3u64;
        for _ in 0..600 {
            e.update((2000.0 * noise(&mut s)) as i64, 3000);
        }
        assert_eq!(e.size_delay_us(), 0);
        e.break_chain();
        e.update(0, 0);
        assert_eq!(e.size_delay_us(), 0);
    }
}
