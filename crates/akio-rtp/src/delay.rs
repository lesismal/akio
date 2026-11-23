//! The delay statistics of the playout buffers ([`JitterBuffer`](crate::JitterBuffer),
//! [`VideoPlayout`](crate::VideoPlayout)): the smallest transit time seen lately and a
//! forgetting histogram of each sample's delay beyond it.

use std::time::Duration;

/// Histogram bucket width (µs).
pub(crate) const BUCKET_US: i64 = 2_000;
/// The share of samples that should arrive in time.
const QUANTILE: f64 = 0.95;
/// The histogram's forgetting factor per sample.
const FORGET: f64 = 0.997;
/// Samples between two percentile computations.
const RECOMPUTE: u32 = 8;
/// The window of the smallest transit time (µs); the minimum covers the last one or two.
const MIN_WINDOW_US: i64 = 5_000_000;

pub(crate) fn us(d: Duration) -> i64 {
    i64::try_from(d.as_micros()).unwrap_or(i64::MAX)
}

/// Transit times (arrival minus media time, µs on a local epoch) and the 95th percentile of
/// their excess over the smallest one: the minimum over two windows of 5 s (so a clock drift
/// or a route change moves it); a histogram of 2 ms buckets up to the largest delay asked
/// for, forgetting by 0.997 per sample; the percentile recomputed every 8 samples and at
/// once for a sample above it.
#[derive(Debug)]
pub(crate) struct DelayEstimator {
    min_cur: i64,
    min_prev: i64,
    window_end: i64,
    hist: Vec<f64>,
    weight: f64,
    total: f64,
    since: u32,
    quantile_us: i64,
}

impl DelayEstimator {
    /// Buckets for delays up to `max` (at most 1002 for the 2 s bound).
    pub(crate) fn new(max: Duration) -> DelayEstimator {
        DelayEstimator {
            min_cur: i64::MAX,
            min_prev: i64::MAX,
            window_end: MIN_WINDOW_US,
            hist: vec![0.0; (us(max) / BUCKET_US) as usize + 2],
            weight: 1.0,
            total: 0.0,
            since: 0,
            quantile_us: 0,
        }
    }

    /// The smallest transit lately (`i64::MAX` before the first sample).
    pub(crate) fn min_transit(&self) -> i64 {
        self.min_cur.min(self.min_prev)
    }

    /// The latest percentile (µs).
    pub(crate) fn quantile_us(&self) -> i64 {
        self.quantile_us
    }

    /// Forgets the smallest transit (the media clock jumped): the next sample sets it.
    pub(crate) fn reset_min(&mut self, now_us: i64) {
        self.min_cur = i64::MAX;
        self.min_prev = i64::MAX;
        self.window_end = now_us;
    }

    /// A sample of transit `transit` at `now_us`: its delay beyond the smallest transit, and
    /// whether the percentile was recomputed.
    pub(crate) fn sample(&mut self, now_us: i64, transit: i64) -> (i64, bool) {
        if now_us >= self.window_end {
            self.min_prev = self.min_cur;
            self.min_cur = transit;
            self.window_end = now_us + MIN_WINDOW_US;
        } else {
            self.min_cur = self.min_cur.min(transit);
        }
        let d = transit - self.min_transit();
        self.histogram_add(d);
        self.since += 1;
        if self.since >= RECOMPUTE || d > self.quantile_us {
            self.since = 0;
            self.quantile_us = self.quantile();
            return (d, true);
        }
        (d, false)
    }

    fn histogram_add(&mut self, d: i64) {
        // Bucket b holds delays in ((b - 1) W, b W]: 0 alone in the first.
        let b = ((d.max(0) + BUCKET_US - 1) / BUCKET_US) as usize;
        let b = b.min(self.hist.len() - 1);
        self.hist[b] += self.weight;
        self.total += self.weight;
        self.weight /= FORGET;
        if self.weight > 1e200 {
            for h in &mut self.hist {
                *h /= self.weight;
            }
            self.total /= self.weight;
            self.weight = 1.0;
        }
    }

    fn quantile(&self) -> i64 {
        let goal = QUANTILE * self.total;
        let mut cum = 0.0;
        for (b, &h) in self.hist.iter().enumerate() {
            cum += h;
            if h > 0.0 && cum >= goal {
                return b as i64 * BUCKET_US;
            }
        }
        (self.hist.len() as i64 - 1) * BUCKET_US
    }
}
