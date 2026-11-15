//! Welch's t-test and the dudect test set (Reparaz, Balasch, Verbauwhede, "Dude, is my code
//! constant time?", DATE 2017).
//!
//! Every measurement goes into:
//!
//! - one first-order test over all measurements;
//! - [`PERCENTILES`] first-order tests, test `i` keeping only the measurements below the
//!   `1 - 0.5^(10(i+1)/100)` quantile of the warm-up batch (cropping away the long upper tail
//!   that interrupts and cache misses add, which can hide a small difference);
//! - one second-order test over the squared distance from the class mean (a difference in
//!   variance rather than in mean), once [`SECOND_ORDER_AFTER`] measurements are in.
//!
//! The statistic reported is the largest `|t|` among the tests that have at least `min_n`
//! measurements in each class; `|t| > 4.5` is taken as a leak (as in dudect: for
//! normally-distributed equal means, the probability of `|t| > 4.5` is about 7·10⁻⁶ per test).

/// Number of cropped tests.
pub(crate) const PERCENTILES: usize = 100;
/// Measurements before the second-order test starts (its class means must have settled).
pub(crate) const SECOND_ORDER_AFTER: f64 = 10_000.0;

/// Online Welch's t-test between two classes (Welford's running mean and variance).
#[derive(Clone, Debug, Default)]
pub(crate) struct TTest {
    n: [f64; 2],
    mean: [f64; 2],
    m2: [f64; 2],
}

impl TTest {
    /// Adds measurement `x` of class `class` (0 or 1).
    pub(crate) fn push(&mut self, x: f64, class: usize) {
        self.n[class] += 1.0;
        let d = x - self.mean[class];
        self.mean[class] += d / self.n[class];
        self.m2[class] += d * (x - self.mean[class]);
    }

    /// Measurements per class.
    pub(crate) fn n(&self) -> [f64; 2] {
        self.n
    }

    /// Class means.
    pub(crate) fn mean(&self) -> [f64; 2] {
        self.mean
    }

    /// Welch's t statistic (0 until both classes have two measurements, or with zero
    /// variance in both).
    pub(crate) fn t(&self) -> f64 {
        if self.n[0] < 2.0 || self.n[1] < 2.0 {
            return 0.0;
        }
        let v0 = self.m2[0] / (self.n[0] - 1.0);
        let v1 = self.m2[1] / (self.n[1] - 1.0);
        let se = (v0 / self.n[0] + v1 / self.n[1]).sqrt();
        if se == 0.0 {
            // Identical constant samples: no evidence of a difference unless the means differ.
            return if self.mean[0] == self.mean[1] {
                0.0
            } else {
                f64::INFINITY
            };
        }
        (self.mean[0] - self.mean[1]) / se
    }
}

/// Which of the dudect tests produced a statistic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Which {
    /// All measurements.
    Raw,
    /// Measurements below the given cropping percentile (index into the thresholds).
    Cropped(usize),
    /// Second order (variance).
    SecondOrder,
}

impl std::fmt::Display for Which {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Raw => f.write_str("raw"),
            Self::Cropped(i) => write!(f, "crop{i}"),
            Self::SecondOrder => f.write_str("2nd-order"),
        }
    }
}

/// The largest `|t|` of a [`Dudect`] set.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MaxT {
    /// The signed statistic (class 0 slower when positive).
    pub(crate) t: f64,
    /// The test it came from.
    pub(crate) which: Which,
    /// Measurements in that test (both classes).
    pub(crate) n: f64,
}

/// The dudect test set over one target.
#[derive(Debug)]
pub(crate) struct Dudect {
    thresholds: Vec<f64>,
    raw: TTest,
    cropped: Vec<TTest>,
    second: TTest,
}

impl Dudect {
    /// A test set cropping at the quantiles of `warmup` (measurements of both classes, which
    /// are not counted).
    pub(crate) fn new(warmup: &[u64]) -> Self {
        let mut sorted = warmup.to_vec();
        sorted.sort_unstable();
        let thresholds = (0..PERCENTILES)
            .map(|i| {
                // `i` < 100, exact in f64.
                #[allow(clippy::cast_precision_loss)]
                let q = 1.0 - 0.5f64.powf(10.0 * (i as f64 + 1.0) / PERCENTILES as f64);
                percentile(&sorted, q)
            })
            .collect();
        Self {
            thresholds,
            raw: TTest::default(),
            cropped: vec![TTest::default(); PERCENTILES],
            second: TTest::default(),
        }
    }

    /// Adds measurement `x` of class `class`.
    pub(crate) fn push(&mut self, x: u64, class: usize) {
        // Cycle counts of one call fit f64 exactly far beyond any realistic duration.
        #[allow(clippy::cast_precision_loss)]
        let xf = x as f64;
        self.raw.push(xf, class);
        for (t, &thr) in self.cropped.iter_mut().zip(&self.thresholds) {
            if xf < thr {
                t.push(xf, class);
            }
        }
        let n = self.raw.n();
        if n[0] + n[1] > SECOND_ORDER_AFTER {
            let c = xf - self.raw.mean()[class];
            self.second.push(c * c, class);
        }
    }

    /// The test over all measurements.
    pub(crate) fn raw(&self) -> &TTest {
        &self.raw
    }

    /// The largest `|t|` among the tests with at least `min_n` measurements in each class
    /// (the raw test always counts once it has two per class).
    pub(crate) fn max_t(&self, min_n: f64) -> MaxT {
        let mut best = MaxT {
            t: self.raw.t(),
            which: Which::Raw,
            n: self.raw.n[0] + self.raw.n[1],
        };
        let others = self
            .cropped
            .iter()
            .enumerate()
            .map(|(i, t)| (Which::Cropped(i), t))
            .chain(std::iter::once((Which::SecondOrder, &self.second)));
        for (which, t) in others {
            if t.n[0] < min_n || t.n[1] < min_n {
                continue;
            }
            let v = t.t();
            if v.abs() > best.t.abs() {
                best = MaxT {
                    t: v,
                    which,
                    n: t.n[0] + t.n[1],
                };
            }
        }
        best
    }
}

/// The `q` quantile (0..1) of sorted values, as `f64` (nearest rank; 0 for no values).
pub(crate) fn percentile(sorted: &[u64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    // In range: q in [0, 1), len fits f64 for any batch that fits in memory.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let i = ((q * sorted.len() as f64) as usize).min(sorted.len() - 1);
    #[allow(clippy::cast_precision_loss)]
    let v = sorted[i] as f64;
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    /// Roughly normal noise (sum of 12 uniforms) around `mean` with a long upper tail.
    fn sample(rng: &mut Rng, mean: f64) -> u64 {
        let mut s = 0.0;
        for _ in 0..12 {
            #[allow(clippy::cast_precision_loss)]
            let u = (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
            s += u;
        }
        let tail = if rng.next_u64() % 100 == 0 {
            5000.0
        } else {
            0.0
        };
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let x = (mean + (s - 6.0) * 20.0 + tail) as u64;
        x
    }

    fn run(shift: f64, n: usize) -> MaxT {
        let mut rng = Rng::new(7);
        let warm: Vec<u64> = (0..10_000).map(|_| sample(&mut rng, 1000.0)).collect();
        let mut d = Dudect::new(&warm);
        for _ in 0..n {
            let c = usize::from(rng.next_u64() & 1 == 1);
            let m = if c == 1 { 1000.0 + shift } else { 1000.0 };
            d.push(sample(&mut rng, m), c);
        }
        d.max_t(1000.0)
    }

    #[test]
    fn welch_known_values() {
        // Two classes of known mean and variance: t = (2 - 4) / sqrt(1/3 + 1/3).
        let mut t = TTest::default();
        for x in [1.0, 2.0, 3.0] {
            t.push(x, 0);
        }
        for x in [3.0, 4.0, 5.0] {
            t.push(x, 1);
        }
        let want = -2.0 / (2.0f64 / 3.0).sqrt();
        assert!((t.t() - want).abs() < 1e-12, "{}", t.t());
        assert_eq!(TTest::default().t(), 0.0);
    }

    #[test]
    fn same_distribution_is_quiet() {
        let m = run(0.0, 200_000);
        assert!(m.t.abs() < 4.5, "{m:?}");
    }

    #[test]
    fn shifted_distribution_is_found() {
        // A shift of a tenth of the standard deviation, hidden under the tail in the raw test.
        let m = run(2.0, 200_000);
        assert!(m.t.abs() > 4.5, "{m:?}");
        assert_ne!(m.which, Which::Raw, "{m:?}");
    }

    #[test]
    fn percentiles() {
        let v: Vec<u64> = (0..100).collect();
        assert_eq!(percentile(&v, 0.0), 0.0);
        assert_eq!(percentile(&v, 0.5), 50.0);
        assert_eq!(percentile(&v, 0.999), 99.0);
        assert_eq!(percentile(&[], 0.5), 0.0);
    }
}
