#![deny(unsafe_code)]
//! A dudect-style statistical timing test for akio-crypto's secret-dependent paths
//! (docs/constant-time.md).
//!
//! For each target, measurements of two input classes (a fixed secret and a fresh random one)
//! are taken in random interleaved order with the CPU's cycle counter, and Welch's t-test
//! compares the two timing distributions: over all measurements, over 100 croppings of the upper
//! tail, and on the variance (second order). `|t| > 4.5` is a leak. A deliberately leaky compare
//! and square-and-multiply must be detected, an A/A test must not.
//!
//! ```text
//! ct-dudect [--seconds S] [--max-measurements N] [--threshold T] [--min-n N] [--seed X]
//!           [--fixed-random X] [--json FILE] [--list] [FILTER...]
//! AKIO_CRYPTO_PORTABLE=1 ct-dudect ...   # the portable implementations
//! ```
//!
//! The exit status is 1 if a secret target leaks or a sanity target is not detected.

// The same source file as akio-crypto's private `ct` module, so the primitives are measured as
// written (inlined into the harness, as they are inlined into their callers in akio-crypto).
#[path = "../../../crates/akio-crypto/src/ct.rs"]
mod ct;
mod rng;
mod stats;
mod targets;
mod timer;

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use rng::Rng;
use stats::{Dudect, MaxT};
use targets::{Kind, Spec, Target};

/// How long and how much to measure one target, and what the fixed class is.
#[derive(Clone, Copy, Debug)]
struct Budget {
    time: Duration,
    max_measurements: u64,
    min_n: f64,
    /// Class 0 is a fixed random-looking secret drawn from this seed instead of the special
    /// value (tells a value-specific difference from a general one).
    fixed_random: Option<u64>,
}

/// The outcome of one target.
#[derive(Debug)]
struct Outcome {
    spec: Spec,
    measurements: u64,
    max: MaxT,
    mean: [f64; 2],
    leak: bool,
}

impl Outcome {
    fn verdict(&self) -> &'static str {
        match (self.spec.kind, self.leak) {
            (Kind::Secret, false) => "ok",
            (Kind::Secret, true) => "LEAK",
            (Kind::Public, false) => "same",
            (Kind::Public, true) => "differs (public)",
            (Kind::Leaky, true) => "detected",
            (Kind::Leaky, false) => "MISSED",
        }
    }

    fn failed(&self) -> bool {
        matches!(
            (self.spec.kind, self.leak),
            (Kind::Secret, true) | (Kind::Leaky, false)
        )
    }
}

/// Times one batch: makes the inputs, then runs input `i` between two counter reads.
fn measure(
    t: &mut dyn Target,
    classes: &[u8],
    rng: &mut Rng,
    fixed_random: Option<u64>,
    times: &mut [u64],
) {
    t.prepare(classes, rng, fixed_random);
    for (i, slot) in times.iter_mut().enumerate() {
        let a = timer::now();
        t.run(i);
        let b = timer::now();
        *slot = b.wrapping_sub(a);
    }
}

/// Runs one target: a warm-up batch (sets the cropping thresholds, not counted), then batches
/// until the budget is spent.
fn run(spec: Spec, budget: Budget, threshold: f64, rng: &mut Rng) -> Outcome {
    let mut target = (spec.make)();
    let mut classes = vec![0u8; spec.batch];
    let mut times = vec![0u64; spec.batch];
    let fill = |classes: &mut [u8], rng: &mut Rng| {
        for c in classes.iter_mut() {
            *c = rng.class();
        }
    };
    fill(&mut classes, rng);
    measure(&mut *target, &classes, rng, budget.fixed_random, &mut times);
    let mut d = Dudect::new(&times);
    let start = Instant::now();
    let mut n = 0u64;
    while n < budget.max_measurements && (n == 0 || start.elapsed() < budget.time) {
        fill(&mut classes, rng);
        measure(&mut *target, &classes, rng, budget.fixed_random, &mut times);
        for (&c, &x) in classes.iter().zip(&times) {
            d.push(x, usize::from(c));
        }
        n += spec.batch as u64;
    }
    let max = d.max_t(budget.min_n);
    Outcome {
        spec,
        measurements: n,
        max,
        mean: d.raw().mean(),
        leak: max.t.abs() > threshold,
    }
}

struct Args {
    budget: Budget,
    threshold: f64,
    seed: Option<u64>,
    json: Option<String>,
    list: bool,
    filters: Vec<String>,
}

const USAGE: &str = "usage: ct-dudect [--seconds S] [--max-measurements N] [--threshold T] \
[--min-n N] [--seed X] [--fixed-random X] [--json FILE] [--list] [FILTER...]
  --seconds S           time per target (default 10)
  --max-measurements N  measurements per target at most (default 100000000)
  --threshold T         |t| above which a difference counts (default 4.5)
  --min-n N             measurements per class a cropped or 2nd-order test needs (default 1000)
  --seed X              seed of the class sequence and random secrets (default: OS randomness)
  --fixed-random X      fixed class: a random-looking secret from seed X, not the special value
  --json FILE           write the results as JSON
  --list                list the targets
  FILTER                run the targets whose name contains one of these
AKIO_CRYPTO_PORTABLE=1 measures the portable implementations instead of the hardware paths.";

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        budget: Budget {
            time: Duration::from_secs(10),
            max_measurements: 100_000_000,
            min_n: 1000.0,
            fixed_random: None,
        },
        threshold: 4.5,
        seed: None,
        json: None,
        list: false,
        filters: Vec::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
        let num = |name: &str, v: String| {
            v.parse::<f64>()
                .ok()
                .filter(|x| x.is_finite() && *x >= 0.0)
                .ok_or_else(|| format!("{name}: not a number: {v}"))
        };
        match arg.as_str() {
            "--seconds" => {
                a.budget.time = Duration::from_secs_f64(num("--seconds", value("--seconds")?)?);
            }
            "--max-measurements" => {
                let v = value("--max-measurements")?;
                a.budget.max_measurements =
                    v.parse().map_err(|_| format!("--max-measurements: {v}"))?;
            }
            "--threshold" => a.threshold = num("--threshold", value("--threshold")?)?,
            "--min-n" => a.budget.min_n = num("--min-n", value("--min-n")?)?,
            "--seed" => {
                let v = value("--seed")?;
                a.seed = Some(v.parse().map_err(|_| format!("--seed: {v}"))?);
            }
            "--fixed-random" => {
                let v = value("--fixed-random")?;
                a.budget.fixed_random =
                    Some(v.parse().map_err(|_| format!("--fixed-random: {v}"))?);
            }
            "--json" => a.json = Some(value("--json")?),
            "--list" => a.list = true,
            "-h" | "--help" => return Err(String::new()),
            s if s.starts_with('-') => return Err(format!("unknown option {s}")),
            _ => a.filters.push(arg),
        }
    }
    Ok(a)
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn json_num(x: f64) -> String {
    if x.is_finite() {
        format!("{x:.3}")
    } else {
        // JSON has no infinity; a difference between constant samples.
        "1e308".to_string()
    }
}

fn to_json(path: &str, seed: u64, args: &Args, results: &[Outcome]) -> String {
    let mut o = String::from("{\n");
    let _ = writeln!(o, "  \"path\": {},", json_str(path));
    let _ = writeln!(o, "  \"timer\": {},", json_str(timer::NAME));
    let _ = writeln!(
        o,
        "  \"features\": {},",
        json_str(&akio_crypto::hardware_features())
    );
    let _ = writeln!(o, "  \"arch\": {},", json_str(std::env::consts::ARCH));
    let _ = writeln!(o, "  \"os\": {},", json_str(std::env::consts::OS));
    let _ = writeln!(o, "  \"seed\": {seed},");
    let _ = writeln!(o, "  \"threshold\": {},", json_num(args.threshold));
    let _ = writeln!(
        o,
        "  \"seconds_per_target\": {},",
        json_num(args.budget.time.as_secs_f64())
    );
    let fixed = args
        .budget
        .fixed_random
        .map_or_else(|| "special".to_string(), |x| format!("random seed {x}"));
    let _ = writeln!(o, "  \"fixed_class\": {},", json_str(&fixed));
    o.push_str("  \"results\": [\n");
    for (i, r) in results.iter().enumerate() {
        let _ = write!(
            o,
            "    {{\"target\": {}, \"kind\": {}, \"measurements\": {}, \"max_t\": {}, \"test\": {}, \
             \"test_n\": {}, \"mean_fixed\": {}, \"mean_random\": {}, \"verdict\": {}}}",
            json_str(r.spec.name),
            json_str(r.spec.kind.label()),
            r.measurements,
            json_num(r.max.t),
            json_str(&r.max.which.to_string()),
            json_num(r.max.n),
            json_num(r.mean[0]),
            json_num(r.mean[1]),
            json_str(r.verdict()),
        );
        o.push_str(if i + 1 < results.len() { ",\n" } else { "\n" });
    }
    o.push_str("  ]\n}\n");
    o
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("ct-dudect: {e}");
            }
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };
    let portable = akio_crypto::is_portable();
    let specs: Vec<Spec> = targets::all()
        .into_iter()
        .filter(|s| args.filters.is_empty() || args.filters.iter().any(|f| s.name.contains(f)))
        .collect();
    if args.list {
        for s in &specs {
            println!(
                "{:<28} {:<7} {}{}",
                s.name,
                s.kind.label(),
                s.about,
                if s.hw { "" } else { " [no hw path]" }
            );
        }
        return;
    }
    let seed = args.seed.unwrap_or_else(|| {
        let mut b = [0u8; 8];
        akio_crypto::rand::fill_random(&mut b).expect("OS randomness");
        u64::from_le_bytes(b)
    });
    let mut rng = Rng::new(seed);
    let path = if portable { "portable" } else { "hw" };
    println!(
        "ct-dudect: path {path} [{}], timer {}, {} s per target, |t| > {} is a leak, seed {seed}",
        akio_crypto::hardware_features(),
        timer::NAME,
        args.budget.time.as_secs_f64(),
        args.threshold,
    );
    if let Some(x) = args.budget.fixed_random {
        println!("fixed class: a random-looking secret from seed {x} (not the special value)");
    }
    println!(
        "{:<28} {:>7} {:>12} {:>9} {:>10} {:>12} {:>12}  verdict",
        "target", "kind", "measurements", "max |t|", "test", "mean fixed", "mean random"
    );
    let mut results = Vec::new();
    for spec in specs {
        // Without a hardware path the portable pass would repeat the hardware pass.
        if portable && !spec.hw {
            continue;
        }
        let r = run(spec, args.budget, args.threshold, &mut rng);
        println!(
            "{:<28} {:>7} {:>12} {:>9.2} {:>10} {:>12.1} {:>12.1}  {}",
            r.spec.name,
            r.spec.kind.label(),
            r.measurements,
            r.max.t.abs(),
            r.max.which.to_string(),
            r.mean[0],
            r.mean[1],
            r.verdict(),
        );
        results.push(r);
    }
    if let Some(file) = &args.json {
        if let Err(e) = std::fs::write(file, to_json(path, seed, &args, &results)) {
            eprintln!("ct-dudect: {file}: {e}");
            std::process::exit(2);
        }
    }
    let failed: Vec<&str> = results
        .iter()
        .filter(|r| r.failed())
        .map(|r| r.spec.name)
        .collect();
    if !failed.is_empty() {
        println!("FAILED: {}", failed.join(", "));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str) -> Spec {
        targets::all()
            .into_iter()
            .find(|s| s.name == name)
            .expect("target")
    }

    fn quick() -> Budget {
        Budget {
            time: Duration::from_secs(20),
            max_measurements: 40_000,
            min_n: 1000.0,
            fixed_random: None,
        }
    }

    /// The harness finds a real leak: an early-exit compare over 256 bytes, with differences
    /// of hundreds of cycles, on any machine and under a debug build.
    #[test]
    fn leaky_compare_is_detected() {
        let mut rng = Rng::new(1);
        let r = run(spec("sanity-leaky-memcmp"), quick(), 4.5, &mut rng);
        assert!(r.leak, "{r:?}");
        assert!(!r.failed());
    }

    /// Every target builds and runs (correctness, not timing: no verdict is checked).
    #[test]
    fn every_target_runs() {
        let mut rng = Rng::new(2);
        let b = Budget {
            time: Duration::ZERO,
            max_measurements: 1,
            min_n: 1000.0,
            fixed_random: None,
        };
        for s in targets::all() {
            let s = Spec {
                batch: s.batch.min(4),
                ..s
            };
            let r = run(s, b, 4.5, &mut rng);
            assert_eq!(r.measurements, s.batch as u64, "{}", s.name);
        }
    }

    #[test]
    fn json_is_well_formed() {
        let mut rng = Rng::new(3);
        let b = Budget {
            time: Duration::ZERO,
            max_measurements: 1,
            min_n: 1000.0,
            fixed_random: None,
        };
        let r = run(spec("ct-eq"), b, 4.5, &mut rng);
        let args = Args {
            budget: b,
            threshold: 4.5,
            seed: None,
            json: None,
            list: false,
            filters: Vec::new(),
        };
        let j = to_json("hw", 3, &args, &[r]);
        assert!(j.contains("\"target\": \"ct-eq\""), "{j}");
        assert_eq!(j.matches('{').count(), j.matches('}').count());
        assert_eq!(json_str("a\"b\\\n"), "\"a\\\"b\\\\\\u000a\"");
    }
}
