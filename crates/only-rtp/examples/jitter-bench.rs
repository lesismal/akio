//! The jitter buffer's cost per frame (ADR-087), for the benchmark host:
//!
//! ```text
//! jitter-bench [frames]   push and pop 20 ms frames under 0..60 ms of jitter, 2 % loss
//! ```
//!
//! Prints `BENCH jitter <ns per frame>` (the best of 5 runs).
#![allow(missing_docs)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use only_rtp::{JitterBuffer, PlayoutDelay};

fn main() {
    let n: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000_000);
    // Arrivals precomputed (xorshift noise), sorted: only the buffer is timed.
    let t0 = Instant::now();
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut pkts: Vec<(u64, u32, Instant)> = Vec::with_capacity(n as usize);
    for i in 0..n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        if x % 100 < 2 {
            continue;
        }
        let jitter = Duration::from_micros(x % 60_000);
        pkts.push((
            i,
            (960 * i) as u32,
            t0 + Duration::from_millis(20 * i) + jitter,
        ));
    }
    pkts.sort_by_key(|p| p.2);
    let mut best = f64::MAX;
    for _ in 0..5 {
        let mut jb: JitterBuffer<u64> = JitterBuffer::new(48_000, PlayoutDelay::default());
        let start = Instant::now();
        let mut out = 0u64;
        for &(seq, ts, at) in &pkts {
            while let Some(f) = jb.pop(at) {
                out += f.seq;
            }
            jb.push(seq, ts, false, at, seq, 160);
        }
        out += jb.drain().len() as u64;
        let ns = start.elapsed().as_nanos() as f64 / pkts.len() as f64;
        black_box(out);
        best = best.min(ns);
    }
    println!("BENCH jitter {best:.1}");
}
