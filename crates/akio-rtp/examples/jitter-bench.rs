//! The playout buffers' cost per frame (ADR-087, ADR-092), for the benchmark host:
//!
//! ```text
//! jitter-bench [frames]         push and pop 20 ms audio frames under 0..60 ms of jitter, 2 % loss
//! jitter-bench video [frames]   push and pop 30 frames/s video frames completed under 0..40 ms
//!                               of jitter (in order), a keyframe every 60, 2 % flagged repaired
//! ```
//!
//! Prints `BENCH jitter <ns per frame>` or `BENCH video-playout <ns per frame>` (the best of 5
//! runs).
#![allow(missing_docs)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use akio_rtp::{JitterBuffer, PlayoutDelay, VideoFrameFlags, VideoPlayout};

fn xorshift(x: &mut u64) -> u64 {
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    *x
}

fn audio(n: u64) {
    // Arrivals precomputed (xorshift noise), sorted: only the buffer is timed.
    let t0 = Instant::now();
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut pkts: Vec<(u64, u32, Instant)> = Vec::with_capacity(n as usize);
    for i in 0..n {
        let r = xorshift(&mut x);
        if r % 100 < 2 {
            continue;
        }
        let jitter = Duration::from_micros(r % 60_000);
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

fn video(n: u64) {
    // Completion instants precomputed: each frame's jittered arrival, never before the
    // previous frame's (the assembler releases in order).
    let t0 = Instant::now();
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut frames: Vec<(u32, Instant, VideoFrameFlags)> = Vec::with_capacity(n as usize);
    let mut last = t0;
    for i in 0..n {
        let r = xorshift(&mut x);
        let at = (t0 + Duration::from_micros(i * 33_333 + r % 40_000)).max(last);
        last = at;
        let mut flags = VideoFrameFlags::NONE;
        if i % 60 == 0 {
            flags |= VideoFrameFlags::KEYFRAME;
        }
        if r % 100 < 2 {
            flags |= VideoFrameFlags::REPAIRED;
        }
        frames.push(((3000 * i) as u32, at, flags));
    }
    let mut best = f64::MAX;
    for _ in 0..5 {
        let mut pb: VideoPlayout<u64> = VideoPlayout::new(90_000, PlayoutDelay::default());
        pb.set_round_trip(Some(Duration::from_millis(50)));
        let start = Instant::now();
        let mut out = 0u64;
        for (i, &(ts, at, flags)) in frames.iter().enumerate() {
            while let Some(f) = pb.pop(at) {
                out += f.data;
            }
            pb.push(ts, at, flags, i as u64, 3000);
        }
        out += pb.drain().len() as u64;
        let ns = start.elapsed().as_nanos() as f64 / frames.len() as f64;
        black_box(out);
        best = best.min(ns);
    }
    println!("BENCH video-playout {best:.1}");
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (video_mode, count) = match a.get(1).map(String::as_str) {
        Some("video") => (true, a.get(2)),
        _ => (false, a.get(1)),
    };
    let n: u64 = count.and_then(|s| s.parse().ok()).unwrap_or(2_000_000);
    if video_mode {
        video(n);
    } else {
        audio(n);
    }
}
