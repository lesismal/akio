//! Compression ratio and throughput against flate2 (zlib-rs) at the same levels.
//!
//!     cargo run --release -p only-deflate --example bench [FILE...]
//!
//! Without files it uses generated corpora; with files, each file is one corpus.

use std::io::Write;
use std::time::{Duration, Instant};

use only_deflate::{Format, Level, compress, decompress};

fn gen_text(n: usize) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "the",
        "of",
        "and",
        "to",
        "in",
        "a",
        "is",
        "that",
        "for",
        "it",
        "as",
        "was",
        "with",
        "be",
        "by",
        "on",
        "not",
        "he",
        "this",
        "are",
        "or",
        "his",
        "from",
        "at",
        "which",
        "but",
        "have",
        "an",
        "had",
        "they",
        "you",
        "were",
        "their",
        "one",
        "all",
        "we",
        "can",
        "her",
        "compression",
        "window",
        "huffman",
        "deflate",
        "stream",
        "network",
        "library",
    ];
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let i = ((x % 1000) as f64 / 1000.0).powi(3) * WORDS.len() as f64;
        out.extend_from_slice(WORDS[i as usize].as_bytes());
        out.push(if x >> 60 == 0 { b'\n' } else { b' ' });
    }
    out.truncate(n);
    out
}

fn gen_random(n: usize) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn gen_json(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 200);
    let mut i = 0u64;
    while out.len() < n {
        let _ = writeln!(
            out,
            "{{\"id\":{i},\"name\":\"user{}\",\"active\":{},\"score\":{}.{},\"tags\":[\"a\",\"b{}\"]}},",
            i * 7919 % 10007,
            i % 3 == 0,
            i * 31 % 1000,
            i % 10,
            i % 17
        );
        i += 1;
    }
    out.truncate(n);
    out
}

fn time<F: FnMut()>(mut f: F) -> Duration {
    // Best of several rounds of at least 200 ms.
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let start = Instant::now();
        let mut n = 0u32;
        while start.elapsed() < Duration::from_millis(200) || n == 0 {
            f();
            n += 1;
        }
        best = best.min(start.elapsed() / n);
    }
    best
}

fn mbps(bytes: usize, d: Duration) -> f64 {
    bytes as f64 / d.as_secs_f64() / 1e6
}

fn flate2_raw(level: u32, data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::DeflateEncoder::new(
        Vec::with_capacity(data.len() / 2),
        flate2::Compression::new(level),
    );
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn flate2_inflate(data: &[u8], n: usize) -> Vec<u8> {
    let mut d = flate2::Decompress::new(false);
    let mut out = Vec::with_capacity(n + 16);
    d.decompress_vec(data, &mut out, flate2::FlushDecompress::Finish)
        .unwrap();
    out
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let corpora: Vec<(String, Vec<u8>)> = if args.is_empty() {
        vec![
            ("text 4 MB".into(), gen_text(4 << 20)),
            ("json 4 MB".into(), gen_json(4 << 20)),
            ("random 1 MB".into(), gen_random(1 << 20)),
        ]
    } else {
        args.iter()
            .map(|p| (p.clone(), std::fs::read(p).expect("read file")))
            .collect()
    };
    println!(
        "| corpus | level | ratio only | ratio zlib-rs | deflate MB/s only | deflate MB/s zlib-rs | inflate MB/s only | inflate MB/s zlib-rs |"
    );
    println!("|---|---|---|---|---|---|---|---|");
    for (name, data) in &corpora {
        for level in [1u32, 6, 9] {
            let ours = compress(Format::Raw, Level::new(level), data);
            let theirs = flate2_raw(level, data);
            assert_eq!(flate2_inflate(&ours, data.len()), *data);
            let tc_ours = time(|| {
                std::hint::black_box(compress(Format::Raw, Level::new(level), data));
            });
            let tc_theirs = time(|| {
                std::hint::black_box(flate2_raw(level, data));
            });
            let td_ours = time(|| {
                std::hint::black_box(decompress(Format::Raw, &theirs, data.len()).unwrap());
            });
            let td_theirs = time(|| {
                std::hint::black_box(flate2_inflate(&theirs, data.len()));
            });
            println!(
                "| {name} | {level} | {:.3} | {:.3} | {:.0} | {:.0} | {:.0} | {:.0} |",
                data.len() as f64 / ours.len() as f64,
                data.len() as f64 / theirs.len() as f64,
                mbps(data.len(), tc_ours),
                mbps(data.len(), tc_theirs),
                mbps(data.len(), td_ours),
                mbps(data.len(), td_theirs),
            );
        }
    }
}
