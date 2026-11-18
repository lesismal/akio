//! Compression ratio and throughput per level, against the `brotli` command-line tool when it is
//! installed.
//!
//!     cargo run --release -p only-brotli --example brotli-bench [FILE...]
//!
//! Generated corpora (text, JSON, random) come first, then each file is one more corpus
//! (`BENCH_GENERATED=0` leaves the generated ones out). `BENCH_LEVELS=1,6,11` picks the levels
//! (default 0..=11). For each corpus the zlib level 9 size (only-deflate) is printed as a
//! baseline. With `brotli(1)` on the PATH the table also shows its size at the same quality and
//! the time it takes to decode our stream (`brotli -d -c FILE > /dev/null`, process start-up
//! included, best of several runs).

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use only_brotli::{Level, compress, decompress};

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
        "dictionary",
        "brotli",
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

fn cli_present() -> bool {
    Command::new("brotli")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// The size of `brotli -q Q` output for `data`.
fn cli_size(q: u32, data: &[u8]) -> usize {
    let mut c = Command::new("brotli")
        .args(["-c", "-q", &q.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("brotli");
    let mut stdin = c.stdin.take().expect("stdin");
    let d = data.to_vec();
    let w = std::thread::spawn(move || stdin.write_all(&d).expect("write"));
    let out = c.wait_with_output().expect("brotli output");
    w.join().expect("writer");
    out.stdout.len()
}

/// Best wall time of `brotli -d -c` decoding `z` (written to a temporary file) to /dev/null.
fn cli_decode_time(z: &[u8]) -> Duration {
    let path = std::env::temp_dir().join(format!("only-brotli-bench-{}.br", std::process::id()));
    std::fs::write(&path, z).expect("temp file");
    let mut best = Duration::MAX;
    for _ in 0..5 {
        let start = Instant::now();
        let st = Command::new("brotli")
            .arg("-d")
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::null())
            .status()
            .expect("brotli -d");
        assert!(st.success());
        best = best.min(start.elapsed());
    }
    let _ = std::fs::remove_file(&path);
    best
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut corpora: Vec<(String, Vec<u8>)> = Vec::new();
    if std::env::var("BENCH_GENERATED").as_deref() != Ok("0") {
        corpora.push(("text 4 MB".into(), gen_text(4 << 20)));
        corpora.push(("json 4 MB".into(), gen_json(4 << 20)));
        corpora.push(("random 1 MB".into(), gen_random(1 << 20)));
    }
    for p in &args {
        let data = std::fs::read(p).expect("read file");
        let name = std::path::Path::new(p)
            .file_name()
            .map_or_else(|| p.clone(), |n| n.to_string_lossy().into_owned());
        corpora.push((format!("{name} {} B", data.len()), data));
    }
    let levels: Vec<u32> = std::env::var("BENCH_LEVELS").map_or_else(
        |_| (0..=11).collect(),
        |v| {
            v.split(',')
                .map(|x| x.trim().parse().expect("level"))
                .collect()
        },
    );
    let cli = cli_present();
    if !cli {
        eprintln!("brotli(1) not found: no reference columns");
    }
    println!(
        "| corpus | level | size | ratio | brotli(1) size | compress MB/s | decompress MB/s | brotli -d MB/s |"
    );
    println!("|---|---|---|---|---|---|---|---|");
    for (name, data) in &corpora {
        let zlib =
            only_deflate::compress(only_deflate::Format::Zlib, only_deflate::Level::BEST, data);
        println!(
            "| {name} | zlib 9 | {} | {:.3} | | | | |",
            zlib.len(),
            data.len() as f64 / zlib.len() as f64
        );
        for &level in &levels {
            let z = compress(Level::new(level), data);
            assert!(decompress(&z, data.len()).expect("decodes") == *data);
            let tc = time(|| {
                std::hint::black_box(compress(Level::new(level), data));
            });
            let td = time(|| {
                std::hint::black_box(decompress(&z, data.len()).expect("decodes"));
            });
            let (theirs, cli_mbps) = if cli {
                (
                    cli_size(level, data).to_string(),
                    format!("{:.0}", mbps(data.len(), cli_decode_time(&z))),
                )
            } else {
                (String::new(), String::new())
            };
            println!(
                "| {name} | {level} | {} | {:.3} | {theirs} | {:.1} | {:.0} | {cli_mbps} |",
                z.len(),
                data.len() as f64 / z.len() as f64,
                mbps(data.len(), tc),
                mbps(data.len(), td),
            );
        }
    }
}
