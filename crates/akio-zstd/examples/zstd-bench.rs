//! Compression ratio and throughput of akio-zstd, against zlib level 9 (akio-deflate) for the
//! ratio and against libzstd (`zstd -b`, when the CLI is installed) for ratio and speed.
//!
//!     cargo run --release -p akio-zstd --example zstd-bench [FILE...]
//!
//! Corpora: TLS 1.3 Certificate messages built from the certificate chains in
//! `fuzz/corpus/x509_parse` (what RFC 8879 compresses), generated text, JSON and random data,
//! then each file given. `BENCH_GENERATED=0` leaves the generated ones out; `BENCH_LEVELS=1,3,19`
//! picks the levels (default 1, 3, 9, 19, 22).

use std::io::Write;
use std::time::{Duration, Instant};

use akio_zstd::{Level, compress, decompress};

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
        "zstandard",
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

/// A TLS 1.3 Certificate message body (RFC 8446 section 4.4.2) carrying `certs`.
fn certificate_message(certs: &[Vec<u8>]) -> Vec<u8> {
    let mut list = Vec::new();
    for c in certs {
        list.extend_from_slice(&(c.len() as u32).to_be_bytes()[1..]);
        list.extend_from_slice(c);
        list.extend_from_slice(&[0, 0]); // no extensions
    }
    let mut m = vec![0]; // empty certificate_request_context
    m.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
    m.extend_from_slice(&list);
    m
}

fn cert_chains() -> Vec<(String, Vec<u8>)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/x509_parse");
    let mut out = Vec::new();
    for site in [
        "www_google_com",
        "www_cloudflare_com",
        "www_rust-lang_org",
        "letsencrypt_org",
    ] {
        let certs: Vec<Vec<u8>> = (0..4)
            .map_while(|i| std::fs::read(dir.join(format!("{site}_pem_{i}.der"))).ok())
            .collect();
        if !certs.is_empty() {
            out.push((
                format!("certs {site} ({})", certs.len()),
                certificate_message(&certs),
            ));
        }
    }
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

/// libzstd's frame of `data` (`zstd -c LEVEL`), when the CLI is installed.
fn libzstd_frame(level: u32, data: &[u8]) -> Option<Vec<u8>> {
    let mut c = std::process::Command::new("zstd")
        .args(["-q", "-c", "--ultra", &format!("-{level}")])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let mut stdin = c.stdin.take()?;
    let d = data.to_vec();
    let w = std::thread::spawn(move || stdin.write_all(&d));
    let out = c.wait_with_output().ok()?;
    w.join().ok()?.ok()?;
    out.status.success().then_some(out.stdout)
}

/// `zstd -b LEVEL` on `data`: ratio, compression and decompression MB/s of libzstd.
fn libzstd_bench(level: u32, data: &[u8]) -> Option<(f64, f64, f64)> {
    let path = std::env::temp_dir().join(format!("akio-zstd-bench-{}", std::process::id()));
    std::fs::write(&path, data).ok()?;
    let mut cmd = std::process::Command::new("zstd");
    cmd.arg("-q").arg(format!("-b{level}")).arg("-i1");
    if level > 19 {
        cmd.arg("--ultra");
    }
    let out = cmd.arg(&path).output().ok();
    let _ = std::fs::remove_file(&path);
    let out = out?;
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    // "-3   508 (3.937) 122.08 MB/s  278.9 MB/s  file"
    let line = text.lines().rev().find(|l| l.contains("MB/s"))?;
    let f: Vec<&str> = line.split_whitespace().collect();
    let ratio = f
        .get(2)?
        .trim_matches(|c| c == '(' || c == ')')
        .parse()
        .ok()?;
    Some((ratio, f.get(3)?.parse().ok()?, f.get(5)?.parse().ok()?))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut corpora: Vec<(String, Vec<u8>)> = cert_chains();
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
        corpora.push((format!("{name} {:.1} MB", data.len() as f64 / 1e6), data));
    }
    let levels: Vec<u32> = std::env::var("BENCH_LEVELS").map_or_else(
        |_| vec![1, 3, 9, 19, 22],
        |v| {
            v.split(',')
                .map(|x| x.trim().parse().expect("level"))
                .collect()
        },
    );
    println!(
        "| corpus | bytes | level | ratio | ratio zlib-9 | ratio libzstd | compress MB/s | compress MB/s libzstd | decompress MB/s | decompress MB/s, libzstd's frame | decompress MB/s libzstd |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|---|");
    for (name, data) in &corpora {
        let zlib9 =
            akio_deflate::compress(akio_deflate::Format::Zlib, akio_deflate::Level::BEST, data);
        for &level in &levels {
            let packed = compress(Level::new(level), data);
            assert_eq!(decompress(&packed, data.len()).expect("decodes"), *data);
            let tc = time(|| {
                std::hint::black_box(compress(Level::new(level), data));
            });
            let td = time(|| {
                std::hint::black_box(decompress(&packed, data.len()).expect("decodes"));
            });
            let lib = libzstd_bench(level, data);
            let td_lib = libzstd_frame(level, data).map(|f| {
                assert_eq!(
                    decompress(&f, data.len()).expect("decodes libzstd's frame"),
                    *data
                );
                mbps(
                    data.len(),
                    time(|| {
                        std::hint::black_box(decompress(&f, data.len()).expect("decodes"));
                    }),
                )
            });
            let show = |v: Option<f64>, prec: usize| {
                v.map_or_else(|| "-".into(), |v| format!("{v:.prec$}"))
            };
            println!(
                "| {name} | {} | {level} | {:.3} | {:.3} | {} | {:.1} | {} | {:.0} | {} | {} |",
                data.len(),
                data.len() as f64 / packed.len() as f64,
                data.len() as f64 / zlib9.len() as f64,
                show(lib.map(|l| l.0), 3),
                mbps(data.len(), tc),
                show(lib.map(|l| l.1), 1),
                mbps(data.len(), td),
                show(td_lib, 0),
                show(lib.map(|l| l.2), 0),
            );
        }
    }
}
