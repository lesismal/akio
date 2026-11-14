//! permessage-deflate echo cost per message: client deflate -> server inflate -> server deflate
//! -> client inflate, with context takeover, for only-deflate and for flate2 (zlib-rs) driven
//! the way only-ws drove it before.
//!
//!     cargo run --release -p only-deflate --example pmd_echo

use std::time::{Duration, Instant};

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use only_deflate::{Deflater, Flush, Format, Inflater, Level};

const TAIL: [u8; 4] = [0, 0, 0xff, 0xff];

trait Pmd {
    fn deflate(&mut self, m: &[u8]) -> Vec<u8>;
    fn inflate(&mut self, m: &[u8]) -> Vec<u8>;
}

struct Ours(Deflater, Inflater);

impl Pmd for Ours {
    fn deflate(&mut self, m: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(m.len() / 2 + 64);
        self.0.compress(m, &mut out, Flush::Sync);
        out.truncate(out.len() - 4);
        out
    }
    fn inflate(&mut self, m: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(m.len() * 3);
        self.1.decompress_vec(m, &mut out, usize::MAX).unwrap();
        self.1.decompress_vec(&TAIL, &mut out, usize::MAX).unwrap();
        out
    }
}

struct Zlib(Compress, Decompress);

impl Pmd for Zlib {
    fn deflate(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(data.len() / 2 + 64);
        let mut consumed = 0;
        loop {
            if out.len() == out.capacity() {
                out.reserve(out.len().max(256));
            }
            let in0 = self.0.total_in();
            let _ = self
                .0
                .compress_vec(&data[consumed..], &mut out, FlushCompress::Sync);
            consumed += (self.0.total_in() - in0) as usize;
            if consumed >= data.len() && out.len() < out.capacity() {
                break;
            }
        }
        out.truncate(out.len() - 4);
        out
    }
    fn inflate(&mut self, data: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(data.len() + 4);
        input.extend_from_slice(data);
        input.extend_from_slice(&TAIL);
        let mut out: Vec<u8> = Vec::with_capacity((data.len() * 3).max(256));
        let mut consumed = 0;
        loop {
            if out.len() == out.capacity() {
                out.reserve(out.len().max(4096));
            }
            let in0 = self.1.total_in();
            let st = self
                .1
                .decompress_vec(&input[consumed..], &mut out, FlushDecompress::Sync)
                .unwrap();
            consumed += (self.1.total_in() - in0) as usize;
            if st == Status::StreamEnd || (consumed >= input.len() && out.len() < out.capacity()) {
                break;
            }
        }
        out
    }
}

fn messages(size: usize) -> Vec<Vec<u8>> {
    (0..64u32)
        .map(|k| {
            let mut m = Vec::with_capacity(size + 64);
            let mut i = k * 1000;
            while m.len() < size {
                m.extend_from_slice(
                    format!(
                        "{{\"seq\":{i},\"user\":\"u{}\",\"op\":\"update\",\"v\":{}}}",
                        i % 97,
                        i * 31 % 1000
                    )
                    .as_bytes(),
                );
                i += 1;
            }
            m.truncate(size);
            m
        })
        .collect()
}

fn run<P: Pmd>(client: &mut P, server: &mut P, msgs: &[Vec<u8>]) -> (f64, usize) {
    let start = Instant::now();
    let mut n = 0usize;
    let mut wire = 0usize;
    while start.elapsed() < Duration::from_millis(700) {
        for m in msgs {
            let c = client.deflate(m);
            wire += c.len();
            let s = server.inflate(&c);
            let r = server.deflate(&s);
            let back = client.inflate(&r);
            assert!(back.len() == m.len());
            n += 1;
        }
    }
    (n as f64 / start.elapsed().as_secs_f64(), wire / n)
}

fn main() {
    if let Ok(size) = std::env::var("PMD_PROFILE") {
        // Profiling aid: only-deflate alone, one message size, for a while.
        let msgs = messages(size.parse().expect("size"));
        let new = || {
            Ours(
                Deflater::new(Format::Raw, Level::DEFAULT),
                Inflater::new(Format::Raw),
            )
        };
        let (mut c, mut s) = (new(), new());
        for _ in 0..10 {
            println!("{:.0}", run(&mut c, &mut s, &msgs).0);
        }
        return;
    }
    println!(
        "| message | only-deflate echoes/s | zlib-rs echoes/s | ratio | wire bytes (only / zlib-rs) |"
    );
    println!("|---|---|---|---|---|");
    for size in [64usize, 512, 4096, 65_536] {
        let msgs = messages(size);
        let ours = || {
            Ours(
                Deflater::new(Format::Raw, Level::DEFAULT),
                Inflater::new(Format::Raw),
            )
        };
        let zlib = || {
            Zlib(
                Compress::new(Compression::default(), false),
                Decompress::new(false),
            )
        };
        let (a, wa) = run(&mut ours(), &mut ours(), &msgs);
        let (b, wb) = run(&mut zlib(), &mut zlib(), &msgs);
        println!(
            "| {size} B | {a:.0} | {b:.0} | {:.2} | {wa} / {wb} |",
            a / b
        );
    }
}
