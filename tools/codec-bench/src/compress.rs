//! akio-brotli and akio-zstd against the C reference libraries (Google's libbrotli through
//! `brotlic-sys`, libzstd through `zstd`), both built from their bundled C sources.
//!
//! `codec-bench brotli|zstd FILE...` prints, per file and level, the compressed sizes and the
//! compression and decompression throughput (MB/s of uncompressed data, best of several rounds)
//! of both. "dec C-stream" decodes the C library's output with both decoders (same input, so the
//! decoders are compared on equal terms); "dec own" decodes each library's own output.
//! `BENCH_LEVELS` picks levels (brotli default 1,4,5,6,11; zstd 1,3,19). `BENCH_MS` is the
//! minimum time per round (default 300). Levels at or above `BENCH_SLOW` (brotli 10, zstd 16)
//! compress once per run. `BENCH_ENC=0` skips the compression timings (for profiling decoders),
//! `BENCH_C=0` the C library's (for a second run against another version of the crates).
//! `BENCH_OWN=0` skips decoding each library's own output.
//! `BENCH_DUMP=DIR` writes the zstd frames there (`FILE.LEVEL.zst` from the C library,
//! `FILE.LEVEL.only.zst` from akio-zstd), for inspecting what the decoders are timed on.
//! `BENCH_BR_LIMIT=N` decodes brotli with an output limit of `N` bytes instead of the exact
//! size (a caller that does not know the size; the C one-shot call needs none).

use std::hint::black_box;
use std::time::Instant;

/// MB/s of `bytes` processed by `f`, best of 3 rounds of at least `min_ms` each (one call when
/// `once`).
fn mbps(bytes: usize, min_ms: u128, once: bool, mut f: impl FnMut()) -> f64 {
    if min_ms == 0 {
        return 0.0;
    }
    if once {
        let t = Instant::now();
        f();
        return bytes as f64 / t.elapsed().as_secs_f64() / 1e6;
    }
    f();
    let mut best = 0f64;
    for _ in 0..3 {
        let t = Instant::now();
        let mut n = 0u64;
        while t.elapsed().as_millis() < min_ms {
            f();
            n += 1;
        }
        best = best.max(bytes as f64 * n as f64 / t.elapsed().as_secs_f64() / 1e6);
    }
    best
}

fn c_brotli_compress(q: u32, data: &[u8]) -> Vec<u8> {
    use brotlic_sys::*;
    // SAFETY: a pure function of its argument.
    let bound = unsafe { BrotliEncoderMaxCompressedSize(data.len()) };
    let mut out = vec![0u8; bound.max(64)];
    let mut n = out.len();
    // SAFETY: the buffers are valid for the sizes given.
    let ok = unsafe {
        BrotliEncoderCompress(
            q as i32,
            22,
            BrotliEncoderMode_BROTLI_MODE_GENERIC,
            data.len(),
            data.as_ptr(),
            &mut n,
            out.as_mut_ptr(),
        )
    };
    assert_eq!(ok, 1);
    out.truncate(n);
    out
}

fn c_brotli_decompress(src: &[u8], out: &mut [u8]) -> usize {
    use brotlic_sys::*;
    let mut n = out.len();
    // SAFETY: the buffers are valid for the sizes given.
    let r = unsafe { BrotliDecoderDecompress(src.len(), src.as_ptr(), &mut n, out.as_mut_ptr()) };
    assert_eq!(r, BrotliDecoderResult_BROTLI_DECODER_RESULT_SUCCESS);
    n
}

fn levels(default: &[u32]) -> Vec<u32> {
    std::env::var("BENCH_LEVELS")
        .ok()
        .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
        .unwrap_or_else(|| default.to_vec())
}

fn env_u(name: &str, default: u128) -> u128 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn header() {
    println!(
        "{:<28} {:>3} {:>10} {:>10} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9}",
        "file",
        "lvl",
        "size akio",
        "size C",
        "enc only",
        "enc C",
        "dec only",
        "dec C",
        "dec own",
        "(akio)"
    );
}

struct Row<'a> {
    name: &'a str,
    level: u32,
    ours: Vec<u8>,
    theirs: Vec<u8>,
    enc: (f64, f64),
    dec: (f64, f64),
    own: f64,
}

fn print(r: &Row<'_>) {
    println!(
        "{:<28} {:>3} {:>10} {:>10} {:>9.1} {:>9.1} {:>9.1} {:>9.1} {:>9.1}",
        r.name,
        r.level,
        r.ours.len(),
        r.theirs.len(),
        r.enc.0,
        r.enc.1,
        r.dec.0,
        r.dec.1,
        r.own,
    );
}

fn load(files: &[String]) -> Vec<(String, Vec<u8>)> {
    files
        .iter()
        .map(|f| {
            let name = std::path::Path::new(f)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| f.clone());
            (name, std::fs::read(f).expect("readable file"))
        })
        .collect()
}

pub fn brotli(files: &[String]) {
    let ms = env_u("BENCH_MS", 300);
    let slow = env_u("BENCH_SLOW", 10) as u32;
    println!("brotli: akio-brotli vs libbrotli (C, brotlic-sys), lgwin 22, MB/s of input");
    header();
    for (name, data) in load(files) {
        let mut out = vec![0u8; data.len()];
        let limit = (env_u("BENCH_BR_LIMIT", 0) as usize).max(data.len());
        for level in levels(&[1, 4, 5, 6, 11]) {
            let once = level >= slow;
            let lv = akio_brotli::Level::new(level);
            let ours = akio_brotli::compress(lv, &data);
            let theirs = c_brotli_compress(level, &data);
            assert_eq!(akio_brotli::decompress(&theirs, data.len()).unwrap(), data);
            assert_eq!(c_brotli_decompress(&ours, &mut out), data.len());
            assert_eq!(out, data);
            let ems = if env_u("BENCH_ENC", 1) == 0 { 0 } else { ms };
            let cms = if env_u("BENCH_C", 1) == 0 { 0 } else { ms };
            let enc = (
                mbps(data.len(), ems, once, || {
                    black_box(akio_brotli::compress(lv, black_box(&data)));
                }),
                mbps(data.len(), ems.min(cms), once, || {
                    black_box(c_brotli_compress(level, black_box(&data)));
                }),
            );
            let dec = (
                mbps(data.len(), ms, false, || {
                    black_box(akio_brotli::decompress(black_box(&theirs), limit).unwrap());
                }),
                mbps(data.len(), cms, false, || {
                    // The C one-shot API writes into a caller buffer: one reused buffer (its best
                    // case; ours allocates its output every time).
                    black_box(c_brotli_decompress(black_box(&theirs), &mut out));
                }),
            );
            let own = mbps(data.len(), ms, false, || {
                black_box(akio_brotli::decompress(black_box(&ours), limit).unwrap());
            });
            print(&Row {
                name: &name,
                level,
                ours,
                theirs,
                enc,
                dec,
                own,
            });
        }
    }
}

pub fn zstd(files: &[String]) {
    let ms = env_u("BENCH_MS", 300);
    let slow = env_u("BENCH_SLOW", 16) as u32;
    println!(
        "zstd: akio-zstd vs libzstd {} (C, zstd crate, one-shot with a reused context), MB/s of input",
        zstd::zstd_safe::version_string()
    );
    header();
    for (name, data) in load(files) {
        for level in levels(&[1, 3, 19]) {
            let once = level >= slow;
            let lv = akio_zstd::Level::new(level);
            let mut cc = zstd::bulk::Compressor::new(level as i32).unwrap();
            // Like ours: content size and checksum in the frame.
            cc.include_checksum(true).unwrap();
            let mut dc = zstd::bulk::Decompressor::new().unwrap();
            let ours = akio_zstd::compress(lv, &data);
            let theirs = cc.compress(&data).unwrap();
            if let Ok(dir) = std::env::var("BENCH_DUMP") {
                std::fs::write(format!("{dir}/{name}.{level}.zst"), &theirs).unwrap();
                std::fs::write(format!("{dir}/{name}.{level}.only.zst"), &ours).unwrap();
            }
            assert_eq!(akio_zstd::decompress(&theirs, data.len()).unwrap(), data);
            assert_eq!(dc.decompress(&ours, data.len()).unwrap(), data);
            let ems = if env_u("BENCH_ENC", 1) == 0 { 0 } else { ms };
            let cms = if env_u("BENCH_C", 1) == 0 { 0 } else { ms };
            let enc = (
                mbps(data.len(), ems, once, || {
                    black_box(akio_zstd::compress(lv, black_box(&data)));
                }),
                mbps(data.len(), ems.min(cms), once, || {
                    black_box(cc.compress(black_box(&data)).unwrap());
                }),
            );
            let dec = (
                mbps(data.len(), ms, false, || {
                    black_box(akio_zstd::decompress(black_box(&theirs), data.len()).unwrap());
                }),
                mbps(data.len(), cms, false, || {
                    black_box(dc.decompress(black_box(&theirs), data.len()).unwrap());
                }),
            );
            let oms = if env_u("BENCH_OWN", 1) == 0 { 0 } else { ms };
            let own = mbps(data.len(), oms, false, || {
                black_box(akio_zstd::decompress(black_box(&ours), data.len()).unwrap());
            });
            print(&Row {
                name: &name,
                level,
                ours,
                theirs,
                enc,
                dec,
                own,
            });
        }
    }
}
