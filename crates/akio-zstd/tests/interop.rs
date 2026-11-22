//! Round trips on varied data, the official zstd test vectors, interop with the `zstd(1)` CLI in
//! both directions, and hostile input (truncation, bit flips, bombs).

use std::io::Write;
use std::process::{Command, Stdio};

use akio_zstd::{Error, Level, compress, decompress, xxh64};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Text-like data: words from a small vocabulary with Zipf-ish frequencies.
fn text(n: usize, seed: u64) -> Vec<u8> {
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
        "has",
        "there",
        "been",
        "if",
        "more",
        "when",
        "will",
        "would",
        "who",
        "so",
        "no",
        "zstandard",
        "window",
        "huffman",
        "entropy",
        "stream",
        "network",
        "library",
    ];
    let mut r = Rng(seed | 1);
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        let x = r.next();
        let i = ((x % 1000) as f64 / 1000.0).powi(3) * WORDS.len() as f64;
        out.extend_from_slice(WORDS[i as usize].as_bytes());
        out.push(if x >> 60 == 0 { b'\n' } else { b' ' });
    }
    out.truncate(n);
    out
}

fn random(n: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng(seed | 1);
    (0..n).map(|_| r.next() as u8).collect()
}

/// Structured binary: little-endian counters and records, like a log or a table dump.
fn binary(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 16);
    let mut i = 0u32;
    while out.len() < n {
        out.extend_from_slice(&i.to_le_bytes());
        out.extend_from_slice(&(i.wrapping_mul(2_654_435_761) >> 20).to_le_bytes());
        out.extend_from_slice(b"\x00\x01rec");
        i += 1;
    }
    out.truncate(n);
    out
}

fn corpora() -> Vec<(&'static str, Vec<u8>)> {
    let mut low = Rng(7);
    vec![
        ("empty", Vec::new()),
        ("one", b"x".to_vec()),
        ("two", b"xy".to_vec()),
        ("short", b"hello hello hello".to_vec()),
        ("same", vec![b'a'; 300_000]),
        ("zeros", vec![0; 70_000]),
        ("text", text(200_000, 1)),
        ("binary", binary(150_000)),
        ("random", random(100_000, 2)),
        (
            "low-entropy",
            (0..120_000).map(|_| (low.next() % 4) as u8).collect(),
        ),
        // Repeats of a 40 KiB block: matches across blocks.
        ("long-period", random(40_000, 3).repeat(5)),
        // Repeats of a 300-byte pattern: very long matches.
        ("period-300", random(300, 4).repeat(1000)),
        ("all-bytes", (0..=255u8).cycle().take(5000).collect()),
    ]
}

fn check(packed: &[u8], data: &[u8], what: &str) {
    let back = decompress(packed, data.len()).unwrap_or_else(|e| panic!("{what}: {e}"));
    assert!(back == data, "{what}: output differs");
    if !data.is_empty() {
        assert_eq!(
            decompress(packed, data.len() - 1),
            Err(Error::TooLarge),
            "{what}: limit one below"
        );
    }
}

#[test]
fn roundtrip_every_level() {
    for (name, data) in corpora() {
        for level in 1..=22 {
            // The slowest levels on the big inputs only in release builds.
            if cfg!(debug_assertions) && level > 12 && data.len() > 100_000 && level % 5 != 0 {
                continue;
            }
            let packed = compress(Level::new(level), &data);
            check(&packed, &data, &format!("{name} level {level}"));
        }
    }
}

#[test]
fn levels_and_ratio() {
    assert_eq!(Level::new(0), Level::FASTEST);
    assert_eq!(Level::new(99), Level::BEST);
    assert_eq!(Level::default(), Level::DEFAULT);
    assert_eq!(Level::DEFAULT.get(), 3);
    let data = text(300_000, 9);
    let mut last = data.len();
    for level in [1, 3, 9, 19] {
        let n = compress(Level::new(level), &data).len();
        assert!(n < data.len() / 2, "level {level}: {n}");
        assert!(
            n <= last + last / 50,
            "level {level} larger than the one below"
        );
        last = n;
    }
    // Incompressible data costs only the framing.
    let r = random(200_000, 5);
    assert!(compress(Level::DEFAULT, &r).len() <= r.len() + 32);
}

fn data_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

fn read(path: &str) -> Vec<u8> {
    std::fs::read(data_dir().join(path)).unwrap()
}

/// facebook/zstd tests/golden-decompression: each must decode (to the length and XXH64 that
/// libzstd gives). block-128k.zst is stored zstd-compressed.
#[test]
fn golden_decompression() {
    let block_128k = decompress(&read("golden-decompression/block-128k.zst.zst"), 1 << 20).unwrap();
    let cases: [(&str, Vec<u8>, usize, u64); 4] = [
        ("block-128k", block_128k, 131_068, 0x2c25_4ff1_9aba_22ea),
        (
            "empty-block",
            read("golden-decompression/empty-block.zst"),
            0,
            0xef46_db37_51d8_e999,
        ),
        (
            "rle-first-block",
            read("golden-decompression/rle-first-block.zst"),
            1_048_576,
            0x87d2_a1b6_e116_3ef1,
        ),
        (
            "zeroSeq_2B",
            read("golden-decompression/zeroSeq_2B.zst"),
            13,
            0x2de0_458b_04f9_6095,
        ),
    ];
    for (name, frame, len, hash) in cases {
        let out = decompress(&frame, 1 << 21).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!((out.len(), xxh64(&out, 0)), (len, hash), "{name}");
    }
}

/// facebook/zstd tests/golden-decompression-errors: each must be rejected.
#[test]
fn golden_decompression_errors() {
    for (name, want) in [
        ("off0.bin.zst", Error::BadOffset),
        ("truncated_huff_state.zst", Error::BadHuffmanTable),
        ("zeroSeq_extraneous.zst", Error::BadSequences),
    ] {
        let frame = read(&format!("golden-decompression-errors/{name}"));
        assert_eq!(decompress(&frame, 1 << 20), Err(want), "{name}");
    }
}

/// facebook/zstd tests/golden-compression: inputs that once broke libzstd's compressor; ours
/// must round-trip them at every level (large-literal-and-match-lengths is stored compressed).
#[test]
fn golden_compression() {
    let big = decompress(
        &read("golden-compression/large-literal-and-match-lengths.zst"),
        1 << 20,
    )
    .unwrap();
    assert_eq!(
        (big.len(), xxh64(&big, 0)),
        (199_998, 0x3662_044b_041f_c004)
    );
    let inputs = [
        (
            "http",
            read("golden-compression/http"),
            0xc970_6315_8070_530f,
        ),
        (
            "huffman-compressed-larger",
            read("golden-compression/huffman-compressed-larger"),
            0x28d2_14e4_ef81_b8ec,
        ),
        (
            "large-literal-and-match-lengths",
            big,
            0x3662_044b_041f_c004,
        ),
    ];
    for (name, data, hash) in inputs {
        assert_eq!(xxh64(&data, 0), hash, "{name}");
        for level in 1..=22 {
            let packed = compress(Level::new(level), &data);
            check(&packed, &data, &format!("{name} level {level}"));
            if let Some(out) = zstd_cli(&["-d", "-c"], &packed) {
                assert!(out == data, "{name} level {level}: zstd -d differs");
            }
        }
    }
}

/// Runs `zstd ARGS` with `input` on stdin; `None` when zstd(1) is not installed.
fn zstd_cli(args: &[&str], input: &[u8]) -> Option<Vec<u8>> {
    let mut c = Command::new("zstd")
        .args(["-q"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let mut stdin = c.stdin.take().unwrap();
    let data = input.to_vec();
    let w = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let out = c.wait_with_output().unwrap();
    w.join().unwrap();
    assert!(
        out.status.success(),
        "zstd {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(out.stdout)
}

fn have_zstd() -> bool {
    match Command::new("zstd").arg("--version").output() {
        Ok(o) if o.status.success() => true,
        _ => {
            eprintln!("zstd(1) not found; skipped");
            false
        }
    }
}

/// zstd(1) compresses with many settings, we decompress.
#[test]
fn system_zstd_compresses() {
    if !have_zstd() {
        return;
    }
    let mut data = text(400_000, 61);
    data.extend_from_slice(&binary(100_000));
    data.extend_from_slice(&random(30_000, 8));
    data.extend_from_within(1000..90_000);
    let mut settings: Vec<Vec<String>> = (1..=19).map(|l| vec![format!("-{l}")]).collect();
    for extra in [
        "--ultra -22",
        "--ultra -20 --long=27",
        "-19 --long",
        "-3 --no-check",
        "-5 --zstd=wlog=10",
        "-12 --zstd=wlog=12,strat=2",
        "-1 --target-compressed-block-size=1340",
        "-19 --target-compressed-block-size=2000",
        "--fast=5",
        "-7 --no-content-size",
        "-15 --zstd=strat=9,mml=3",
        "-3 --rsyncable",
    ] {
        settings.push(extra.split(' ').map(String::from).collect());
    }
    for s in &settings {
        let mut args: Vec<&str> = s.iter().map(String::as_str).collect();
        args.push("-c");
        let packed = zstd_cli(&args, &data).unwrap();
        let back = decompress(&packed, data.len()).unwrap_or_else(|e| panic!("{s:?}: {e}"));
        assert!(back == data, "{s:?}: output differs");
    }
    // Several frames, skippable frames between them, streamed without a content size.
    let a = zstd_cli(&["-c", "-3"], &data[..100_000]).unwrap();
    let b = zstd_cli(&["-c", "-19", "--no-content-size"], &data[100_000..]).unwrap();
    let mut both = a;
    both.extend_from_slice(&[0x5A, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 1, 2, 3]);
    both.extend_from_slice(&b);
    both.extend_from_slice(&[0x50, 0x2A, 0x4D, 0x18, 0, 0, 0, 0]);
    assert!(decompress(&both, data.len()).unwrap() == data);
}

/// We compress at every level; zstd(1) decompresses and tests.
#[test]
fn system_zstd_decompresses() {
    if !have_zstd() {
        return;
    }
    let mut data = text(250_000, 71);
    data.extend_from_slice(&binary(50_000));
    data.extend_from_slice(&random(5_000, 9));
    data.extend_from_slice(&vec![7u8; 140_000]);
    for (name, input) in corpora().into_iter().chain([("mixed", data)]) {
        for level in 1..=22 {
            if cfg!(debug_assertions) && level > 12 && input.len() > 100_000 && level % 5 != 0 {
                continue;
            }
            let packed = compress(Level::new(level), &input);
            let out = zstd_cli(&["-d", "-c"], &packed).unwrap();
            assert!(out == input, "{name} level {level}: zstd -d differs");
            zstd_cli(&["-t"], &packed).unwrap();
        }
    }
}

/// Builds a frame by hand: single segment with the given content size, blocks as given.
fn frame(content_size: Option<u64>, checksum: bool, blocks: &[(u32, &[u8], u32)]) -> Vec<u8> {
    let mut f = 0xFD2F_B528u32.to_le_bytes().to_vec();
    match content_size {
        Some(n) => {
            f.push(0x20 | 3 << 6 | u8::from(checksum) << 2);
            f.extend_from_slice(&n.to_le_bytes());
        }
        None => {
            f.push(u8::from(checksum) << 2);
            f.push(17 << 3); // 128 MiB window
        }
    }
    for (i, &(kind, body, size)) in blocks.iter().enumerate() {
        let last = u32::from(i + 1 == blocks.len());
        let v = size << 3 | kind << 1 | last;
        f.extend_from_slice(&v.to_le_bytes()[..3]);
        f.extend_from_slice(body);
    }
    f
}

#[test]
fn decompression_bombs_are_refused_quickly() {
    // 10 000 RLE blocks of 128 KiB: 1.3 GB from 40 KB, no content size.
    let blocks: Vec<(u32, &[u8], u32)> = (0..10_000).map(|_| (1, &b"A"[..], 128 << 10)).collect();
    let bomb = frame(None, false, &blocks);
    let t = std::time::Instant::now();
    assert_eq!(decompress(&bomb, 1 << 20), Err(Error::TooLarge));
    // A tiny frame announcing a terabyte.
    let liar = frame(Some(1 << 40), false, &[(1, b"A", 1000)]);
    assert_eq!(decompress(&liar, 1 << 24), Err(Error::TooLarge));
    assert!(t.elapsed() < std::time::Duration::from_secs(2));
    // Our own output of a big run: tiny, refused at the limit, exact at its size.
    let zeros = vec![0u8; 50 << 20];
    let z = compress(Level::DEFAULT, &zeros);
    assert!(z.len() < 3_000, "{}", z.len());
    assert_eq!(decompress(&z, 1 << 20), Err(Error::TooLarge));
    assert_eq!(decompress(&z, zeros.len()).unwrap().len(), zeros.len());
}

#[test]
fn truncation_and_bit_flips() {
    let data = text(20_000, 41);
    for level in [1, 3, 19] {
        let z = compress(Level::new(level), &data);
        for cut in 0..z.len() {
            let r = decompress(&z[..cut], 1 << 20);
            if cut == 0 {
                assert_eq!(r, Ok(Vec::new()));
            } else {
                assert!(r.is_err(), "level {level} cut {cut}");
            }
        }
        // Every bit flip fails or (by checksum) gives the data back; it never panics.
        for i in 0..z.len() {
            for bit in [0x01, 0x10, 0x80] {
                let mut bad = z.clone();
                bad[i] ^= bit;
                let r = decompress(&bad, 1 << 20);
                assert!(
                    r.is_err() || r.as_deref() == Ok(&data[..]),
                    "level {level} byte {i}"
                );
            }
        }
    }
    // Without the checksum flag corrupt data may decode differently, but never panics.
    let mut z = compress(Level::DEFAULT, &data);
    z[4] &= !0x04;
    z.truncate(z.len() - 4);
    assert_eq!(decompress(&z, 1 << 20).unwrap(), data);
    for i in 5..z.len() {
        let mut bad = z.clone();
        bad[i] ^= 0x08;
        let _ = decompress(&bad, 1 << 20);
    }
}

#[test]
fn frame_level_errors() {
    let good = compress(Level::DEFAULT, b"hello hello hello hello");
    assert_eq!(decompress(&[], 10), Ok(Vec::new()));
    assert_eq!(decompress(b"\x28\xb5\x2f\xfd", 10), Err(Error::Truncated));
    assert_eq!(decompress(b"hello world", 10), Err(Error::BadMagic));
    // Trailing bytes after a frame.
    let mut t = good.clone();
    t.extend_from_slice(&[0, 0]);
    assert_eq!(decompress(&t, 100), Err(Error::Truncated));
    let mut t = good.clone();
    t.extend_from_slice(b"garbage");
    assert_eq!(decompress(&t, 100), Err(Error::BadMagic));
    // Reserved bit.
    let mut t = good.clone();
    t[4] |= 0x08;
    assert_eq!(decompress(&t, 100), Err(Error::BadFrameHeader));
    // Dictionary ID.
    let mut d = 0xFD2F_B528u32.to_le_bytes().to_vec();
    d.extend_from_slice(&[0x01, 0x00, 0x07, 1, 0, 0]);
    assert_eq!(decompress(&d, 100), Err(Error::DictionaryRequired));
    // Window_Log 10 + 22 = 32.
    let mut w = 0xFD2F_B528u32.to_le_bytes().to_vec();
    w.extend_from_slice(&[0x00, 22 << 3, 1, 0, 0]);
    assert_eq!(decompress(&w, 100), Err(Error::WindowTooLarge));
    w[5] = 21 << 3 | 7;
    assert_eq!(decompress(&w, 100), Ok(Vec::new()));
    // Reserved block type; raw block larger than the window; content size mismatch.
    assert_eq!(
        decompress(&frame(None, false, &[(3, b"", 0)]), 100),
        Err(Error::BadBlock)
    );
    let mut small = 0xFD2F_B528u32.to_le_bytes().to_vec();
    small.extend_from_slice(&[0x20, 3, 1 | 4 << 3, 0, 0, b'a', b'b', b'c', b'd']);
    assert_eq!(decompress(&small, 100), Err(Error::BadBlock));
    assert_eq!(
        decompress(&frame(Some(5), false, &[(0, b"abcd", 4)]), 100),
        Err(Error::ContentSizeMismatch)
    );
    // Checksum.
    let mut c = good.clone();
    let n = c.len();
    c[n - 1] ^= 1;
    assert_eq!(decompress(&c, 100), Err(Error::ChecksumMismatch));
    // Skippable frames only, and around a frame.
    let skip = [0x5F, 0x2A, 0x4D, 0x18, 2, 0, 0, 0, 9, 9];
    assert_eq!(decompress(&skip, 0), Ok(Vec::new()));
    assert_eq!(decompress(&skip[..9], 0), Err(Error::Truncated));
    let mut s = skip.to_vec();
    s.extend_from_slice(&good);
    s.extend_from_slice(&skip);
    s.extend_from_slice(&good);
    assert_eq!(
        decompress(&s, 100).unwrap(),
        b"hello hello hello hello".repeat(2)
    );
    // A match may not reach into the previous frame: frame 2 is "repeat 5 bytes back".
    let mut two = frame(Some(5), false, &[(0, b"abcde", 5)]);
    // Compressed block: raw literals (0), 1 sequence, predefined tables, a bit stream for
    // LL 0, OF code 2 (offset 5 - 3 = 2 + extra), ML 5... built by our encoder instead:
    two.extend_from_slice(&compress(Level::DEFAULT, b"abcdeabcde"));
    assert_eq!(decompress(&two, 100).unwrap(), b"abcdeabcdeabcde");
}

#[test]
fn many_frames_and_empty_blocks_are_linear() {
    let one = frame(Some(0), false, &[(0, b"", 0)]);
    let many = one.repeat(100_000);
    let t = std::time::Instant::now();
    assert_eq!(decompress(&many, 10), Ok(Vec::new()));
    let empties: Vec<(u32, &[u8], u32)> = (0..100_000).map(|_| (0, &b""[..], 0)).collect();
    assert_eq!(
        decompress(&frame(None, false, &empties), 10),
        Ok(Vec::new())
    );
    assert!(t.elapsed() < std::time::Duration::from_secs(2));
}
