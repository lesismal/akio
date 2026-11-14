//! Round trips on varied data, and interop with zlib-rs (through flate2) and `gzip(1)` in both
//! directions.

use std::io::{Read, Write};

use only_deflate::{
    Deflater, Error, Flush, Format, Inflater, Level, adler32, compress, crc32, decompress,
};

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
        "compression",
        "window",
        "huffman",
        "deflate",
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
        // Repeats of a 40 KiB block: matches at distances beyond any small window.
        ("long-period", random(40_000, 3).repeat(4)),
        // Repeats of a 300-byte pattern: very long matches.
        ("period-300", random(300, 4).repeat(1000)),
    ]
}

fn flate2_compress(format: Format, level: u32, data: &[u8]) -> Vec<u8> {
    let lvl = flate2::Compression::new(level);
    match format {
        Format::Raw => {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), lvl);
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        Format::Zlib => {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), lvl);
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        Format::Gzip => {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), lvl);
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
    }
}

fn flate2_decompress(format: Format, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    match format {
        Format::Raw => flate2::read::DeflateDecoder::new(data).read_to_end(&mut out),
        Format::Zlib => flate2::read::ZlibDecoder::new(data).read_to_end(&mut out),
        Format::Gzip => flate2::read::GzDecoder::new(data).read_to_end(&mut out),
    }
    .unwrap();
    out
}

const FORMATS: [Format; 3] = [Format::Raw, Format::Zlib, Format::Gzip];

#[test]
fn roundtrip_all_levels_and_formats_both_ways_with_zlib_rs() {
    for (name, data) in corpora() {
        for level in 0..=9 {
            for format in FORMATS {
                let ours = compress(format, Level::new(level), &data);
                assert_eq!(
                    decompress(format, &ours, data.len()).unwrap(),
                    data,
                    "{name} level {level} {format:?}"
                );
                assert_eq!(
                    flate2_decompress(format, &ours),
                    data,
                    "zlib-rs decodes ours: {name} level {level} {format:?}"
                );
                let theirs = flate2_compress(format, level, &data);
                assert_eq!(
                    decompress(format, &theirs, data.len()).unwrap(),
                    data,
                    "ours decodes zlib-rs: {name} level {level} {format:?}"
                );
            }
        }
    }
}

#[test]
fn ratio_close_to_zlib() {
    // Within a few percent of zlib-rs at the same level on compressible data.
    for (name, data) in corpora() {
        if data.len() < 50_000 || name == "random" {
            continue;
        }
        for level in [1, 6, 9] {
            let ours = compress(Format::Raw, Level::new(level), &data).len() as f64;
            let theirs = flate2_compress(Format::Raw, level, &data).len() as f64;
            assert!(
                ours <= theirs * 1.10 + 64.0,
                "{name} level {level}: {ours} vs zlib-rs {theirs}"
            );
        }
    }
    // Incompressible data barely grows (stored blocks).
    let r = random(100_000, 9);
    for level in 0..=9 {
        let n = compress(Format::Raw, Level::new(level), &r).len();
        assert!(n <= r.len() + r.len() / 100 + 16, "level {level}: {n}");
    }
}

#[test]
fn any_input_split_and_output_size() {
    let data = text(30_000, 5);
    for format in FORMATS {
        for packed in [
            compress(format, Level::DEFAULT, &data),
            flate2_compress(format, 6, &data),
            compress(format, Level::NONE, &data),
        ] {
            for (in_step, out_step) in [(1, 1), (1, 7), (3, 1000), (17, 1), (4096, 3), (1, 65_536)]
            {
                let mut inf = Inflater::new(format);
                let mut out = Vec::new();
                let mut buf = vec![0u8; out_step];
                let mut pos = 0;
                loop {
                    let end = (pos + in_step).min(packed.len());
                    let p = inf.decompress(&packed[pos..end], &mut buf).unwrap();
                    out.extend_from_slice(&buf[..p.produced]);
                    pos += p.consumed;
                    if p.done {
                        break;
                    }
                    assert!(pos < packed.len() || p.produced > 0, "stuck");
                }
                assert_eq!(out, data, "{format:?} in {in_step} out {out_step}");
                assert_eq!(pos, packed.len(), "consumed exactly the stream");
                assert_eq!(inf.total_out(), data.len() as u64);
            }
        }
    }
}

#[test]
fn trailing_data_is_given_back() {
    for format in FORMATS {
        let mut z = compress(format, Level::DEFAULT, b"payload payload payload");
        let n = z.len();
        z.extend_from_slice(b"NEXT");
        let mut inf = Inflater::new(format);
        let mut out = [0u8; 100];
        let p = inf.decompress(&z, &mut out).unwrap();
        assert!(p.done);
        assert_eq!(p.consumed, n, "{format:?}");
        assert_eq!(&out[..p.produced], b"payload payload payload");
    }
}

/// Streams with many sync flushes at awkward places (the miniz_oxide bug Autobahn found lost
/// bytes at a sync flush with context takeover).
#[test]
fn sync_flush_boundaries_with_context_takeover() {
    let mut rng = Rng(11);
    let data = text(400_000, 12);
    for level in [1, 3, 6, 9] {
        for bits in [8u8, 9, 10, 12, 15] {
            let mut d = Deflater::with_window_bits(Format::Raw, Level::new(level), bits);
            let mut ours_inf = Inflater::with_window_bits(Format::Raw, bits.max(9));
            let mut z = flate2::Decompress::new(false);
            let mut pos = 0;
            let mut msg = 0;
            while pos < data.len() {
                let len = match rng.next() % 6 {
                    0 => 0,
                    1 => 1 + (rng.next() % 5) as usize,
                    2 => 32_768 + (rng.next() % 600) as usize - 300,
                    3 => 65_536,
                    _ => (rng.next() % 9000) as usize,
                }
                .min(data.len() - pos);
                let m = &data[pos..pos + len];
                pos += len;
                let mut wire = Vec::new();
                d.compress(m, &mut wire, Flush::Sync);
                assert!(wire.ends_with(&[0, 0, 0xff, 0xff]), "sync marker");
                // Ours, in one go and with the zlib-rs decoder in a running stream.
                let mut back = Vec::new();
                ours_inf
                    .decompress_vec(&wire, &mut back, usize::MAX)
                    .unwrap();
                assert!(back == m, "level {level} bits {bits} message {msg}");
                let mut zb = Vec::with_capacity(len + 64);
                let in0 = z.total_in();
                loop {
                    let off = (z.total_in() - in0) as usize;
                    zb.reserve(4096);
                    z.decompress_vec(&wire[off..], &mut zb, flate2::FlushDecompress::Sync)
                        .unwrap();
                    if (z.total_in() - in0) as usize == wire.len() && zb.len() < zb.capacity() {
                        break;
                    }
                }
                assert!(zb == m, "zlib-rs: level {level} bits {bits} message {msg}");
                msg += 1;
            }
        }
    }
}

#[test]
fn full_flush_and_reset_forget_history() {
    let data = text(20_000, 21);
    let mut d = Deflater::new(Format::Raw, Level::DEFAULT);
    let mut first = Vec::new();
    d.compress(&data, &mut first, Flush::Full);
    let mut second = Vec::new();
    d.compress(&data, &mut second, Flush::Finish);
    // After a full flush the second part decodes on its own.
    assert_eq!(decompress(Format::Raw, &second, data.len()).unwrap(), data);
    // With a sync flush instead it refers back and is much smaller.
    let mut d = Deflater::new(Format::Raw, Level::DEFAULT);
    let mut a = Vec::new();
    d.compress(&data, &mut a, Flush::Sync);
    let mut b = Vec::new();
    d.compress(&data, &mut b, Flush::Sync);
    assert!(
        b.len() * 5 < second.len(),
        "{} vs {}",
        b.len(),
        second.len()
    );
    // Reset: a fresh, independent stream.
    d.reset();
    let mut c = Vec::new();
    d.compress(&data, &mut c, Flush::Finish);
    assert_eq!(decompress(Format::Raw, &c, data.len()).unwrap(), data);
}

#[test]
fn window_bits_limit_distances() {
    // Data that repeats with period 300: a window of 2^8 cannot use those matches.
    let data = random(300, 31).repeat(200);
    for bits in 8u8..=15 {
        let mut d = Deflater::with_window_bits(Format::Raw, Level::BEST, bits);
        let mut out = Vec::new();
        d.compress(&data, &mut out, Flush::Finish);
        // A decoder with a window of exactly 2^bits accepts it.
        let mut inf = Inflater::with_window_bits(Format::Raw, bits);
        let mut back = Vec::new();
        let p = inf.decompress_vec(&out, &mut back, usize::MAX).unwrap();
        assert!(p.done && back == data, "bits {bits}");
        // So does zlib-rs with that window (raw deflate, 9..=15).
        if bits >= 9 {
            let mut z = flate2::Decompress::new_with_window_bits(false, bits);
            let mut zb = Vec::with_capacity(data.len() + 10);
            z.decompress_vec(&out, &mut zb, flate2::FlushDecompress::Finish)
                .unwrap();
            assert!(zb == data, "zlib-rs bits {bits}");
        }
        if bits >= 10 {
            assert!(out.len() < 2000, "bits {bits}: {}", out.len());
        }
    }
    // A stream with distance 300 is rejected by a 256-byte window.
    let big = compress(Format::Raw, Level::BEST, &data);
    let mut inf = Inflater::with_window_bits(Format::Raw, 8);
    let mut v = Vec::new();
    assert_eq!(
        inf.decompress_vec(&big, &mut v, usize::MAX),
        Err(Error::BadDistance)
    );
    // zlib headers announce the window; a smaller decoder refuses a larger one.
    let z = compress(Format::Zlib, Level::DEFAULT, &data);
    assert_eq!(z[0], 0x78);
    let mut inf = Inflater::with_window_bits(Format::Zlib, 10);
    let mut v = Vec::new();
    assert_eq!(
        inf.decompress_vec(&z, &mut v, usize::MAX),
        Err(Error::BadHeader)
    );
    let mut d = Deflater::with_window_bits(Format::Zlib, Level::DEFAULT, 10);
    let mut z10 = Vec::new();
    d.compress(&data, &mut z10, Flush::Finish);
    assert_eq!(z10[0], 0x28);
    let mut inf = Inflater::with_window_bits(Format::Zlib, 10);
    let mut v = Vec::new();
    assert!(inf.decompress_vec(&z10, &mut v, usize::MAX).unwrap().done);
    assert_eq!(flate2_decompress(Format::Zlib, &z10), data);
}

#[test]
fn bomb_limit() {
    let z = compress(Format::Gzip, Level::BEST, &vec![0u8; 50 << 20]);
    assert!(z.len() < 100_000);
    assert_eq!(decompress(Format::Gzip, &z, 1 << 20), Err(Error::TooLarge));
    let mut inf = Inflater::new(Format::Gzip);
    let mut out = Vec::new();
    let p = inf.decompress_vec(&z, &mut out, 1000).unwrap();
    assert_eq!(out.len(), 1000);
    assert!(!p.done);
}

#[test]
fn corrupt_streams_are_rejected() {
    let data = text(20_000, 41);
    for format in FORMATS {
        let z = compress(format, Level::DEFAULT, &data);
        // Truncation.
        for cut in [0, 1, z.len() / 2, z.len() - 1] {
            assert!(
                decompress(format, &z[..cut], usize::MAX).is_err(),
                "{format:?} {cut}"
            );
        }
        // Checksums.
        if format != Format::Raw {
            let mut bad = z.clone();
            let n = bad.len();
            bad[n - 1] ^= 1;
            assert_eq!(
                decompress(format, &bad, usize::MAX),
                Err(Error::ChecksumMismatch)
            );
        }
        // Every single-bit flip either fails or (rarely, raw) decodes to something; it never
        // panics. zlib and gzip catch everything after the header through the checksum.
        for i in (0..z.len()).step_by(7) {
            let mut bad = z.clone();
            bad[i] ^= 0x10;
            let r = decompress(format, &bad, 1 << 20);
            if format != Format::Raw {
                assert!(
                    r.is_err() || r.as_deref() == Ok(&data[..]),
                    "{format:?} byte {i}"
                );
            }
        }
    }
    assert_eq!(
        decompress(Format::Zlib, &[0x78, 0x9d, 0, 0], 10),
        Err(Error::BadHeader)
    );
    assert_eq!(
        decompress(Format::Zlib, &[0x78, 0xbb, 0, 0, 0, 1], 10),
        Err(Error::DictionaryRequired)
    );
    assert_eq!(
        decompress(Format::Gzip, &[0x1f, 0x8c, 8, 0, 0, 0, 0, 0, 0, 0], 10),
        Err(Error::BadHeader)
    );
}

#[test]
fn gzip_header_fields() {
    // FEXTRA, FNAME, FCOMMENT and FHCRC, built with flate2's GzBuilder.
    let data = text(5000, 51);
    let mut e = flate2::GzBuilder::new()
        .filename("file.txt")
        .comment("a comment")
        .extra(vec![1, 2, 3, 4])
        .mtime(1_700_000_000)
        .write(Vec::new(), flate2::Compression::best());
    e.write_all(&data).unwrap();
    let mut z = e.finish().unwrap();
    for step in [1, 2, 5, 1000] {
        let mut inf = Inflater::new(Format::Gzip);
        let mut out = Vec::new();
        for piece in z.chunks(step) {
            inf.decompress_vec(piece, &mut out, usize::MAX).unwrap();
        }
        assert!(inf.is_done());
        assert_eq!(out, data);
    }
    // FHCRC: set the flag and insert the header CRC by hand.
    let flags_at = 3;
    let header_end = 10 + 2 + 4 + "file.txt".len() + 1 + "a comment".len() + 1;
    z[flags_at] |= 0x02;
    let hcrc = (crc32(&z[..header_end]) & 0xffff) as u16;
    z.splice(header_end..header_end, hcrc.to_le_bytes());
    assert_eq!(decompress(Format::Gzip, &z, usize::MAX).unwrap(), data);
    z[header_end] ^= 1;
    assert_eq!(
        decompress(Format::Gzip, &z, usize::MAX),
        Err(Error::BadHeader)
    );
}

#[test]
fn system_gzip_interop() {
    let Ok(probe) = std::process::Command::new("gzip").arg("--version").output() else {
        eprintln!("gzip(1) not found; skipped");
        return;
    };
    if !probe.status.success() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("only-deflate-gzip-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let data = text(300_000, 61);
    for lvl in ["-1", "-6", "-9"] {
        // gzip(1) compresses, we decompress.
        let mut c = std::process::Command::new("gzip")
            .args(["-c", "-n", lvl])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = c.stdin.take().unwrap();
        let d2 = data.clone();
        let w = std::thread::spawn(move || stdin.write_all(&d2).unwrap());
        let out = c.wait_with_output().unwrap();
        w.join().unwrap();
        assert_eq!(
            decompress(Format::Gzip, &out.stdout, usize::MAX).unwrap(),
            data
        );
    }
    for level in [1, 6, 9] {
        // We compress, gzip(1) decompresses and tests.
        let path = dir.join(format!("l{level}.gz"));
        std::fs::write(&path, compress(Format::Gzip, Level::new(level), &data)).unwrap();
        let out = std::process::Command::new("gzip")
            .arg("-dc")
            .arg(&path)
            .output()
            .unwrap();
        assert!(out.status.success(), "gzip -d level {level}");
        assert!(out.stdout == data, "gzip -d output level {level}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Hand-made streams for the decoder's corner cases, checked against zlib-rs.
#[test]
fn decoder_corner_cases_agree_with_zlib_rs() {
    fn zlib_rs(raw: &[u8]) -> Result<Vec<u8>, ()> {
        let mut z = flate2::Decompress::new(false);
        let mut out = Vec::with_capacity(1 << 16);
        match z.decompress_vec(raw, &mut out, flate2::FlushDecompress::Finish) {
            Ok(flate2::Status::StreamEnd) => Ok(out),
            _ => Err(()),
        }
    }
    let cases: Vec<Vec<u8>> = vec![
        // Empty fixed block, final.
        vec![0x03, 0x00],
        // Empty stored blocks, then a final empty fixed block.
        vec![0x00, 0x00, 0x00, 0xff, 0xff, 0x03, 0x00],
        // Fixed block with a length/distance pair (distance 1, length 258 via symbol 285).
        compress(Format::Raw, Level::FASTEST, &[b'z'; 259]),
        // Fixed block using literal/length symbol 286 (invalid).
        vec![0x63, 0x18, 0x00],
        // Dynamic header with too many length codes (HLIT = 30 -> 287).
        vec![0xf5, 0x00, 0x00, 0x00],
        // Dynamic header with no code lengths at all.
        vec![0x05, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];
    for (i, c) in cases.iter().enumerate() {
        let theirs = zlib_rs(c);
        let ours = decompress(Format::Raw, c, 1 << 16);
        assert_eq!(
            ours.is_ok(),
            theirs.is_ok(),
            "case {i}: {ours:?} vs {theirs:?}"
        );
        if let (Ok(a), Ok(b)) = (&ours, &theirs) {
            assert_eq!(a, b, "case {i}");
        }
    }
}

#[test]
fn checksums_match_flate2_crc() {
    let data = random(100_003, 71);
    let mut c = flate2::Crc::new();
    c.update(&data);
    assert_eq!(crc32(&data), c.sum());
    // Adler-32 through a zlib stream's trailer.
    let z = flate2_compress(Format::Zlib, 6, &data);
    let n = z.len();
    assert_eq!(
        adler32(&data),
        u32::from_be_bytes([z[n - 4], z[n - 3], z[n - 2], z[n - 1]])
    );
}

/// Short inputs are coded with the fixed code: every literal value (8- and 9-bit codes) and
/// every length and distance range must come out right.
#[test]
fn fixed_code_covers_every_symbol() {
    let mut z = flate2::Decompress::new(false);
    let mut d = Deflater::new(Format::Raw, Level::DEFAULT);
    let mut inf = Inflater::new(Format::Raw);
    for b in 0..=255u8 {
        let msg = [b, b.wrapping_add(1), b.wrapping_mul(7), b];
        let mut wire = Vec::new();
        d.compress(&msg, &mut wire, Flush::Sync);
        assert_eq!(wire[0] & 0b110, 0b010, "fixed block for {b}");
        let mut zb = Vec::with_capacity(64);
        z.decompress_vec(&wire, &mut zb, flate2::FlushDecompress::Sync)
            .unwrap();
        assert_eq!(zb, msg, "zlib-rs, literal {b}");
        let mut back = Vec::new();
        inf.decompress_vec(&wire, &mut back, 64).unwrap();
        assert_eq!(back, msg, "ours, literal {b}");
    }
    // Matches of every length at many distances: "x" + filler + a repeat of `len` bytes.
    let pool = random(40_000, 81);
    for len in (3..=258).step_by(5).chain([258]) {
        for dist in [1usize, 2, 5, 16, 17, 100, 1000, 4097, 20_000, 32_000] {
            let mut data = pool[..dist.max(len)].to_vec();
            let start = data.len() - dist;
            for i in 0..len {
                data.push(data[start + i]);
            }
            let ours = compress(Format::Raw, Level::BEST, &data);
            assert_eq!(
                flate2_decompress(Format::Raw, &ours),
                data,
                "len {len} dist {dist}"
            );
            assert_eq!(decompress(Format::Raw, &ours, data.len()).unwrap(), data);
        }
    }
}

/// The same incompressible message again and again with context takeover: every later copy is
/// one long run of matches into the previous message.
#[test]
fn repeated_random_messages_with_context_takeover() {
    for len in [1000usize, 32_768, 70_000] {
        let data = random(len, 0x2545_F491_4F6C_DD1D);
        for bits in [9u8, 15] {
            let mut d = Deflater::with_window_bits(Format::Raw, Level::DEFAULT, bits);
            let mut inf = Inflater::new(Format::Raw);
            let mut z = flate2::Decompress::new(false);
            for round in 0..3 {
                let mut wire = Vec::new();
                d.compress(&data, &mut wire, Flush::Sync);
                let mut zb = Vec::with_capacity(len + 64);
                z.decompress_vec(&wire, &mut zb, flate2::FlushDecompress::Sync)
                    .unwrap();
                assert!(
                    zb == data,
                    "zlib-rs decodes ours: len {len} bits {bits} round {round}"
                );
                let mut back = Vec::new();
                inf.decompress_vec(&wire, &mut back, usize::MAX).unwrap();
                assert!(back == data, "ours: len {len} bits {bits} round {round}");
            }
        }
    }
}
