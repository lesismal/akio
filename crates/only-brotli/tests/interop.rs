//! Google's test vectors, interop with the `brotli` command-line tool in both directions,
//! round trips on varied data, corrupt and truncated streams, the output limit and hand-made
//! streams for the corners of the format.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use only_brotli::{Error, Level, compress, decompress};

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
        "dictionary",
        "brotli",
        "stream",
        "network",
        "library",
        "Ünïcödé",
        "日本語",
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

fn json(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 200);
    let mut i = 0u64;
    while out.len() < n {
        let _ = writeln!(
            out,
            "{{\"id\":{i},\"name\":\"user{}\",\"active\":{},\"score\":{}.{}}},",
            i * 7919 % 10007,
            i % 3 == 0,
            i * 31 % 1000,
            i % 10
        );
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
        ("json", json(100_000)),
        ("binary", binary(150_000)),
        ("random", random(100_000, 2)),
        (
            "low-entropy",
            (0..120_000).map(|_| (low.next() % 4) as u8).collect(),
        ),
        // Repeats of a 40 KiB block.
        ("long-period", random(40_000, 3).repeat(4)),
        // Repeats of a 300-byte pattern: very long matches.
        ("period-300", random(300, 4).repeat(1000)),
        // Text, then random bytes, then text again (an uncompressed meta-block in between).
        ("mixed", {
            let mut v = text(1_200_000, 5);
            v.extend(random(1_100_000, 6));
            v.extend(text(300_000, 7));
            v
        }),
    ]
}

fn data_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

fn fnv1a(d: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in d {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// Decodes every stream of `tests/data/MANIFEST` (name, decoded length, FNV-1a of the decoded
/// bytes). The streams are a subset of `tests/testdata` of Google's brotli v1.1.0 (MIT
/// licence): the dictionary and transforms, context maps, block switching, long distances,
/// uncompressed and empty meta-blocks, every window size.
#[test]
fn official_vectors() {
    let manifest = std::fs::read_to_string(data_dir().join("MANIFEST")).unwrap();
    let mut n = 0;
    for line in manifest.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (name, len, hash) = (f[0], f[1].parse::<usize>().unwrap(), f[2]);
        let z = std::fs::read(data_dir().join(name)).unwrap();
        let out = decompress(&z, len).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(out.len(), len, "{name}");
        assert_eq!(format!("{:016x}", fnv1a(&out)), hash, "{name}");
        if len > 0 {
            assert_eq!(decompress(&z, len - 1), Err(Error::TooLarge), "{name}");
        }
        // Every prefix is refused.
        if z.len() < 200 {
            for cut in 0..z.len() {
                assert!(decompress(&z[..cut], len).is_err(), "{name} cut at {cut}");
            }
        }
        n += 1;
    }
    assert!(n >= 20);
}

/// All of Google's test vectors, when `BROTLI_TESTDATA` names a checkout's `tests/testdata`.
#[test]
fn all_official_vectors() {
    let Ok(dir) = std::env::var("BROTLI_TESTDATA") else {
        eprintln!("BROTLI_TESTDATA not set; skipped");
        return;
    };
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let Some((base, _)) = name.split_once(".compressed") else {
            continue;
        };
        let want = std::fs::read(p.with_file_name(base)).unwrap();
        let got = decompress(&std::fs::read(&p).unwrap(), usize::MAX);
        assert!(got.as_ref() == Ok(&want), "{name}: {:?}", got.err());
        n += 1;
    }
    eprintln!("{n} vectors decoded");
}

#[test]
fn round_trips() {
    for (name, data) in corpora() {
        for level in 0..=11 {
            if data.len() > 1_000_000 && level % 4 != 3 && level < 10 {
                continue; // the large corpus at a few levels only
            }
            let z = compress(Level::new(level), &data);
            let out = decompress(&z, data.len()).unwrap_or_else(|e| panic!("{name} {level}: {e}"));
            assert!(out == data, "{name} level {level}");
            if !data.is_empty() {
                assert_eq!(decompress(&z, data.len() - 1), Err(Error::TooLarge));
            }
            if name == "random" {
                // Incompressible data is stored: a few bytes of overhead.
                assert!(z.len() <= data.len() + 16, "{level}: {}", z.len());
            }
        }
    }
    assert_eq!(compress(Level::BEST, b""), [6]);
    for n in 0..300 {
        let d = text(n, n as u64);
        for level in [0, 5, 11] {
            assert_eq!(decompress(&compress(Level::new(level), &d), n).unwrap(), d);
        }
    }
}

#[test]
fn levels() {
    assert_eq!(Level::new(99), Level::BEST);
    assert_eq!(Level::default(), Level::DEFAULT);
    assert_eq!(
        (
            Level::FASTEST.get(),
            Level::DEFAULT.get(),
            Level::BEST.get()
        ),
        (1, 6, 11)
    );
    // Higher levels compress text better.
    let d = text(300_000, 9);
    let s: Vec<usize> = [1, 6, 11]
        .iter()
        .map(|&l| compress(Level::new(l), &d).len())
        .collect();
    assert!(s[0] > s[1] && s[1] > s[2], "{s:?}");
}

/// The level 11 output for DER certificate chains is no larger than zlib's at level 9 (the
/// compression TLS certificate compression would otherwise use).
#[test]
fn certificate_chains() {
    for name in ["github.com.chain.der", "www.wikipedia.org.chain.der"] {
        let der = std::fs::read(data_dir().join(name)).unwrap();
        let br = compress(Level::BEST, &der);
        let zlib =
            only_deflate::compress(only_deflate::Format::Zlib, only_deflate::Level::BEST, &der);
        assert!(
            br.len() <= zlib.len(),
            "{name}: {} > {}",
            br.len(),
            zlib.len()
        );
        assert_eq!(decompress(&br, der.len()).unwrap(), der);
    }
}

#[test]
fn corrupt_streams_are_rejected() {
    let data = text(20_000, 41);
    for level in [1, 6, 11] {
        let z = compress(Level::new(level), &data);
        for cut in 0..z.len() {
            assert!(decompress(&z[..cut], usize::MAX).is_err(), "{level} {cut}");
        }
        let mut longer = z.clone();
        longer.push(0);
        assert_eq!(decompress(&longer, usize::MAX), Err(Error::TrailingData));
        // Every single-bit flip fails or decodes to something; it never panics.
        for i in 0..z.len() * 8 {
            let mut bad = z.clone();
            bad[i / 8] ^= 1 << (i % 8);
            let _ = decompress(&bad, 1 << 20);
        }
    }
    let mut r = Rng(99);
    for n in 0..2000 {
        let junk = random(n % 64, r.next());
        let _ = decompress(&junk, 1 << 16);
    }
}

#[test]
fn limits() {
    let data = text(100_000, 3);
    let z = compress(Level::DEFAULT, &data);
    assert_eq!(decompress(&z, data.len()).unwrap(), data);
    assert_eq!(decompress(&z, data.len() - 1), Err(Error::TooLarge));
    assert_eq!(decompress(&z, 0), Err(Error::TooLarge));
    // Stored meta-blocks.
    let r = random(5000, 4);
    let z = compress(Level::DEFAULT, &r);
    assert_eq!(decompress(&z, r.len()).unwrap(), r);
    assert_eq!(decompress(&z, r.len() - 1), Err(Error::TooLarge));
    assert_eq!(decompress(&[6], 0), Ok(Vec::new()));
}

// ---- Hand-made streams ------------------------------------------------------------------------

#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    n: usize,
}

impl Bits {
    fn put(&mut self, n: u32, v: u64) -> &mut Self {
        for i in 0..n {
            if self.n % 8 == 0 {
                self.out.push(0);
            }
            let last = self.out.len() - 1;
            self.out[last] |= (((v >> i) & 1) as u8) << (self.n % 8);
            self.n += 1;
        }
        self
    }

    fn align(&mut self) -> &mut Self {
        self.n = self.n.div_ceil(8) * 8;
        self
    }

    fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.align();
        self.out.extend_from_slice(b);
        self.n += 8 * b.len();
        self
    }

    fn end(&mut self) -> Vec<u8> {
        self.put(2, 0b11); // ISLAST, ISLASTEMPTY
        std::mem::take(&mut self.out)
    }
}

/// A compressed meta-block of `mlen` bytes whose prefix codes each have a single symbol: every
/// command is `cmd`, every distance symbol `dsym`; the caller appends the commands' extra bits.
fn single_symbol_block(b: &mut Bits, last: bool, mlen: usize, cmd: u64, dsym: u64) {
    b.put(1, u64::from(last));
    if last {
        b.put(1, 0);
    }
    let nibbles = match mlen - 1 {
        0..=0xffff => 4,
        0x1_0000..=0xf_ffff => 5,
        _ => 6,
    };
    b.put(2, nibbles - 4)
        .put(4 * nibbles as u32, (mlen - 1) as u64);
    if !last {
        b.put(1, 0);
    }
    b.put(3, 0).put(6, 0).put(2, 0); // one block type each; NPOSTFIX, NDIRECT; LSB6
    b.put(1, 0).put(1, 0); // one literal tree, one distance tree
    b.put(2, 1).put(2, 0).put(8, u64::from(b'z')); // literals: always 'z'
    b.put(2, 1).put(2, 0).put(10, cmd);
    b.put(2, 1).put(2, 0).put(6, dsym);
}

/// Distance symbol, extra bits and their number for distance `d` (`NPOSTFIX` = `NDIRECT` = 0).
fn dist_code(d: u64) -> (u64, u64, u32) {
    let v = d + 3;
    let nb = 63 - v.leading_zeros() - 1;
    let h = (v >> nb) & 1;
    (16 + 2 * u64::from(nb - 1) + h, v & ((1 << nb) - 1), nb)
}

#[test]
fn window_sizes_and_headers() {
    // Every window size, with an empty stream.
    for w in 10..=24u64 {
        let mut b = Bits::default();
        match w {
            16 => b.put(1, 0),
            17 => b.put(7, 1),
            18..=24 => b.put(4, (w - 17) << 1 | 1),
            _ => b.put(7, (w - 8) << 4 | 1),
        };
        assert_eq!(decompress(&b.end(), 0), Ok(Vec::new()), "{w}");
    }
    // The large-window extension (WBITS escape 0010001) is not RFC 7932.
    assert_eq!(decompress(&[0x11, 0x03], 10), Err(Error::BadWindow));
    assert_eq!(decompress(&[], 10), Err(Error::Truncated));
    assert_eq!(decompress(&[6, 0], 10), Err(Error::TrailingData));
    assert_eq!(decompress(&[6 | 0x80], 10), Err(Error::BadPadding));

    // Metadata meta-blocks are skipped.
    let meta = |reserved: u64, nbytes: u64, len_minus_1: u64, body: &[u8]| {
        let mut b = Bits::default();
        b.put(1, 0)
            .put(1, 0)
            .put(2, 3)
            .put(1, reserved)
            .put(2, nbytes);
        b.put(8 * nbytes as u32, len_minus_1);
        b.bytes(body);
        b.end()
    };
    assert_eq!(decompress(&meta(0, 1, 2, b"abc"), 0), Ok(Vec::new()));
    assert_eq!(decompress(&meta(1, 1, 2, b"abc"), 0), Err(Error::BadHeader));
    assert_eq!(decompress(&meta(0, 2, 2, b"abc"), 0), Err(Error::BadHeader));
    assert_eq!(decompress(&meta(0, 1, 5, b"abc"), 0), Err(Error::Truncated));
    let mut b = Bits::default();
    b.put(1, 0).put(1, 0).put(2, 3).put(1, 0).put(2, 0).align(); // empty metadata
    assert_eq!(decompress(&b.end(), 0), Ok(Vec::new()));

    // Uncompressed meta-blocks.
    let stored = |nibbles: u64, mlen_minus_1: u64, pad: u64, body: &[u8]| {
        let mut b = Bits::default();
        b.put(1, 0).put(1, 0).put(2, nibbles - 4);
        b.put(4 * nibbles as u32, mlen_minus_1).put(1, 1);
        let r = (8 - b.n % 8) % 8;
        b.put(r as u32, pad);
        b.bytes(body);
        b.end()
    };
    assert_eq!(decompress(&stored(4, 4, 0, b"hello"), 5).unwrap(), b"hello");
    assert_eq!(
        decompress(&stored(4, 4, 0, b"hello"), 4),
        Err(Error::TooLarge)
    );
    assert_eq!(
        decompress(&stored(4, 5, 0, b"hello"), 9),
        Err(Error::Truncated)
    );
    assert_eq!(
        decompress(&stored(4, 4, 1, b"hello"), 9),
        Err(Error::BadPadding)
    );
    // MLEN with a superfluous zero nibble.
    assert_eq!(
        decompress(&stored(5, 4, 0, b"hello"), 9),
        Err(Error::BadHeader)
    );
}

#[test]
fn dictionary_references() {
    // Insert 0, copy code 2 (4 bytes), explicit distance: command symbol 130.
    let word = |dist: u64, mlen: usize| {
        let mut b = Bits::default();
        b.put(1, 0);
        let (sym, extra, nb) = dist_code(dist);
        single_symbol_block(&mut b, true, mlen, 130, sym);
        b.put(nb, extra);
        b.align();
        b.out.clone()
    };
    // At position 0 every distance is past the window: address = distance - 1; word 0 of
    // length 4 is "time"; transform 9 upper-cases the first letter; transform 3 omits it.
    assert_eq!(decompress(&word(1, 4), 4).unwrap(), b"time");
    assert_eq!(decompress(&word(1 + (9 << 10), 4), 4).unwrap(), b"Time");
    assert_eq!(decompress(&word(1 + (3 << 10), 3), 3).unwrap(), b"ime");
    assert_eq!(decompress(&word(1 + (44 << 10), 4), 4).unwrap(), b"TIME");
    assert_eq!(
        decompress(&word(1 + (1 << 10) + 1, 5), 5).unwrap(),
        b"down "
    );
    // The transform must exist, and the word fit the meta-block.
    assert_eq!(
        decompress(&word(1 + (121 << 10), 4), 9),
        Err(Error::BadDictionaryReference)
    );
    assert_eq!(decompress(&word(1, 3), 9), Err(Error::BadBlockLength));
    // Copy length 2 has no dictionary words: insert 0, copy code 0 is symbol 128.
    let mut b = Bits::default();
    b.put(1, 0);
    let (sym, extra, nb) = dist_code(1);
    single_symbol_block(&mut b, true, 2, 128, sym);
    b.put(nb, extra);
    b.align();
    assert_eq!(decompress(&b.out, 9), Err(Error::BadDictionaryReference));
}

#[test]
fn distance_ring() {
    // Insert 1 ('z'), copy 2 from distance 1; then, with distance code 4 (last - 1 = 0),
    // the reference is invalid. Commands: insert code 1, copy code 0 = symbol 136.
    let mut b = Bits::default();
    b.put(1, 0);
    b.put(1, 1).put(1, 0).put(2, 0).put(16, 5); // ISLAST, MLEN 6
    b.put(3, 0).put(6, 0).put(2, 0).put(1, 0).put(1, 0);
    b.put(2, 1).put(2, 0).put(8, u64::from(b'z'));
    b.put(2, 1).put(2, 0).put(10, 136);
    b.put(2, 1).put(2, 1).put(6, 4).put(6, 16); // two distance symbols: 4 and 16 (1 bit each)
    b.put(1, 1).put(1, 0); // symbol 16, extra 0: distance 1 -> "zzz"
    b.put(1, 0); // symbol 4
    b.align();
    assert_eq!(decompress(&b.out, 9), Err(Error::BadDistance));
}

/// A few hundred bytes that would expand to 1 GiB are refused at the limit, quickly.
#[test]
fn decompression_bomb() {
    let mut b = Bits::default();
    b.put(1, 0);
    let blocks = 64;
    for _ in 0..blocks {
        // Insert 1 literal and copy 2^24 - 1 bytes from distance 1: insert code 1, copy code
        // 23 is symbol 6 * 64 + 8 + 7 = 399.
        single_symbol_block(&mut b, false, 1 << 24, 399, 16);
        b.put(24, (1 << 24) - 1 - 2118); // copy extra bits
        b.put(1, 0); // distance extra bit
    }
    let z = b.end();
    assert!(z.len() < 1000, "{}", z.len());
    let t = std::time::Instant::now();
    assert_eq!(decompress(&z, 64 << 20), Err(Error::TooLarge));
    assert!(t.elapsed() < std::time::Duration::from_secs(5));
    // The first 16 MiB are right.
    let mut one = Bits::default();
    one.put(1, 0);
    single_symbol_block(&mut one, false, 1 << 24, 399, 16);
    one.put(24, (1 << 24) - 1 - 2118).put(1, 0);
    let out = decompress(&one.end(), 1 << 24).unwrap();
    assert!(out.len() == 1 << 24 && out.iter().all(|&c| c == b'z'));
}

// ---- The brotli command-line tool ------------------------------------------------------------

fn brotli_cli() -> bool {
    match Command::new("brotli").arg("--version").output() {
        Ok(o) if o.status.success() => true,
        _ => {
            eprintln!("brotli(1) not found; skipped");
            false
        }
    }
}

fn run(args: &[&str], input: &[u8]) -> Vec<u8> {
    let mut c = Command::new("brotli")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = c.stdin.take().unwrap();
    let d = input.to_vec();
    let w = std::thread::spawn(move || stdin.write_all(&d).unwrap());
    let out = c.wait_with_output().unwrap();
    w.join().unwrap();
    assert!(out.status.success(), "brotli {args:?}");
    out.stdout
}

#[test]
fn brotli_cli_decodes_ours() {
    if !brotli_cli() {
        return;
    }
    for (name, data) in corpora() {
        for level in 0..=11 {
            if data.len() > 1_000_000 && level % 4 != 3 {
                continue;
            }
            let z = compress(Level::new(level), &data);
            let out = run(&["-d", "-c"], &z);
            assert!(out == data, "{name} level {level}");
        }
    }
}

#[test]
fn ours_decodes_brotli_cli() {
    if !brotli_cli() {
        return;
    }
    for (name, data) in corpora() {
        for q in 0..=11 {
            if data.len() > 1_000_000 && q % 4 != 3 {
                continue;
            }
            let windows: &[u32] = if (q == 5 || q == 11) && data.len() < 1_000_000 {
                &[10, 16, 18, 22, 24]
            } else {
                &[22]
            };
            for &w in windows {
                let z = run(&["-c", "-q", &q.to_string(), "-w", &w.to_string()], &data);
                let out =
                    decompress(&z, data.len()).unwrap_or_else(|e| panic!("{name} q{q} w{w}: {e}"));
                assert!(out == data, "{name} q{q} w{w}");
            }
        }
    }
    // Distances of several MiB with a 2^24 window.
    let mut big = random(3 << 20, 11);
    big.extend_from_within(..);
    let z = run(&["-c", "-q", "4", "-w", "24"], &big);
    assert!(z.len() < (3 << 20) + (1 << 16));
    assert!(decompress(&z, big.len()).unwrap() == big);
}
