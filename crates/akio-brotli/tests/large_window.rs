//! Large-window brotli (RFC 9841 section 6): the header, the larger distance alphabet, the
//! encoder and both decoders, and Google's `brotli --large_window` where it is installed.

use std::io::Write;
use std::process::{Command, Stdio};

use akio_brotli::{
    Compressor, Decompressor, Error, Flush, Level, compress, compress_large_window, decompress,
    decompress_large_window,
};

/// Bits written least significant first.
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
            let bit = (v >> i) & 1;
            *self.out.last_mut().unwrap() |= (bit as u8) << (self.n % 8);
            self.n += 1;
        }
        self
    }

    fn end(&mut self) -> Vec<u8> {
        self.put(2, 0b11); // ISLAST, ISLASTEMPTY
        std::mem::take(&mut self.out)
    }
}

fn large_header(b: &mut Bits, wbits: u64) {
    b.put(8, 0x11).put(6, wbits);
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn text(n: usize, seed: u64) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "the", "of", "and", "window", "large", "distance", "brotli", "<td>", "</td>", "{", "}",
        "stream", "alphabet", "symbol", "copy", "literal",
    ];
    let mut r = Rng(seed | 1);
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        out.extend_from_slice(WORDS[(r.next() % WORDS.len() as u64) as usize].as_bytes());
        out.push(if r.next() % 7 == 0 { b'\n' } else { b' ' });
    }
    out.truncate(n);
    out
}

fn random(n: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng(seed | 1);
    (0..n).map(|_| r.next() as u8).collect()
}

fn stream_decode(packed: &[u8], step: usize, max_wbits: u32) -> Result<Vec<u8>, Error> {
    let mut d = Decompressor::new()
        .large_window(true)
        .max_window_bits(max_wbits);
    let mut out = Vec::new();
    for piece in packed.chunks(step.max(1)) {
        let mut piece = piece;
        while !piece.is_empty() {
            let p = d.decompress_vec(piece, &mut out, usize::MAX)?;
            piece = &piece[p.consumed..];
        }
    }
    if !d.is_done() {
        return Err(Error::Truncated);
    }
    Ok(out)
}

#[test]
fn headers() {
    for w in 10..=30u64 {
        let mut b = Bits::default();
        large_header(&mut b, w);
        let s = b.end();
        assert_eq!(decompress_large_window(&s, 0), Ok(Vec::new()), "{w}");
        // A regular decoder refuses it.
        assert_eq!(decompress(&s, 0), Err(Error::BadWindow), "{w}");
        assert_eq!(stream_decode(&s, 1, 30), Ok(Vec::new()), "{w}");
        if w > 24 {
            assert_eq!(stream_decode(&s, 1, 24), Err(Error::WindowTooLarge), "{w}");
        }
    }
    for w in [0u64, 9, 31, 62, 63] {
        let mut b = Bits::default();
        large_header(&mut b, w);
        assert_eq!(
            decompress_large_window(&b.end(), 0),
            Err(Error::BadWindow),
            "{w}"
        );
    }
    // The bit after 0x11 must be 0 (Google's decoder).
    let mut b = Bits::default();
    b.put(7, 0x11).put(1, 1).put(6, 20);
    assert_eq!(decompress_large_window(&b.end(), 0), Err(Error::BadWindow));
    // Regular headers decode as before.
    assert_eq!(
        decompress_large_window(&compress(Level::new(5), b"abcabcabc"), 9).unwrap(),
        b"abcabcabc"
    );
}

/// A meta-block of one literal and a copy of 4 whose distance has symbol `dsym` (simple
/// prefix codes of one symbol, distance symbols in `dbits` bits) with zero extra bits.
fn one_copy(b: &mut Bits, dsym: u64, dbits: u32) {
    b.put(1, 1).put(1, 0); // ISLAST
    b.put(2, 0).put(16, 4); // MLEN 5
    b.put(3, 0).put(6, 0).put(2, 0); // one block type each; NPOSTFIX, NDIRECT; LSB6
    b.put(1, 0).put(1, 0); // one literal tree, one distance tree
    b.put(2, 1).put(2, 0).put(8, u64::from(b'z')); // literals: 'z'
    // Insert 1 (code 1), copy 4 (code 2), explicit distance: symbol 128 + 8 + 2.
    b.put(2, 1).put(2, 0).put(10, 138);
    b.put(2, 1).put(2, 0).put(dbits, dsym);
    // Symbol 16 + 2 * (nb - 1) + h has nb extra bits (zero here).
    let nb = if dsym >= 16 { (dsym - 16) / 2 + 1 } else { 0 };
    b.put(nb as u32, 0);
}

#[test]
fn distance_alphabet() {
    // Symbols up to 73 (distances up to 2^31 - 4) are allowed, in 8 bits in a simple code;
    // this distance is past the window and the static dictionary.
    for (dsym, want) in [
        (73, Error::BadDictionaryReference),
        (74, Error::BadPrefixCode),
        (139, Error::BadPrefixCode),
    ] {
        let mut b = Bits::default();
        large_header(&mut b, 30);
        one_copy(&mut b, dsym, 8);
        let s = b.end();
        assert_eq!(decompress_large_window(&s, 1 << 20), Err(want), "{dsym}");
        assert_eq!(stream_decode(&s, 3, 30), Err(want), "{dsym}");
    }
    // A regular stream: 64 symbols in 6 bits; 63 is a distance past the dictionary too.
    let mut b = Bits::default();
    b.put(1, 0); // window 2^16
    one_copy(&mut b, 63, 6);
    let s = b.end();
    assert_eq!(decompress(&s, 1 << 20), Err(Error::BadDictionaryReference));
    assert_eq!(
        decompress_large_window(&s, 1 << 20),
        Err(Error::BadDictionaryReference)
    );
}

#[test]
fn round_trips() {
    let data = [text(300_000, 1), random(70_000, 2), text(100, 3)].concat();
    for q in 0..=11u32 {
        let data = if q >= 10 { &data[..120_000] } else { &data[..] };
        let packed = compress_large_window(Level::new(q), data);
        assert_eq!(
            decompress(&packed, data.len()),
            Err(Error::BadWindow),
            "{q}"
        );
        assert_eq!(
            decompress_large_window(&packed, data.len()).unwrap(),
            data,
            "{q}"
        );
        assert_eq!(stream_decode(&packed, 4093, 24).unwrap(), data, "{q}");
        // Streamed, with flushes, a window of 2^26.
        let mut c = Compressor::new(Level::new(q))
            .large_window(true)
            .window_bits(26);
        let mut out = Vec::new();
        for piece in data.chunks(50_000) {
            c.compress(piece, &mut out, Flush::Flush);
        }
        c.compress(&[], &mut out, Flush::Finish);
        assert_eq!(stream_decode(&out, 777, 26).unwrap(), data, "{q}");
        assert_eq!(stream_decode(&out, 777, 25), Err(Error::WindowTooLarge));
        // All at once: the one-shot stream, still large-window.
        let mut c = Compressor::new(Level::new(q))
            .large_window(true)
            .window_bits(28);
        let mut out = Vec::new();
        c.compress(data, &mut out, Flush::Finish);
        assert_eq!(decompress(&out, data.len()), Err(Error::BadWindow), "{q}");
        assert_eq!(decompress_large_window(&out, data.len()).unwrap(), data);
    }
    // Without `large_window` the window stays within RFC 7932.
    let mut c = Compressor::new(Level::new(4)).window_bits(30);
    let mut out = Vec::new();
    c.compress(&data[..1000], &mut out, Flush::Flush);
    c.compress(&[], &mut out, Flush::Finish);
    assert_eq!(decompress(&out, 1000).unwrap(), &data[..1000]);
}

/// Matches more than 64 MiB back: distance symbols past RFC 7932's alphabet (run with
/// `--ignored --release`: about 140 MiB of data). Between two copies of 64 KiB of random data
/// is a run of zeros, which leaves the match finder's tables holding the first copy.
#[test]
#[ignore]
fn distances_past_64_mib() {
    let a = random(64 << 10, 7);
    let mut data = a.clone();
    data.resize(data.len() + (70 << 20), 0);
    data.extend_from_slice(&a);
    for q in [1u32, 5, 9] {
        let packed = compress_large_window(Level::new(q), &data);
        // The second copy costs almost nothing.
        assert!(
            packed.len() < a.len() + 20_000,
            "level {q}: {}",
            packed.len()
        );
        assert_eq!(decompress_large_window(&packed, data.len()).unwrap(), data);
        assert_eq!(stream_decode(&packed, 1 << 20, 27).unwrap(), data);
        if let Some(back) = brotli_cli(&["-d", "-c", "--large_window=30"], &packed) {
            assert!(back == data, "brotli -d, level {q}");
        }
        let mut c = Compressor::new(Level::new(q))
            .large_window(true)
            .window_bits(27);
        let mut out = Vec::new();
        for piece in data.chunks(1 << 20) {
            c.compress(piece, &mut out, Flush::None);
        }
        c.compress(&[], &mut out, Flush::Finish);
        assert!(
            out.len() < a.len() + 20_000,
            "level {q} streamed: {}",
            out.len()
        );
        assert_eq!(stream_decode(&out, 1 << 20, 27).unwrap(), data);
        // A regular stream cannot reach back that far.
        let regular = compress(Level::new(q), &data);
        assert!(regular.len() > a.len() * 3 / 2, "level {q}");
    }
}

fn brotli_cli(args: &[&str], input: &[u8]) -> Option<Vec<u8>> {
    let mut child = Command::new("brotli")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdin = child.stdin.take()?;
    let input = input.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let out = child.wait_with_output().ok()?;
    let _ = writer.join();
    out.status.success().then_some(out.stdout)
}

/// Google's `brotli --large_window` decodes ours and ours decodes its (skipped without it).
#[test]
fn cli_interop() {
    if brotli_cli(&["-c"], b"x").is_none() {
        eprintln!("brotli(1) not found: skipped");
        return;
    }
    let data = [text(400_000, 11), random(30_000, 12), text(400_000, 11)].concat();
    for q in [0u32, 1, 4, 5, 9, 11] {
        let data = if q == 11 { &data[..200_000] } else { &data[..] };
        let packed = compress_large_window(Level::new(q), data);
        let back = brotli_cli(&["-d", "-c", "--large_window=30"], &packed);
        assert_eq!(back.as_deref(), Some(data), "brotli -d, level {q}");
        let mut c = Compressor::new(Level::new(q))
            .large_window(true)
            .window_bits(30);
        let mut out = Vec::new();
        for piece in data.chunks(100_000) {
            c.compress(piece, &mut out, Flush::Flush);
        }
        c.compress(&[], &mut out, Flush::Finish);
        let back = brotli_cli(&["-d", "-c", "--large_window=30"], &out);
        assert_eq!(back.as_deref(), Some(data), "brotli -d, streamed level {q}");
    }
    for (q, w) in [(1, 30), (3, 30), (5, 25), (9, 30), (11, 24), (11, 30)] {
        let qs = format!("--quality={q}");
        let ws = format!("--large_window={w}");
        let packed = brotli_cli(&["-c", &qs, &ws], &data).expect("brotli --large_window");
        // Google's encoder writes the large-window header for windows over 2^24 only, and
        // never at qualities 0..=2.
        if q > 2 && w > 24 {
            assert_eq!(decompress(&packed, data.len()), Err(Error::BadWindow));
        }
        assert_eq!(
            decompress_large_window(&packed, data.len()).unwrap(),
            data,
            "brotli -q{q} --large_window={w}"
        );
        assert_eq!(stream_decode(&packed, 1000, 30).unwrap(), data);
    }
}
