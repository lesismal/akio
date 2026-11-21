//! The streaming compressor and decompressor and raw dictionaries, against each other, the
//! one-shot functions and the `brotli(1)` CLI.

use std::io::Write;
use std::process::{Command, Stdio};

use only_brotli::{
    Compressor, Decompressor, Error, Flush, Level, compress, compress_with_dictionary, decompress,
    decompress_with_dictionary,
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
        "stream",
        "window",
        "block",
        "meta",
        "literal",
        "copy",
        "distance",
        "dictionary",
        "zstd",
        "brotli",
        "<div class=\"x\">",
        "</div>",
        "function",
        "return",
        "{",
        "}",
    ];
    let mut r = Rng(seed | 1);
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        let a = (r.next() % WORDS.len() as u64) as usize;
        let b = (r.next() % WORDS.len() as u64) as usize;
        out.extend_from_slice(WORDS[a.min(b)].as_bytes());
        out.push(if r.next() % 9 == 0 { b'\n' } else { b' ' });
    }
    out.truncate(n);
    out
}

fn random(n: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng(seed | 1);
    (0..n).map(|_| r.next() as u8).collect()
}

fn corpora() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty", Vec::new()),
        ("one", b"x".to_vec()),
        ("text", text(1_300_000, 1)),
        ("random", random(150_000, 2)),
        ("same", vec![b'q'; 300_000]),
        ("long-period", random(30_000, 3).repeat(10)),
    ]
}

fn stream_compress(c: &mut Compressor, data: &[u8], step: usize, flush: Flush) -> Vec<u8> {
    let mut out = Vec::new();
    for piece in data.chunks(step.max(1)) {
        c.compress(piece, &mut out, flush);
    }
    c.compress(&[], &mut out, Flush::Finish);
    assert!(c.is_finished());
    out
}

fn stream_decompress(d: &mut Decompressor, packed: &[u8], step: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    for piece in packed.chunks(step.max(1)) {
        let mut at = 0;
        loop {
            let p = d.decompress_vec(&piece[at..], &mut out, usize::MAX)?;
            at += p.consumed;
            if at == piece.len() {
                break;
            }
        }
    }
    Ok(out)
}

#[test]
fn streamed_streams_round_trip() {
    for (name, data) in corpora() {
        for level in [0, 1, 4, 5, 6, 9, 11] {
            if level >= 10 && data.len() > 400_000 {
                continue;
            }
            for (step, flush) in [
                (data.len().max(1), Flush::None),
                (300_000, Flush::None),
                (9_999, Flush::Flush),
            ] {
                let mut c = Compressor::new(Level::new(level));
                let packed = stream_compress(&mut c, &data, step, flush);
                let what = format!("{name} level {level} step {step} {flush:?}");
                let back =
                    decompress(&packed, data.len()).unwrap_or_else(|e| panic!("{what}: {e}"));
                assert!(back == data, "{what}: one-shot decoding differs");
                for dstep in [1 << 20, 1000, 1] {
                    if dstep == 1 && packed.len() > 40_000 {
                        continue;
                    }
                    let mut d = Decompressor::new();
                    let back = stream_decompress(&mut d, &packed, dstep)
                        .unwrap_or_else(|e| panic!("{what} dstep {dstep}: {e}"));
                    assert!(
                        back == data,
                        "{what} dstep {dstep}: streamed decoding differs"
                    );
                    assert!(d.is_done(), "{what}: not done");
                }
            }
        }
    }
}

#[test]
fn small_windows_and_sliding() {
    let data = text(5_000_000, 9);
    for bits in [10, 16, 18] {
        let mut c = Compressor::new(Level::new(5)).window_bits(bits);
        let packed = stream_compress(&mut c, &data, 70_000, Flush::None);
        let mut d = Decompressor::new().max_window_bits(bits);
        let back = stream_decompress(&mut d, &packed, 50_000).expect("decodes");
        assert!(back == data, "window bits {bits}");
        assert!(decompress(&packed, data.len()).unwrap() == data);
        if bits > 10 {
            let mut d = Decompressor::new().max_window_bits(bits - 1);
            assert_eq!(
                d.decompress_vec(&packed, &mut Vec::new(), usize::MAX),
                Err(Error::WindowTooLarge)
            );
        }
    }
}

#[test]
fn flush_makes_everything_decodable() {
    for level in [1, 5, 11] {
        let mut c = Compressor::new(Level::new(level));
        let mut d = Decompressor::new();
        let mut wire = Vec::new();
        let mut got = Vec::new();
        let mut want = Vec::new();
        for i in 0..100 {
            let msg = format!("data: event number {i} with a payload payload payload\n\n");
            want.extend_from_slice(msg.as_bytes());
            let at = wire.len();
            c.compress(msg.as_bytes(), &mut wire, Flush::Flush);
            let p = d.decompress_vec(&wire[at..], &mut got, usize::MAX).unwrap();
            assert_eq!(p.consumed, wire.len() - at);
            assert_eq!(got, want, "level {level} after event {i}");
        }
        let at = wire.len();
        c.compress(&[], &mut wire, Flush::Finish);
        d.decompress_vec(&wire[at..], &mut got, usize::MAX).unwrap();
        assert!(d.is_done());
        assert_eq!(got, want);
    }
}

#[test]
fn whole_input_before_output_is_the_one_shot_stream() {
    let data = text(50_000, 4);
    for level in [1, 6, 11] {
        let mut c = Compressor::new(Level::new(level));
        let mut out = Vec::new();
        c.compress(&data[..10_000], &mut out, Flush::None);
        assert!(out.is_empty());
        c.compress(&data[10_000..], &mut out, Flush::Finish);
        assert_eq!(out, compress(Level::new(level), &data));
    }
}

#[test]
fn decompressor_limits_and_errors() {
    let data = text(400_000, 5);
    let packed = compress(Level::DEFAULT, &data);
    let mut d = Decompressor::new();
    let mut out = Vec::new();
    let p = d.decompress_vec(&packed, &mut out, 1000).unwrap();
    assert_eq!(out.len(), 1000);
    assert!(!p.done);
    let mut at = p.consumed;
    while !d.is_done() {
        let lim = out.len() + 777;
        let p = d.decompress_vec(&packed[at..], &mut out, lim).unwrap();
        at += p.consumed;
    }
    assert_eq!(at, packed.len());
    assert!(out == data);
    // Into a slice.
    let mut d = Decompressor::new();
    let mut buf = vec![0u8; 4096];
    let mut back = Vec::new();
    let mut at = 0;
    loop {
        let p = d.decompress(&packed[at..], &mut buf).unwrap();
        at += p.consumed;
        back.extend_from_slice(&buf[..p.produced]);
        if p.done {
            break;
        }
    }
    assert!(back == data);
    // Truncated: not done. Trailing bytes: an error that sticks.
    let mut d = Decompressor::new();
    d.decompress_vec(&packed[..packed.len() - 1], &mut Vec::new(), usize::MAX)
        .unwrap();
    assert!(!d.is_done());
    let mut extra = packed.clone();
    extra.push(0);
    let mut d = Decompressor::new();
    assert_eq!(
        d.decompress_vec(&extra, &mut Vec::new(), usize::MAX),
        Err(Error::TrailingData)
    );
    assert_eq!(
        d.decompress_vec(&[], &mut Vec::new(), usize::MAX),
        Err(Error::TrailingData)
    );
    d.reset();
    let mut out = Vec::new();
    d.decompress_vec(&packed, &mut out, usize::MAX).unwrap();
    assert!(d.is_done() && out == data);
    // Every truncation and a sample of bit flips: the streaming decoder agrees with the
    // one-shot one (fed whole or in pieces).
    let small = compress(Level::new(9), &text(3000, 6));
    for cut in 0..small.len() {
        let one = decompress(&small[..cut], 1 << 20);
        let mut d = Decompressor::new();
        let r = stream_decompress(&mut d, &small[..cut], 7);
        assert!(one.is_err());
        assert!(r.is_err() || !d.is_done(), "cut {cut}");
    }
    for i in 0..small.len() * 8 {
        let mut bad = small.clone();
        bad[i / 8] ^= 1 << (i % 8);
        let one = decompress(&bad, 1 << 20);
        let mut d = Decompressor::new();
        let r = stream_decompress(&mut d, &bad, 3);
        match (&one, &r) {
            (Ok(a), Ok(b)) => {
                assert!(a == b && d.is_done(), "flip {i}");
            }
            (Err(_), Ok(_)) => assert!(!d.is_done(), "flip {i}: accepted"),
            (Ok(_), Err(e)) => panic!("flip {i}: streaming refuses ({e})"),
            (Err(_), Err(_)) => {}
        }
    }
}

fn data_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

#[test]
fn raw_dictionaries() {
    let dict = text(40_000, 21);
    let similar: Vec<u8> = {
        let mut v = dict[5_000..25_000].to_vec();
        v.extend_from_slice(&text(5_000, 22));
        v.extend_from_slice(&dict[30_000..38_000]);
        v
    };
    for level in [0, 1, 4, 5, 6, 9, 10, 11] {
        let plain = compress(Level::new(level), &similar);
        let packed = compress_with_dictionary(Level::new(level), &similar, &dict);
        assert!(
            packed.len() * 3 < plain.len(),
            "level {level}: {} with, {} without",
            packed.len(),
            plain.len()
        );
        let back = decompress_with_dictionary(&packed, similar.len(), &dict).unwrap();
        assert!(back == similar, "level {level}");
        assert_eq!(
            decompress_with_dictionary(&packed, similar.len() - 1, &dict),
            Err(Error::TooLarge)
        );
        // Without the dictionary: an error or other bytes, never the data.
        assert!(decompress(&packed, 1 << 20).map_or(true, |o| o != similar));
        let mut c = Compressor::with_dictionary(Level::new(level), &dict);
        let s = stream_compress(&mut c, &similar, 3_333, Flush::Flush);
        let mut d = Decompressor::with_dictionary(&dict);
        assert!(stream_decompress(&mut d, &s, 101).unwrap() == similar);
        assert!(d.is_done());
    }
    // Longer than the window: the dictionary is used only while the output is within it.
    let big = [similar.clone(), text(3_000_000, 23), similar].concat();
    let packed = compress_with_dictionary(Level::new(5), &big, &dict);
    assert!(decompress_with_dictionary(&packed, big.len(), &dict).unwrap() == big);
    let mut c = Compressor::with_dictionary(Level::new(5), &dict).window_bits(16);
    let s = stream_compress(&mut c, &big, 100_000, Flush::None);
    let mut d = Decompressor::with_dictionary(&dict);
    assert!(stream_decompress(&mut d, &s, 77_777).unwrap() == big);
    let _ = data_dir();
}

fn brotli_cli(args: &[&str], input: &[u8]) -> Option<Vec<u8>> {
    let mut c = Command::new("brotli")
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
        "brotli {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(out.stdout)
}

fn have_brotli() -> bool {
    match Command::new("brotli").arg("--version").output() {
        Ok(o) if o.status.success() => true,
        _ => {
            eprintln!("brotli(1) not found; skipped");
            false
        }
    }
}

/// Our streams decode with brotli(1), with and without a raw dictionary, and its streams
/// (every quality, large windows) decode with our streaming decoder in pieces.
#[test]
fn cli_interop() {
    if !have_brotli() {
        return;
    }
    let data = text(2_500_000, 12);
    for level in [1, 5, 9] {
        let mut c = Compressor::new(Level::new(level));
        let packed = stream_compress(&mut c, &data, 333_333, Flush::Flush);
        let back = brotli_cli(&["-d", "-c"], &packed).unwrap();
        assert!(back == data, "brotli -d of our level {level} stream");
    }
    for q in [0, 2, 5, 9, 11] {
        let small = &data[..if q >= 10 { 300_000 } else { data.len() }];
        for w in [16, 24] {
            let theirs =
                brotli_cli(&["-c", "-q", &q.to_string(), "-w", &w.to_string()], small).unwrap();
            let mut d = Decompressor::new();
            let back = stream_decompress(&mut d, &theirs, 4096).unwrap();
            assert!(back == small, "brotli -q {q} -w {w}");
            assert!(d.is_done());
        }
    }
    let dir = std::env::temp_dir().join(format!("only-brotli-dict-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dict = text(60_000, 31);
    let dict_path = dir.join("dict");
    std::fs::write(&dict_path, &dict).unwrap();
    let dp = dict_path.to_str().unwrap();
    let msg = [
        &dict[1000..20_000],
        &text(3000, 32)[..],
        &dict[40_000..50_000],
    ]
    .concat();
    for q in [1, 5, 9, 11] {
        let theirs = brotli_cli(&["-c", "-q", &q.to_string(), "-D", dp], &msg).unwrap();
        assert!(
            theirs.len() * 3 < msg.len(),
            "brotli -D at q {q} uses the dictionary"
        );
        let back = decompress_with_dictionary(&theirs, msg.len(), &dict)
            .unwrap_or_else(|e| panic!("brotli -q {q} -D: {e}"));
        assert!(back == msg, "brotli -q {q} -D");
        let mut d = Decompressor::with_dictionary(&dict);
        assert!(stream_decompress(&mut d, &theirs, 13).unwrap() == msg);
        let ours = compress_with_dictionary(Level::new(q), &msg, &dict);
        let back = brotli_cli(&["-d", "-c", "-D", dp], &ours).unwrap();
        assert!(back == msg, "brotli -d -D of our level {q}");
    }
    std::fs::remove_dir_all(&dir).ok();
}
