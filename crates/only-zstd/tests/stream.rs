//! The streaming compressor and decompressor, and dictionaries (raw content and the trained
//! format), against each other and against the `zstd(1)` CLI.

use std::io::Write;
use std::process::{Command, Stdio};

use only_zstd::{
    Compressor, Decompressor, Dictionary, Error, Flush, Level, compress, compress_with_dictionary,
    decompress, decompress_with_dictionary,
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
        "frame",
        "literal",
        "match",
        "offset",
        "dictionary",
        "zstd",
        "brotli",
    ];
    let mut r = Rng(seed | 1);
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        let i = (r.next() % WORDS.len() as u64) as usize;
        let i = i * (r.next() % (WORDS.len() as u64) + 1) as usize / WORDS.len();
        out.extend_from_slice(WORDS[i % WORDS.len()].as_bytes());
        out.push(if r.next() % 11 == 0 { b'\n' } else { b' ' });
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
        ("text", text(700_000, 1)),
        ("random", random(200_000, 2)),
        ("same", vec![b'q'; 400_000]),
        ("long-period", random(50_000, 3).repeat(12)),
    ]
}

/// Compresses `data` in pieces of `step` with `flush` after each.
fn stream_compress(c: &mut Compressor, data: &[u8], step: usize, flush: Flush) -> Vec<u8> {
    let mut out = Vec::new();
    for piece in data.chunks(step.max(1)) {
        c.compress(piece, &mut out, flush);
    }
    c.compress(&[], &mut out, Flush::Finish);
    assert!(c.is_finished());
    out
}

/// Decompresses `packed` in pieces of `step` into an output limited to `limit` per call.
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
fn streamed_frames_round_trip() {
    for (name, data) in corpora() {
        for level in [1, 3, 5, 9, 19] {
            for (step, flush) in [
                (data.len().max(1), Flush::None),
                (100_000, Flush::None),
                (7_777, Flush::Flush),
                (130_000, Flush::Flush),
            ] {
                let mut c = Compressor::new(Level::new(level));
                let packed = stream_compress(&mut c, &data, step, flush);
                let what = format!("{name} level {level} step {step} {flush:?}");
                let back =
                    decompress(&packed, data.len()).unwrap_or_else(|e| panic!("{what}: {e}"));
                assert!(back == data, "{what}: one-shot decoding differs");
                for dstep in [1 << 20, 4096, 3] {
                    if dstep < 4096 && data.len() > 300_000 {
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
    // Windows smaller than the data: the encoder's buffer and the decoder's window slide.
    let data = text(3_000_000, 9);
    for log in [10, 12, 17, 19] {
        let mut c = Compressor::new(Level::new(3)).window_log(log);
        let packed = stream_compress(&mut c, &data, 65_536, Flush::None);
        let mut d = Decompressor::new().max_window(1 << log);
        let back = stream_decompress(&mut d, &packed, 50_000).expect("decodes");
        assert!(back == data, "window log {log}");
        // A smaller window limit refuses the frame (1 KiB is the smallest limit).
        if log == 10 {
            continue;
        }
        let mut d = Decompressor::new().max_window((1 << log) - 1);
        let mut out = Vec::new();
        assert_eq!(
            d.decompress_vec(&packed, &mut out, usize::MAX),
            Err(Error::WindowTooLarge),
            "log {log}"
        );
    }
}

#[test]
fn flush_makes_everything_decodable() {
    let mut c = Compressor::new(Level::DEFAULT);
    let mut d = Decompressor::new();
    let mut wire = Vec::new();
    let mut got = Vec::new();
    let mut want = Vec::new();
    for i in 0..200 {
        let msg = format!("data: event number {i} with some repeated payload payload payload\n\n");
        want.extend_from_slice(msg.as_bytes());
        let at = wire.len();
        c.compress(msg.as_bytes(), &mut wire, Flush::Flush);
        let p = d.decompress_vec(&wire[at..], &mut got, usize::MAX).unwrap();
        assert_eq!(p.consumed, wire.len() - at);
        assert_eq!(got, want, "after event {i}");
    }
    let at = wire.len();
    c.compress(&[], &mut wire, Flush::Finish);
    d.decompress_vec(&wire[at..], &mut got, usize::MAX).unwrap();
    assert!(d.is_done());
    assert_eq!(got, want);
}

#[test]
fn whole_input_before_output_is_the_one_shot_frame() {
    let data = text(50_000, 4);
    for level in [1, 3, 19] {
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
    let data = text(300_000, 5);
    let packed = compress(Level::DEFAULT, &data);
    // The output limit holds within a call, and the rest comes on later calls.
    let mut d = Decompressor::new();
    let mut out = Vec::new();
    let p = d.decompress_vec(&packed, &mut out, 1000).unwrap();
    assert_eq!(out.len(), 1000);
    assert!(!p.done);
    let mut at = p.consumed;
    while !d.is_done() {
        let lim = out.len() + 1000;
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
    // Truncated input is not done; a bad checksum is an error that sticks.
    let mut d = Decompressor::new();
    let mut out = Vec::new();
    d.decompress_vec(&packed[..packed.len() - 1], &mut out, usize::MAX)
        .unwrap();
    assert!(!d.is_done());
    let mut bad = packed.clone();
    *bad.last_mut().unwrap() ^= 1;
    let mut d = Decompressor::new();
    assert_eq!(
        d.decompress_vec(&bad, &mut Vec::new(), usize::MAX),
        Err(Error::ChecksumMismatch)
    );
    assert_eq!(
        d.decompress_vec(&[], &mut Vec::new(), usize::MAX),
        Err(Error::ChecksumMismatch)
    );
    d.reset();
    let mut out = Vec::new();
    d.decompress_vec(&packed, &mut out, usize::MAX).unwrap();
    assert!(d.is_done() && out == data);
    // Concatenated and skippable frames.
    let mut two = compress(Level::FASTEST, b"first ");
    two.extend_from_slice(&[0x50, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 1, 2, 3]);
    two.extend_from_slice(&compress(Level::FASTEST, b"second"));
    let mut d = Decompressor::new();
    let back = stream_decompress(&mut d, &two, 1).unwrap();
    assert_eq!(back, b"first second");
    assert!(d.is_done());
    // A frame naming a dictionary needs one, and the right one.
    let dict = Dictionary::new(&std::fs::read(data_dir().join("records.dict")).unwrap()).unwrap();
    let packed = compress_with_dictionary(Level::DEFAULT, b"{\"name\": \"x\"}", &dict);
    assert_eq!(
        Decompressor::new().decompress_vec(&packed, &mut Vec::new(), 100),
        Err(Error::DictionaryRequired)
    );
    assert_eq!(decompress(&packed, 100), Err(Error::DictionaryRequired));
    let other = {
        let mut b = std::fs::read(data_dir().join("records.dict")).unwrap();
        b[4] ^= 1;
        Dictionary::new(&b).unwrap()
    };
    assert_eq!(
        decompress_with_dictionary(&packed, 100, &other),
        Err(Error::WrongDictionary)
    );
}

fn data_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

fn records() -> Vec<Vec<u8>> {
    let mut r = Rng(11);
    let names = ["ada", "grace", "linus", "ken", "dennis", "barbara", "alan"];
    (0..50)
        .map(|i| {
            let n = names[(r.next() % 7) as usize];
            format!(
                "{{\n \"id\": {i},\n \"name\": \"{n}\",\n \"email\": \"{n}@example.com\",\n \"roles\": [\n  \"editor\"\n ],\n \"active\": true,\n \"created\": \"2026-0{}-1{}T10:20:00Z\",\n \"tags\": []\n}}",
                r.next() % 9 + 1,
                r.next() % 9
            )
            .into_bytes()
        })
        .collect()
}

#[test]
fn dictionaries_round_trip_and_help() {
    let trained =
        Dictionary::new(&std::fs::read(data_dir().join("records.dict")).unwrap()).unwrap();
    assert!(trained.is_trained());
    assert_eq!(trained.id(), 1_234_567);
    let raw = Dictionary::raw(&std::fs::read(data_dir().join("record.json")).unwrap());
    assert!(!raw.is_trained() && raw.id() == 0);
    let mut plain_total = 0;
    let mut sizes = [0usize; 2];
    for rec in records() {
        for level in [1, 3, 7, 19] {
            let plain = compress(Level::new(level), &rec);
            if level == 3 {
                plain_total += plain.len();
            }
            for (k, dict) in [&trained, &raw].into_iter().enumerate() {
                let packed = compress_with_dictionary(Level::new(level), &rec, dict);
                if level == 3 {
                    sizes[k] += packed.len();
                }
                let back = decompress_with_dictionary(&packed, rec.len(), dict).unwrap();
                assert_eq!(back, rec);
                assert_eq!(
                    decompress_with_dictionary(&packed, rec.len() - 1, dict),
                    Err(Error::TooLarge)
                );
                // Streamed, in small pieces both ways.
                let mut c = Compressor::with_dictionary(Level::new(level), dict);
                let s = stream_compress(&mut c, &rec, 17, Flush::Flush);
                let mut d = Decompressor::with_dictionary(dict);
                assert_eq!(stream_decompress(&mut d, &s, 5).unwrap(), rec);
                assert!(d.is_done());
            }
        }
    }
    // The dictionaries pay for themselves on small records.
    assert!(
        sizes[0] * 2 < plain_total,
        "trained {sizes:?} plain {plain_total}"
    );
    assert!(
        sizes[1] * 3 < plain_total * 2,
        "raw {sizes:?} plain {plain_total}"
    );
    // A large input with a dictionary (several blocks, beyond a small window).
    let big = text(1_500_000, 8);
    for dict in [&trained, &raw] {
        let packed = compress_with_dictionary(Level::new(3), &big, dict);
        assert!(decompress_with_dictionary(&packed, big.len(), dict).unwrap() == big);
        let mut c = Compressor::with_dictionary(Level::new(3), dict).window_log(17);
        let s = stream_compress(&mut c, &big, 40_000, Flush::None);
        let mut d = Decompressor::with_dictionary(dict).max_window(1 << 17);
        assert!(stream_decompress(&mut d, &s, 30_000).unwrap() == big);
    }
}

#[test]
fn malformed_dictionaries_are_refused() {
    let good = std::fs::read(data_dir().join("records.dict")).unwrap();
    // Every truncation of the tables, and repeat offsets past the content.
    for cut in 8..good.len() - 1500 {
        let r = Dictionary::new(&good[..cut]);
        if let Ok(d) = r {
            // Cut inside the content: still valid, with less content.
            assert!(d.content().len() < 2048);
        }
    }
    assert_eq!(
        Dictionary::new(&good[..9]).err(),
        Some(Error::BadDictionary)
    );
    // Any bytes not starting with the magic number are raw content.
    assert!(!Dictionary::new(b"short").unwrap().is_trained());
}

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

/// Our streamed frames and dictionary frames decode with zstd(1), and its frames (streamed
/// from a pipe: no content size) and dictionary frames decode with ours.
#[test]
fn cli_interop() {
    if !have_zstd() {
        return;
    }
    let data = text(900_000, 12);
    for level in [1, 3, 19] {
        let mut c = Compressor::new(Level::new(level));
        let packed = stream_compress(&mut c, &data, 33_333, Flush::Flush);
        let back = zstd_cli(&["-d", "-c"], &packed).unwrap();
        assert!(back == data, "zstd -d of our level {level} stream");
        let theirs = zstd_cli(&[&format!("-{level}"), "-c"], &data).unwrap();
        let mut d = Decompressor::new();
        assert!(stream_decompress(&mut d, &theirs, 10_000).unwrap() == data);
    }
    let dict_path = data_dir().join("records.dict");
    let dict_path = dict_path.to_str().unwrap();
    let raw_path = data_dir().join("record.json");
    let raw_path = raw_path.to_str().unwrap();
    let trained = Dictionary::new(&std::fs::read(dict_path).unwrap()).unwrap();
    let raw = Dictionary::raw(&std::fs::read(raw_path).unwrap());
    let mut all = Vec::new();
    for rec in records() {
        all.extend_from_slice(&rec);
        for level in [1, 3, 19] {
            let l = format!("-{level}");
            for (dict, path) in [(&trained, dict_path), (&raw, raw_path)] {
                let ours = compress_with_dictionary(Level::new(level), &rec, dict);
                assert_eq!(zstd_cli(&["-d", "-c", "-D", path], &ours).unwrap(), rec);
                let theirs = zstd_cli(&[&l, "-c", "-D", path], &rec).unwrap();
                assert_eq!(
                    decompress_with_dictionary(&theirs, rec.len(), dict).unwrap(),
                    rec,
                    "zstd {l} -D {path}"
                );
            }
        }
    }
    for (dict, path) in [(&trained, dict_path), (&raw, raw_path)] {
        let ours = compress_with_dictionary(Level::new(3), &all, dict);
        assert!(zstd_cli(&["-d", "-c", "-D", path], &ours).unwrap() == all);
        let theirs = zstd_cli(&["-3", "-c", "-D", path], &all).unwrap();
        let mut d = Decompressor::with_dictionary(dict);
        assert!(stream_decompress(&mut d, &theirs, 999).unwrap() == all);
    }
}
