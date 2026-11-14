//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them (adding a differential check against zlib-rs there); the unit tests below replay
//! `fuzz/corpus/<target>` on stable.

use crate::{Deflater, Flush, Format, Inflater, Level, decompress};

/// Output limit of the decoding targets.
pub const LIMIT: usize = 1 << 20;

fn format_of(b: u8) -> Format {
    match b % 3 {
        0 => Format::Raw,
        1 => Format::Zlib,
        _ => Format::Gzip,
    }
}

/// Decodes `data` with input and output split into pieces of the given sizes (each at least
/// 1), returning the output, or the error, and whether the stream ended.
pub fn inflate_split(
    format: Format,
    data: &[u8],
    in_step: usize,
    out_step: usize,
) -> (Result<Vec<u8>, crate::Error>, bool) {
    let mut inf = Inflater::new(format);
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_step.max(1)];
    let mut pos = 0;
    loop {
        let end = (pos + in_step.max(1)).min(data.len());
        let r = inf.decompress(&data[pos..end], &mut buf);
        let p = match r {
            Ok(p) => p,
            Err(e) => return (Err(e), false),
        };
        out.extend_from_slice(&buf[..p.produced]);
        pos += p.consumed;
        if p.done {
            return (Ok(out), true);
        }
        if out.len() > LIMIT {
            return (Ok(out), false);
        }
        if p.produced < buf.len() && end == data.len() {
            return (Ok(out), false); // input used up
        }
    }
}

/// `deflate_inflate`: arbitrary bytes as a stream of the format chosen by `data[0]`. Never
/// panics; the one-shot result equals the result with input and output in small pieces.
pub fn inflate(data: &[u8]) {
    let Some((&cfg, rest)) = data.split_first() else {
        return;
    };
    let format = format_of(cfg);
    let whole = decompress(format, rest, LIMIT);
    let (split, done) = inflate_split(
        format,
        rest,
        1 + usize::from(cfg >> 2 & 7),
        1 + usize::from(cfg >> 5) * 37,
    );
    match (&whole, &split) {
        (Ok(a), Ok(b)) => {
            assert!(done);
            assert!(a == b, "split output differs");
        }
        (Ok(_), Err(e)) => panic!("one-shot ok, split failed: {e}"),
        (Err(crate::Error::TooLarge | crate::Error::Truncated), _) => {}
        (Err(e), Ok(_)) => assert!(!done, "split ok, one-shot failed: {e}"),
        (Err(a), Err(b)) => assert_eq!(a, b),
    }
}

/// `deflate_roundtrip`: compresses `data[2..]` in pieces with flushes, settings from
/// `data[0..2]`, and checks that decompression gives it back.
pub fn roundtrip(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let (a, b) = (data[0], data[1]);
    let body = &data[2..];
    let format = format_of(a);
    let level = Level::new(u32::from(a >> 2) % 10);
    let bits = 8 + (b & 7);
    let mut d = Deflater::with_window_bits(format, level, bits);
    let mut out = Vec::new();
    let step = 1 + usize::from(b >> 3) * 97;
    for (i, piece) in body.chunks(step).enumerate() {
        let flush = match (a >> 6, i % 3) {
            (0, _) => Flush::None,
            (1, 0) => Flush::Sync,
            (2, 1) => Flush::Full,
            _ => Flush::None,
        };
        d.compress(piece, &mut out, flush);
    }
    d.compress(&[], &mut out, Flush::Finish);
    let back = decompress(format, &out, body.len()).expect("own output decodes");
    assert!(back == body, "round trip differs");
    // A decoder with the compressor's window accepts the stream too.
    let mut inf = Inflater::with_window_bits(format, bits.max(9));
    let mut v = Vec::new();
    let p = inf
        .decompress_vec(&out, &mut v, body.len() + 1)
        .expect("decodes with the compressor's window");
    assert!(p.done && v == body);
}

#[cfg(test)]
mod tests {
    fn replay(target: &str, f: fn(&[u8])) {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/corpus")
            .join(target);
        let mut n = 0;
        for e in std::fs::read_dir(&dir).expect("corpus directory") {
            let p = e.expect("entry").path();
            f(&std::fs::read(&p).expect("corpus file"));
            n += 1;
        }
        assert!(n > 0, "empty corpus {}", dir.display());
    }

    #[test]
    fn deflate_inflate_corpus() {
        replay("deflate_inflate", super::inflate);
    }

    #[test]
    fn deflate_roundtrip_corpus() {
        replay("deflate_roundtrip", super::roundtrip);
    }
}
