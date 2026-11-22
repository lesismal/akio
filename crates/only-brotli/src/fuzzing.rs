//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them (adding a differential check against `brotli-decompressor` there); the unit tests
//! below replay `fuzz/corpus/<target>` on stable.

use crate::{
    Compressor, Decompressor, Error, Flush, Level, compress, compress_with_dictionary,
    decompress_with_dictionary,
};

pub mod shared;

/// Output limit of the decoding targets.
pub const LIMIT: usize = 1 << 20;

/// `brotli_decompress`: arbitrary bytes as a brotli stream. Never panics; decoding is
/// deterministic, and the limit is exact: a stream that decodes to `n` bytes decodes with limit
/// `n` and fails with `TooLarge` under limit `n - 1`.
pub fn decompress(data: &[u8]) {
    let r = crate::decompress(data, LIMIT);
    match &r {
        Ok(out) => {
            assert!(out.len() <= LIMIT);
            let again = crate::decompress(data, out.len()).expect("decodes with an exact limit");
            assert!(again == *out, "output differs between runs");
            if !out.is_empty() {
                assert_eq!(crate::decompress(data, out.len() - 1), Err(Error::TooLarge));
            }
        }
        Err(Error::TooLarge) => {}
        Err(e) => {
            // A stream that fails does so whatever the limit, once the limit is big enough.
            assert_eq!(crate::decompress(data, LIMIT * 2).err(), Some(*e));
        }
    }
}

/// `brotli_roundtrip`: compresses `data[1..]` at the level chosen by `data[0]` and checks that
/// decompression gives it back, with an exact limit.
pub fn roundtrip(data: &[u8]) {
    let Some((&cfg, body)) = data.split_first() else {
        return;
    };
    let level = Level::new(u32::from(cfg) % 12);
    let packed = compress(level, body);
    let back = crate::decompress(&packed, body.len()).expect("own output decodes");
    assert!(back == body, "round trip differs");
}

/// The raw dictionary of the streaming targets (`tests/data/fuzz.dict`).
pub const TEST_DICTIONARY: &[u8] = include_bytes!("../tests/data/fuzz.dict");

/// Piece size for the streaming targets from a configuration byte: 1..=64, or up to ~4 KiB.
fn piece(cfg: u8) -> usize {
    let n = usize::from(cfg & 63) + 1;
    if cfg & 64 != 0 { n * 64 } else { n }
}

/// Decodes `data` with `d` in pieces of `step` into at most `limit` bytes: the output, whether
/// the stream ended, or the error.
fn streamed(
    mut d: Decompressor,
    data: &[u8],
    step: usize,
    limit: usize,
) -> Result<(Vec<u8>, bool), Error> {
    let mut out = Vec::new();
    for p in data.chunks(step) {
        let mut at = 0;
        while at < p.len() {
            let r = d.decompress_vec(&p[at..], &mut out, limit)?;
            at += r.consumed;
            if out.len() >= limit {
                return Ok((out, false));
            }
        }
    }
    Ok((out, d.is_done()))
}

/// The streaming decoder agrees with the one-shot result `one` of the same input: the same
/// output, or both refuse it (the error may differ: the streaming decoder reports what it
/// sees first with the input it has).
fn agree(one: Result<Vec<u8>, Error>, st: Result<(Vec<u8>, bool), Error>) {
    match (one, st) {
        (Ok(a), Ok((b, done))) => assert!(a == b && done, "streamed decoding differs"),
        (Ok(_), Err(e)) => panic!("streaming refuses what one-shot accepts ({e})"),
        (Err(Error::TooLarge), _) => {}
        (Err(e), Ok((b, done))) => {
            assert!(
                !done || b.len() > LIMIT,
                "streaming accepts what one-shot refuses ({e})"
            );
        }
        (Err(_), Err(_)) => {}
    }
}

/// `brotli_stream`: `data[1..]` decoded by the streaming decoder, in pieces sized by
/// `data[0]`, agrees with the one-shot decoder, without a dictionary and (odd `data[0]`) with
/// [`TEST_DICTIONARY`].
pub fn stream(data: &[u8]) {
    let Some((&cfg, body)) = data.split_first() else {
        return;
    };
    let step = piece(cfg);
    let one = crate::decompress(body, LIMIT);
    let st = streamed(Decompressor::new(), body, step, LIMIT + 1);
    agree(one, st);
    if cfg & 1 == 1 {
        let one = decompress_with_dictionary(body, LIMIT, TEST_DICTIONARY);
        let st = streamed(
            Decompressor::with_dictionary(TEST_DICTIONARY),
            body,
            step,
            LIMIT + 1,
        );
        agree(one, st);
    }
}

/// `brotli_stream_roundtrip`: compresses `data[3..]` with the streaming compressor (level from
/// `data[0]`; piece size, flush mode and window from `data[1]`; no dictionary,
/// [`TEST_DICTIONARY`] or the first bytes as the dictionary from `data[2]`) and checks that
/// both decoders give it back. Returns the stream, the input and the dictionary.
pub fn stream_roundtrip_stream(data: &[u8]) -> Option<(Vec<u8>, &[u8], &[u8])> {
    let (&[lv, cfg, dcfg], body) = data.split_first_chunk::<3>()?;
    let level = Level::new(u32::from(lv % 12));
    let flush = match cfg >> 6 {
        0 => Flush::None,
        1 => Flush::Flush,
        _ => [Flush::None, Flush::Flush][usize::from(cfg & 1)],
    };
    let step = piece(cfg & 63 | (cfg & 0x80) >> 1);
    let bits = 10 + u32::from(cfg % 15);
    let (dict, body): (&[u8], &[u8]) = match dcfg % 4 {
        1 => (TEST_DICTIONARY, body),
        2 => {
            let n = usize::from(dcfg >> 2).min(body.len()) * 16 % (body.len() + 1);
            (&body[..n], &body[n..])
        }
        _ => (&[], body),
    };
    let mut c = if dict.is_empty() {
        Compressor::new(level)
    } else {
        Compressor::with_dictionary(level, dict)
    }
    .window_bits(bits);
    let mut out = Vec::new();
    // After each flush everything so far decodes.
    let mut live = if dict.is_empty() {
        Decompressor::new()
    } else {
        Decompressor::with_dictionary(dict)
    };
    let mut seen = Vec::new();
    let mut taken = 0;
    for p in body.chunks(step) {
        let at = out.len();
        c.compress(p, &mut out, flush);
        taken += p.len();
        if flush == Flush::Flush {
            live.decompress_vec(&out[at..], &mut seen, usize::MAX)
                .expect("flushed stream decodes");
            assert!(seen == body[..taken], "flushed data not decodable");
        }
    }
    c.compress(&[], &mut out, Flush::Finish);
    let back = decompress_with_dictionary(&out, body.len(), dict).expect("own stream decodes");
    assert!(back == body, "round trip differs");
    let d = if dict.is_empty() {
        Decompressor::new()
    } else {
        Decompressor::with_dictionary(dict)
    };
    let (st, done) = streamed(d, &out, step, body.len() + 1).expect("decodes streamed");
    assert!(st == body && done, "streamed round trip differs");
    if !dict.is_empty() {
        let packed = compress_with_dictionary(level, body, dict);
        let back = decompress_with_dictionary(&packed, body.len(), dict).expect("decodes");
        assert!(back == body, "dictionary round trip differs");
    }
    Some((out, body, dict))
}

/// `brotli_stream_roundtrip` without the result (see [`stream_roundtrip_stream`]).
pub fn stream_roundtrip(data: &[u8]) {
    let _ = stream_roundtrip_stream(data);
}

/// `brotli_container`: with bit 0 of `data[0]` clear, `data[1..]` as a shared brotli
/// framing format container: never panics (a hash reference resolves to the hash's 32 bytes
/// as a dictionary). With it set, a container written from pieces of `data[1..]` (named
/// resources, hidden ones and resources compressed with an earlier one as their dictionary,
/// at the level of `data[0] >> 4`) reads back as written.
pub fn container(data: &[u8]) {
    let Some((&cfg, body)) = data.split_first() else {
        return;
    };
    if cfg & 1 == 0 {
        let _ = crate::read_container(body, LIMIT, &mut |h| Some(h.to_vec()));
        return;
    }
    let mut w = crate::ContainerWriter::new(Level::new(u32::from(cfg >> 4)));
    let mut want: Vec<(String, &[u8], bool)> = Vec::new();
    let mut dict = None;
    let mut rest = body;
    while let Some((&n, tail)) = rest.split_first() {
        let n = usize::from(n).min(tail.len()) * 16 % (tail.len() + 1);
        let (piece, tail) = tail.split_at(n);
        rest = tail;
        let name = format!("r{}", want.len());
        let hidden = match (want.len() % 3, dict) {
            (1, _) => {
                dict = Some(w.add_dictionary(piece));
                true
            }
            (2, Some(d)) => {
                w.add_with_dictionary(&name, piece, d);
                false
            }
            _ => {
                w.add(&name, piece);
                false
            }
        };
        want.push((if hidden { String::new() } else { name }, piece, hidden));
    }
    let packed = w.finish();
    let got = crate::read_container(&packed, usize::MAX, &mut |_| None).expect("reads back");
    assert_eq!(got.len(), want.len());
    for (g, (name, data, hidden)) in got.iter().zip(&want) {
        assert!(g.data == *data && g.hidden == *hidden, "resource differs");
        let gname = g.name.as_deref().unwrap_or(&[]);
        assert!(gname == name.as_bytes(), "name differs");
    }
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
    fn brotli_decompress_corpus() {
        replay("brotli_decompress", super::decompress);
    }

    #[test]
    fn brotli_roundtrip_corpus() {
        replay("brotli_roundtrip", super::roundtrip);
    }

    #[test]
    fn brotli_stream_corpus() {
        replay("brotli_stream", super::stream);
    }

    #[test]
    fn brotli_shared_corpus() {
        replay("brotli_shared", super::shared::shared);
    }

    #[test]
    fn brotli_stream_roundtrip_corpus() {
        replay("brotli_stream_roundtrip", super::stream_roundtrip);
    }

    #[test]
    fn brotli_container_corpus() {
        replay("brotli_container", super::container);
    }
}
