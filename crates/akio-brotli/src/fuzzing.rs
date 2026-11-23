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
/// as a dictionary), and a container that reads is written back resource by resource
/// ([`ContainerWriter::add_resource`](crate::ContainerWriter::add_resource), global metadata
/// too) and reads back the same. With it set, a container written from pieces of `data[1..]`
/// reads back as written: named resources with a modification time, custom and footer fields
/// and hash codes, hidden ones and resources compressed with an earlier one as their
/// dictionary, global metadata, at the level of `data[0] >> 4`, with repeat metadata if bit 1
/// is set and partial data chunks of 1, 64 or 1000 bytes as bits 2 and 3 say (1, 2, 3; none
/// if 0).
pub fn container(data: &[u8]) {
    use crate::{Container, ContainerWriter, DictionaryRef, Resource};
    let Some((&cfg, body)) = data.split_first() else {
        return;
    };
    if cfg & 1 == 0 {
        let Ok(c) = Container::read(body, LIMIT, &mut |h| Some(h.to_vec())) else {
            return;
        };
        let mut w = ContainerWriter::new(Level::new(1)).repeat_metadata(true);
        if !c.global.is_empty() {
            w.add_global_metadata(&c.global);
        }
        for r in &c.resources {
            w.add_resource(r, None);
        }
        let again = Container::read(&w.finish(), usize::MAX, &mut |_| None).expect("reads back");
        assert!(again == c, "rewritten container differs");
        return;
    }
    let part = [0, 1, 64, 1000][usize::from(cfg >> 2 & 3)];
    let mut w = ContainerWriter::new(Level::new(u32::from(cfg >> 4)))
        .repeat_metadata(cfg & 2 != 0)
        .part_size(part);
    let mut want: Vec<Resource> = Vec::new();
    let mut global = Vec::new();
    let mut dict = None;
    let mut rest = body;
    while let Some((&n, tail)) = rest.split_first() {
        let n = usize::from(n).min(tail.len()) * 16 % (tail.len() + 1);
        let (piece, tail) = tail.split_at(n);
        rest = tail;
        let k = want.len();
        let b = |i: usize| piece.get(i).copied().unwrap_or(0);
        let mut r = Resource {
            data: piece.to_vec(),
            ..Resource::default()
        };
        if b(0) & 1 != 0 {
            r.name = Some(format!("r{k}").into_bytes());
        }
        if b(0) & 2 != 0 {
            r.modified = Some(i64::from(b(1)) << 40 | k as i64);
        }
        if b(0) & 4 != 0 {
            r.fields
                .push((*b"XA", piece[..piece.len().min(5)].to_vec()));
        }
        if b(0) & 8 != 0 {
            r.footer.push((*b"FT", vec![b(2); usize::from(b(3) & 15)]));
        }
        if b(0) & 16 != 0 {
            r.hash = Some([b(4); 32]);
        }
        if b(0) & 32 != 0 {
            global.push((*b"GL", vec![b(5)]));
            w.add_global_metadata(&global[global.len() - 1..]);
        }
        let idx = match (k % 3, dict) {
            (1, _) => {
                r.hidden = true;
                let i = w.add_resource(&r, None);
                dict = Some(i);
                i
            }
            (2, Some(d)) => w.add_resource(&r, Some(DictionaryRef::Resource(d))),
            _ => w.add_resource(&r, None),
        };
        assert_eq!(idx, k);
        want.push(r);
    }
    let packed = w.finish();
    let got = Container::read(&packed, usize::MAX, &mut |_| None).expect("reads back");
    assert!(got.resources == want, "resources differ");
    assert!(got.global == global, "global metadata differs");
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
