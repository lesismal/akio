//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them (adding a differential check against libzstd there); the unit tests below replay
//! `fuzz/corpus/<target>` on stable.

use crate::{
    Compressor, Decompressor, Dictionary, Error, Flush, Level, compress, compress_with_dictionary,
    decompress_with_dictionary,
};

/// Output limit of the decoding target.
pub const LIMIT: usize = 1 << 20;

/// `zstd_decompress`: arbitrary bytes as concatenated frames. Never panics; a successful
/// decoding also succeeds with its exact size as the limit and fails with
/// [`Error::TooLarge`] one byte below.
pub fn decompress_checked(data: &[u8]) -> Result<Vec<u8>, Error> {
    let r = crate::decompress(data, LIMIT);
    if let Ok(out) = &r {
        assert!(
            crate::decompress(data, out.len()).as_ref() == Ok(out),
            "exact limit fails"
        );
        if !out.is_empty() {
            assert_eq!(
                crate::decompress(data, out.len() - 1),
                Err(Error::TooLarge),
                "limit one below the size"
            );
        }
    }
    r
}

/// `zstd_decompress` without the result (see [`decompress_checked`]).
pub fn decompress(data: &[u8]) {
    let _ = decompress_checked(data);
}

/// The level and body of a `zstd_roundtrip` input: the level from `data[0]`, the rest is the
/// data.
pub fn split(data: &[u8]) -> Option<(Level, &[u8])> {
    let (&b, body) = data.split_first()?;
    Some((Level::new(u32::from(b % 22) + 1), body))
}

/// `zstd_roundtrip`: compresses `data[1..]` at the level of `data[0]` and checks that
/// decompression gives it back, within exactly its size as the limit. Returns the frame.
pub fn roundtrip_frame(data: &[u8]) -> Option<Vec<u8>> {
    let (level, body) = split(data)?;
    let packed = compress(level, body);
    let back = crate::decompress(&packed, body.len()).expect("own output decodes");
    assert!(back == body, "round trip differs");
    if !body.is_empty() {
        assert_eq!(
            crate::decompress(&packed, body.len() - 1),
            Err(Error::TooLarge)
        );
    }
    Some(packed)
}

/// `zstd_roundtrip` without the frame (see [`roundtrip_frame`]).
pub fn roundtrip(data: &[u8]) {
    let _ = roundtrip_frame(data);
}

/// The trained dictionary of the tests (`tests/data/records.dict`, Dictionary_ID 1234567).
pub fn test_dictionary() -> Dictionary {
    Dictionary::new(include_bytes!("../tests/data/records.dict")).expect("valid dictionary")
}

/// Piece size for the streaming targets from a configuration byte: 1..=64, or up to ~4 KiB.
fn piece(cfg: u8) -> usize {
    let n = usize::from(cfg & 63) + 1;
    if cfg & 64 != 0 { n * 64 } else { n }
}

/// Decodes `data` with `d` in pieces of `step` into at most `limit` bytes: the output, whether
/// the input ended a frame, or the error.
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

/// Checks the streaming decoder against the one-shot result `one` of the same input.
fn agree(one: Result<Vec<u8>, Error>, st: Result<(Vec<u8>, bool), Error>, empty: bool) {
    match (one, st) {
        (Ok(a), Ok((b, done))) => {
            assert!(a == b, "streamed output differs");
            assert!(done || empty, "streamed decoding not done");
        }
        // The one-shot decoder lets matches reach back to the frame's start; the streaming one
        // holds the frame's window (and up to as much again).
        (Ok(_), Err(Error::BadOffset)) => {}
        (Ok(_), Err(e)) => panic!("streaming refuses what one-shot accepts ({e})"),
        (Err(Error::TooLarge), _) => {}
        (Err(e), Ok((b, done))) => {
            assert!(
                !done || b.len() > LIMIT,
                "streaming accepts what one-shot refuses ({e})"
            )
        }
        (Err(_), Err(_)) => {}
    }
}

/// `zstd_stream`: `data[1..]` decoded by the streaming decoder, in pieces sized by `data[0]`,
/// agrees with the one-shot decoder, without a dictionary and (odd `data[0]`) with the test
/// dictionary. `data[1..]` parsed as a dictionary never panics, and a valid one compresses
/// and decompresses a sample.
pub fn stream(data: &[u8]) {
    let Some((&cfg, body)) = data.split_first() else {
        return;
    };
    let step = piece(cfg);
    let one = crate::decompress(body, LIMIT);
    let st = streamed(
        Decompressor::new().max_window(usize::MAX),
        body,
        step,
        LIMIT + 1,
    );
    agree(one, st, body.is_empty());
    if cfg & 1 == 1 {
        let dict = test_dictionary();
        let one = decompress_with_dictionary(body, LIMIT, &dict);
        let st = streamed(
            Decompressor::with_dictionary(&dict).max_window(usize::MAX),
            body,
            step,
            LIMIT + 1,
        );
        agree(one, st, body.is_empty());
    }
    if let Ok(d) = Dictionary::new(body) {
        let sample =
            b"{\"name\": \"grace\", \"email\": \"grace@example.com\", \"roles\": [\"admin\"]}";
        let level = Level::new(u32::from(cfg % 22) + 1);
        let packed = compress_with_dictionary(level, sample, &d);
        let back = decompress_with_dictionary(&packed, sample.len(), &d).expect("decodes");
        assert!(back == sample, "dictionary round trip differs");
    }
}

/// What [`stream_roundtrip_frame`] compressed: the frame, the input and the dictionary.
#[derive(Debug)]
pub struct Streamed<'a> {
    pub frame: Vec<u8>,
    pub body: &'a [u8],
    pub dict: Option<Dictionary>,
}

/// `zstd_stream_roundtrip`: compresses `data[3..]` with the streaming compressor (level from
/// `data[0]`; piece size, flush mode and window from `data[1]`; no dictionary, the test
/// dictionary or the first bytes as raw content from `data[2]`) and checks that both
/// decoders give it back. Returns the frame for the differential check against libzstd.
pub fn stream_roundtrip_frame(data: &[u8]) -> Option<Streamed<'_>> {
    let (&[lv, cfg, dcfg], body) = data.split_first_chunk::<3>()?;
    let level = Level::new(u32::from(lv % 22) + 1);
    let flush = match cfg >> 6 {
        0 => Flush::None,
        1 => Flush::Flush,
        _ => [Flush::None, Flush::Flush][usize::from(cfg & 1)],
    };
    let step = piece(cfg & 63 | (cfg & 0x80) >> 1);
    let log = 10 + u32::from(cfg % 14);
    let (dict, body) = match dcfg % 4 {
        1 => (Some(test_dictionary()), body),
        2 => {
            let n = usize::from(dcfg >> 2).min(body.len()) * 16 % (body.len() + 1);
            (Some(Dictionary::raw(&body[..n])), &body[n..])
        }
        _ => (None, body),
    };
    let mut c = match &dict {
        Some(d) => Compressor::with_dictionary(level, d),
        None => Compressor::new(level),
    }
    .window_log(log);
    let mut frame = Vec::new();
    // After each flush everything so far decodes.
    let mut live = match &dict {
        Some(d) => Decompressor::with_dictionary(d),
        None => Decompressor::new(),
    };
    let mut seen = Vec::new();
    let mut taken = 0;
    for p in body.chunks(step) {
        let at = frame.len();
        c.compress(p, &mut frame, flush);
        taken += p.len();
        if flush == Flush::Flush {
            live.decompress_vec(&frame[at..], &mut seen, usize::MAX)
                .expect("flushed frame decodes");
            assert!(seen == body[..taken], "flushed data not decodable");
        }
    }
    c.compress(&[], &mut frame, Flush::Finish);
    let (back, st) = match &dict {
        Some(d) => (
            decompress_with_dictionary(&frame, body.len(), d),
            streamed(
                Decompressor::with_dictionary(d),
                &frame,
                step,
                body.len() + 1,
            ),
        ),
        None => (
            crate::decompress(&frame, body.len()),
            streamed(Decompressor::new(), &frame, step, body.len() + 1),
        ),
    };
    assert!(
        back.expect("own stream decodes") == body,
        "round trip differs"
    );
    let (out, done) = st.expect("own stream decodes streamed");
    assert!(out == body && done, "streamed round trip differs");
    if let Some(d) = &dict {
        let packed = compress_with_dictionary(level, body, d);
        let back = decompress_with_dictionary(&packed, body.len(), d).expect("decodes");
        assert!(back == body, "dictionary round trip differs");
    }
    Some(Streamed { frame, body, dict })
}

/// `zstd_stream_roundtrip` without the result (see [`stream_roundtrip_frame`]).
pub fn stream_roundtrip(data: &[u8]) {
    let _ = stream_roundtrip_frame(data);
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
    fn zstd_decompress_corpus() {
        replay("zstd_decompress", super::decompress);
    }

    #[test]
    fn zstd_roundtrip_corpus() {
        replay("zstd_roundtrip", super::roundtrip);
    }

    #[test]
    fn zstd_stream_corpus() {
        replay("zstd_stream", super::stream);
    }

    #[test]
    fn zstd_stream_roundtrip_corpus() {
        replay("zstd_stream_roundtrip", super::stream_roundtrip);
    }
}
