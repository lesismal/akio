#![no_main]
//! akio-zstd's streaming compressor (pieces, flushes, windows and dictionaries chosen by the
//! first three bytes): both of its decoders give the input back, and so does libzstd, with the
//! same dictionary.

use akio_zstd::fuzzing;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some(s) = fuzzing::stream_roundtrip_frame(data) else {
        return;
    };
    let theirs = match &s.dict {
        None => zstd::bulk::decompress(&s.frame, s.body.len()),
        Some(d) => {
            let raw: Vec<u8> = if d.is_trained() {
                include_bytes!("../../crates/akio-zstd/tests/data/records.dict").to_vec()
            } else {
                d.content().to_vec()
            };
            zstd::bulk::Decompressor::with_dictionary(&raw)
                .and_then(|mut z| z.decompress(&s.frame, s.body.len()))
        }
    };
    let theirs = theirs.expect("libzstd decodes our frame");
    assert!(theirs == s.body, "libzstd output differs");
});
