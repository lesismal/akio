#![no_main]
//! only-deflate compress -> decompress round trips (levels, formats, windows, flushes), and
//! zlib-rs decodes the same output.

use only_deflate::{Format, Level, compress, fuzzing};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    fuzzing::roundtrip(data);
    let Some((&cfg, body)) = data.split_first() else {
        return;
    };
    let level = Level::new(u32::from(cfg) % 10);
    let packed = compress(Format::Raw, level, body);
    let mut z = flate2::Decompress::new(false);
    let mut out = Vec::with_capacity(body.len() + 1);
    let st = z
        .decompress_vec(&packed, &mut out, flate2::FlushDecompress::Finish)
        .expect("zlib-rs decodes only-deflate output");
    assert_eq!(st, flate2::Status::StreamEnd);
    assert!(out == body, "zlib-rs output differs");
});
