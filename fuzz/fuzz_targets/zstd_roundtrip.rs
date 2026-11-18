#![no_main]
//! only-zstd's compressor at the level of `data[0]` on `data[1..]`: its output decodes to the
//! input with only-zstd (with exactly the input's size as the limit) and with libzstd.

use only_zstd::fuzzing;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some(packed) = fuzzing::roundtrip_frame(data) else {
        return;
    };
    let body = &data[1..];
    let theirs = zstd::bulk::decompress(&packed, body.len()).expect("libzstd decodes our frame");
    assert!(theirs == body, "libzstd output differs");
});
