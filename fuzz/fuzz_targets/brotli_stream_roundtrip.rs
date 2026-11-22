#![no_main]
//! akio-brotli's streaming compressor (pieces, flushes, windows and raw dictionaries chosen by
//! the first three bytes): both of its decoders give the input back, and so does
//! `brotli-decompressor` for streams without a dictionary.

use akio_brotli::fuzzing;
use brotli_decompressor::{BrotliDecompressStream, BrotliResult, BrotliState, StandardAlloc};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((packed, body, dict)) = fuzzing::stream_roundtrip_stream(data) else {
        return;
    };
    if !dict.is_empty() {
        return;
    }
    let mut out = vec![0u8; body.len() + 1];
    let mut state = BrotliState::new(
        StandardAlloc::default(),
        StandardAlloc::default(),
        StandardAlloc::default(),
    );
    state.large_window = false;
    let (mut avail_in, mut in_off) = (packed.len(), 0);
    let (mut avail_out, mut out_off, mut total) = (out.len(), 0, 0);
    let r = BrotliDecompressStream(
        &mut avail_in,
        &mut in_off,
        &packed,
        &mut avail_out,
        &mut out_off,
        &mut out,
        &mut total,
        &mut state,
    );
    assert!(
        matches!(r, BrotliResult::ResultSuccess),
        "brotli-decompressor rejects our stream"
    );
    assert_eq!(avail_in, 0, "brotli-decompressor leaves input");
    assert!(
        out[..out_off] == *body,
        "brotli-decompressor output differs"
    );
});
