#![no_main]
//! akio-brotli compress -> decompress round trips at every level, and `brotli-decompressor`
//! (a port of Google's decoder) decodes the same output.

use brotli_decompressor::{BrotliDecompressStream, BrotliResult, BrotliState, StandardAlloc};
use akio_brotli::{Level, compress, fuzzing};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    fuzzing::roundtrip(data);
    let Some((&cfg, body)) = data.split_first() else {
        return;
    };
    let packed = compress(Level::new(u32::from(cfg) % 12), body);
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
        "brotli-decompressor rejects our output"
    );
    assert_eq!(avail_in, 0, "brotli-decompressor leaves input");
    assert!(
        out[..out_off] == *body,
        "brotli-decompressor output differs"
    );
});
