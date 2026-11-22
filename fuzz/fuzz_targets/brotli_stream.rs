#![no_main]
//! akio-brotli's streaming decoder on arbitrary bytes fed in pieces (sizes from the first byte):
//! never panics and agrees with the one-shot decoder (which `brotli_decompress` checks against
//! brotli-decompressor), without a dictionary and with a raw one.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    akio_brotli::fuzzing::stream(data);
});
