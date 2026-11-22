#![no_main]
//! akio-zstd's streaming decoder on arbitrary bytes fed in pieces (sizes from the first byte):
//! never panics and agrees with the one-shot decoder (which `zstd_decompress` checks against
//! libzstd), without a dictionary and with a trained one; arbitrary bytes parsed as a
//! dictionary never panic, and a dictionary that parses compresses and decompresses a sample.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    akio_zstd::fuzzing::stream(data);
});
