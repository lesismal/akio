#![no_main]
//! RFC 9841 shared dictionaries: arbitrary bytes as a serialized dictionary never panic; random
//! dictionaries (custom word lists, transforms, context maps) with hand-made streams of
//! dictionary references decode as modelled, one-shot and streamed alike; arbitrary streams
//! decode the same both ways with them; the encoder round-trips with them.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    akio_brotli::fuzzing::shared::shared(data);
});
