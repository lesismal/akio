#![no_main]
//! only-protobuf against prost on the same input (tools/protobuf-test/prost_mirror.rs): both
//! decoders must accept or reject it alike, with the same value, and re-encodings must round-trip.

#[path = "../../tools/protobuf-test/prost_mirror.rs"]
mod mirror;

libfuzzer_sys::fuzz_target!(|data: &[u8]| mirror::differential(data));
