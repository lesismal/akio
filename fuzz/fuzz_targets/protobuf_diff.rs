#![no_main]
//! akio-protobuf against prost on the same input (tools/protobuf-test/prost_mirror.rs): both
//! decoders must accept or reject it alike, with the same value, and re-encodings must round-trip.
//! Also proto2 groups and closed enums (`test.ext.Base`) against prost, and dynamic messages
//! (runtime reflection) against the generated code.

#[path = "../../tools/protobuf-test/prost_mirror.rs"]
mod mirror;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    mirror::differential(data);
    mirror::differential_groups(data);
    mirror::differential_dynamic(data);
});
