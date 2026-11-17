#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_h3::fuzzing::qpack_dynamic(data));
