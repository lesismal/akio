#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| flash_h3::fuzzing::qpack_decode(data));
