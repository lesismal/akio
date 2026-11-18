#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_ice::fuzzing::ice_tcp(data));
