#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_ice::fuzzing::ice_tcp(data));
