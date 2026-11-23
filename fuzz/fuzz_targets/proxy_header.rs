#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_mux::fuzzing::proxy_header(data));
