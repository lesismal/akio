#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| flash_http::fuzzing::h2_server(data));
