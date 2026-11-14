#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| flash_http::fuzzing::http1_client(data));
