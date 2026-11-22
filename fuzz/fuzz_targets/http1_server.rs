#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_http::fuzzing::http1_server(data));
